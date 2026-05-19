//! Refresh worker — keeps each linked user's cached osu! profile + per-mode
//! stats fresh by polling the osu! API. The "live" state of an osu! player
//! (PP, rank, plays, …) drifts continuously; we re-fetch each user at most
//! once per cycle (default ≈ 6h) so role thresholds get re-checked.
//!
//! Design notes:
//!   * Picks the oldest `next_refresh_at` first (priority by staleness).
//!   * Bounded concurrency (`REFRESH_CONCURRENCY`, default 2) so we don't
//!     burn through osu!'s ~60 req/min ceiling.
//!   * Each user costs ~5 HTTP calls (1 profile + 4 per-mode stats), so
//!     keeping concurrency low is essential.
//!   * Failures back off exponentially per user (`refresh_failures` column).
//!   * After each successful refresh we enqueue a player_sync so role
//!     assignments converge to the new facts.

use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{self, StreamExt};

use crate::routes::oauth;
use crate::tasks::shutdown::ShutdownGuard;
use crate::AppState;

/// How often the worker wakes up to pull a batch from the queue. Short
/// enough that brand-new links get refreshed quickly; long enough that an
/// idle pod isn't busy-looping.
const TICK: Duration = Duration::from_secs(60);
/// Soonest a successful refresh re-queues a user. Each user gets refreshed
/// at most once per `REFRESH_INTERVAL`.
const REFRESH_INTERVAL: chrono::Duration = chrono::Duration::hours(6);
/// Maximum exponent for failure backoff. Capped to keep retries from
/// stretching past a day.
const MAX_BACKOFF_HOURS: i64 = 24;

pub async fn run(state: Arc<AppState>, mut shutdown: ShutdownGuard) {
    tracing::info!("Refresh worker started");

    // Short initial delay so we don't smash osu! at boot.
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(15)) => {}
        _ = shutdown.wait() => return,
    }

    let mut interval = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.wait() => break,
        }

        if state.config.osu.client_id.is_none() || state.config.osu.client_secret.is_none() {
            // Without app credentials we can't make any API calls. Stay
            // alive (a future SIGHUP / env reload could fix the config)
            // but don't busy-warn.
            continue;
        }

        let concurrency = state.config.refresh_concurrency.max(1) as usize;
        let batch_size = (concurrency * 4) as i64; // a bit of headroom

        let due: Vec<(String, i64)> = match sqlx::query_as(
            "SELECT discord_id, osu_user_id FROM osu_users \
             WHERE next_refresh_at <= now() \
             ORDER BY next_refresh_at \
             LIMIT $1",
        )
        .bind(batch_size)
        .fetch_all(&state.pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("refresh: query due users failed: {e}");
                continue;
            }
        };

        if due.is_empty() {
            continue;
        }

        let state_ref = Arc::clone(&state);
        stream::iter(due)
            .for_each_concurrent(concurrency, |(discord_id, osu_user_id)| {
                let state = Arc::clone(&state_ref);
                async move {
                    match oauth::refresh_user_full(&state, &discord_id, osu_user_id).await {
                        Ok(()) => {
                            let next = chrono::Utc::now() + REFRESH_INTERVAL;
                            let _ = sqlx::query(
                                "UPDATE osu_users SET refreshed_at = now(), \
                                 next_refresh_at = $2, refresh_failures = 0 \
                                 WHERE discord_id = $1",
                            )
                            .bind(&discord_id)
                            .bind(next)
                            .execute(&state.pool)
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!(
                                discord_id = %discord_id,
                                osu_user_id,
                                "refresh failed: {e}"
                            );
                            // Backoff: 2^failures hours, capped, with light jitter.
                            let cur_failures: i32 = sqlx::query_scalar(
                                "SELECT refresh_failures FROM osu_users WHERE discord_id = $1",
                            )
                            .bind(&discord_id)
                            .fetch_one(&state.pool)
                            .await
                            .unwrap_or(0);
                            let exp = (cur_failures + 1).clamp(1, 5) as u32;
                            let hours = (1_i64 << exp).min(MAX_BACKOFF_HOURS);
                            let next = chrono::Utc::now() + chrono::Duration::hours(hours);
                            let _ = sqlx::query(
                                "UPDATE osu_users SET refresh_failures = refresh_failures + 1, \
                                 next_refresh_at = $2 WHERE discord_id = $1",
                            )
                            .bind(&discord_id)
                            .bind(next)
                            .execute(&state.pool)
                            .await;
                        }
                    }
                }
            })
            .await;
    }

    tracing::info!("Refresh worker stopped");
}
