//! Reconcile worker — periodic safety net + GC.
//!
//! Every 30 minutes:
//!   * Expire / delete stale `osu_oauth_states` rows.
//!   * Re-enqueue a config_sync for every role link, on a slow drip, so a
//!     missed worker dispatch can't leave assignments diverged forever.
//!     The PUT short-circuit in `sync_for_role_link` makes this almost free
//!     when nothing actually changed.

use std::sync::Arc;
use std::time::Duration;

use crate::services::jobs;
use crate::tasks::shutdown::ShutdownGuard;
use crate::AppState;

const TICK: Duration = Duration::from_secs(30 * 60);
const INITIAL_DELAY: Duration = Duration::from_secs(120);

pub async fn run(state: Arc<AppState>, mut shutdown: ShutdownGuard) {
    tracing::info!("Reconcile worker started");

    tokio::select! {
        _ = tokio::time::sleep(INITIAL_DELAY) => {}
        _ = shutdown.wait() => return,
    }

    let mut interval = tokio::time::interval(TICK);
    loop {
        gc(&state).await;

        // Re-enqueue a config_sync per role link. The 5s debounce inside
        // `enqueue_config_sync` collapses overlapping inserts into one run.
        let links: Vec<(String, String)> =
            sqlx::query_as("SELECT guild_id, role_id FROM role_links")
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        for (g, r) in links {
            if let Err(e) = jobs::enqueue_config_sync(&state.pool, &g, &r).await {
                tracing::warn!(g, r, "reconcile: enqueue config_sync failed: {e}");
            }
        }

        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.wait() => break,
        }
    }

    tracing::info!("Reconcile worker stopped");
}

async fn gc(state: &Arc<AppState>) {
    let _ = sqlx::query("DELETE FROM osu_oauth_states WHERE expires_at < now()")
        .execute(&state.pool)
        .await;
    // Sweep `dead` jobs older than 30 days so the DLQ doesn't grow forever.
    let _ = sqlx::query(
        "DELETE FROM jobs WHERE status = 'dead' AND completed_at < now() - interval '30 days'",
    )
    .execute(&state.pool)
    .await;
    // Sweep `completed` jobs older than 24h — workers don't read them, the
    // index they live in is partial, so the row is pure storage cost.
    let _ = sqlx::query(
        "DELETE FROM jobs WHERE status = 'completed' AND completed_at < now() - interval '24 hours'",
    )
    .execute(&state.pool)
    .await;
}
