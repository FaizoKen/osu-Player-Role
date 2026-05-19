//! osu! OAuth callback. Only one flow exists (viewer link); broadcaster /
//! channel concepts don't apply to osu!.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use bytes::Bytes;
use chrono::DateTime;
use serde::Deserialize;

use crate::error::AppError;
use crate::models::mode::Mode;
use crate::services::jobs;
use crate::services::osu::{OsuClient, OsuUser};
use crate::AppState;

const SUCCESS_PAGE: &str = include_str!("../../templates/oauth_done.html");

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(sqlx::FromRow)]
struct OauthState {
    code_verifier: String,
    discord_id: String,
}

/// `{base_url}/oauth/osu/callback` — the exact redirect URI to register on
/// the osu! OAuth application page.
pub fn redirect_uri(base_url: &str) -> String {
    format!("{}/oauth/osu/callback", base_url.trim_end_matches('/'))
}

/// Persist a one-shot PKCE state row. Called by the verify route before
/// redirecting the user to osu!.
pub async fn insert_state(
    state: &Arc<AppState>,
    state_token: &str,
    code_verifier: &str,
    discord_id: &str,
    return_to: Option<&str>,
) -> Result<(), AppError> {
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    sqlx::query(
        "INSERT INTO osu_oauth_states (state, code_verifier, discord_id, return_to, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(state_token)
    .bind(code_verifier)
    .bind(discord_id)
    .bind(return_to)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;
    Ok(())
}

pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    match callback_inner(state, q).await {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn callback_inner(state: Arc<AppState>, q: CallbackQuery) -> Result<Bytes, AppError> {
    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        return Err(AppError::BadRequest(format!(
            "osu! returned an error during authorization: {err} ({desc})"
        )));
    }
    let code = q
        .code
        .ok_or_else(|| AppError::BadRequest("Missing `code` from osu! callback.".into()))?;
    let st = q
        .state
        .ok_or_else(|| AppError::BadRequest("Missing `state` from osu! callback.".into()))?;

    // Consume the state row in a single DELETE … RETURNING so it can't be
    // replayed even on race.
    let row: Option<OauthState> = sqlx::query_as(
        "DELETE FROM osu_oauth_states \
         WHERE state = $1 AND expires_at > now() \
         RETURNING code_verifier, discord_id",
    )
    .bind(&st)
    .fetch_optional(&state.pool)
    .await?;
    let row = row.ok_or_else(|| {
        AppError::BadRequest(
            "OAuth state expired or unknown — start the link flow again from /verify.".into(),
        )
    })?;

    let client = build_osu_client(&state)?;
    let tokens = client
        .exchange_code(
            &code,
            &redirect_uri(&state.config.base_url),
            &row.code_verifier,
        )
        .await?;
    let user = client.get_me(&tokens.access_token, None).await?;

    if user.is_restricted {
        return Err(AppError::BadRequest(
            "This osu! account is restricted; restricted accounts cannot be linked.".into(),
        ));
    }

    // Try to capture the Discord display name from whatever the gateway
    // last minted for this user, so the public users page can show it
    // without a per-user lookup. Best-effort: missing cookie = NULL value.
    let discord_name = peek_session_display_name(&state, &row.discord_id).await;

    // Upsert profile + per-mode stats inside one transaction so a partial
    // write can't leave a dangling state.
    let mut tx = state.pool.begin().await?;
    upsert_user_profile(&mut tx, &row.discord_id, &user, discord_name.as_deref()).await?;
    // Fetch per-mode stats for all four modes app-authenticated. This adds
    // ~4 HTTP requests at link time, which is fine — it gives the role
    // engine immediate data so the role drops in within seconds.
    let app_tokens = client.client_credentials_token().await?;
    for mode in Mode::ALL {
        match client
            .get_user(&app_tokens.access_token, user.id, mode)
            .await
        {
            Ok(u) => {
                upsert_stats(&mut tx, user.id, mode, &u).await?;
            }
            Err(e) => {
                tracing::warn!(
                    osu_user_id = user.id,
                    mode = mode.as_str(),
                    "stats fetch failed: {e}"
                );
            }
        }
    }
    tx.commit().await?;

    // Fan out role evaluation.
    jobs::enqueue_player_sync(&state.pool, &row.discord_id).await?;

    let body = SUCCESS_PAGE
        .replace("{{BASE_URL}}", &state.config.base_url)
        .replace("{{OSU_USERNAME}}", &html_escape(&user.username))
        .replace("{{OSU_USER_ID}}", &user.id.to_string());
    Ok(Bytes::from(body))
}

fn build_osu_client(state: &Arc<AppState>) -> Result<OsuClient, AppError> {
    let client_id = state
        .config
        .osu
        .client_id
        .clone()
        .ok_or_else(|| AppError::Internal("OSU_CLIENT_ID is not configured.".into()))?;
    let client_secret = state
        .config
        .osu
        .client_secret
        .clone()
        .ok_or_else(|| AppError::Internal("OSU_CLIENT_SECRET is not configured.".into()))?;
    Ok(OsuClient::new(client_id, client_secret))
}

/// Pull the display name out of the user's currently-live rl_session
/// cookie, if any. The cookie isn't part of the OAuth callback URL, but
/// the same browser session does still send it on direct nav. We accept
/// the imperfection: a fresh-login user might get a NULL `discord_name`
/// here; the players page just falls back to `discord_id` then.
async fn peek_session_display_name(_state: &Arc<AppState>, _discord_id: &str) -> Option<String> {
    // The callback handler is a redirect target, so the cookie *is* sent
    // by the browser, but in this codebase the handler signature uses
    // `Query` only — we don't take a CookieJar (the OAuth callback is
    // explicitly auth-by-state, not auth-by-cookie). Refactoring to also
    // accept the jar is overkill for a best-effort display name.
    None
}

pub(crate) async fn upsert_user_profile(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    discord_id: &str,
    u: &OsuUser,
    discord_name: Option<&str>,
) -> Result<(), AppError> {
    let join_date = DateTime::parse_from_rfc3339(&u.join_date)
        .map(|d| d.with_timezone(&chrono::Utc))
        .map_err(|e| AppError::OsuApi(format!("invalid join_date: {e}")))?;
    let last_visit = u
        .last_visit
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));

    let country_code = u
        .country_code
        .clone()
        .or_else(|| u.country.as_ref().and_then(|c| c.code.clone()));
    let country_name = u.country.as_ref().and_then(|c| c.name.clone());

    let badge_count = u.badges.as_ref().map(|b| b.len() as i32).unwrap_or(0);
    let groups: Vec<String> = u
        .groups
        .as_ref()
        .map(|gs| {
            gs.iter()
                .filter_map(|g| g.identifier.clone())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let playstyles: Vec<String> = u.playstyle.clone().unwrap_or_default();
    let kudosu = u.kudosu.as_ref().map(|k| k.total as i32).unwrap_or(0);

    // Re-link guard: an osu! account can only be tied to one Discord
    // account at a time. If this osu_user_id was previously linked to a
    // different Discord, sever the old link first so the upsert succeeds.
    sqlx::query("DELETE FROM osu_users WHERE osu_user_id = $1 AND discord_id <> $2")
        .bind(u.id)
        .bind(discord_id)
        .execute(&mut **tx)
        .await?;

    sqlx::query(
        "INSERT INTO osu_users ( \
            discord_id, osu_user_id, osu_username, discord_name, \
            country_code, country_name, profile_colour, avatar_url, \
            osu_joined_at, last_visit_at, is_supporter, support_level, \
            is_restricted, is_active, badge_count, follower_count, \
            mapping_followers, kudosu_total, ranked_beatmaps, loved_beatmaps, \
            pending_beatmaps, graveyard_beatmaps, mapping_playcount, \
            replays_watched_others, favourite_beatmapsets, playstyles, groups, \
            profile, linked_at, refreshed_at, next_refresh_at \
         ) VALUES ( \
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
            $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, \
            now(), now(), now() + interval '6 hours' \
         ) \
         ON CONFLICT (discord_id) DO UPDATE SET \
            osu_user_id = EXCLUDED.osu_user_id, \
            osu_username = EXCLUDED.osu_username, \
            discord_name = COALESCE(EXCLUDED.discord_name, osu_users.discord_name), \
            country_code = EXCLUDED.country_code, \
            country_name = EXCLUDED.country_name, \
            profile_colour = EXCLUDED.profile_colour, \
            avatar_url = EXCLUDED.avatar_url, \
            osu_joined_at = EXCLUDED.osu_joined_at, \
            last_visit_at = EXCLUDED.last_visit_at, \
            is_supporter = EXCLUDED.is_supporter, \
            support_level = EXCLUDED.support_level, \
            is_restricted = EXCLUDED.is_restricted, \
            is_active = EXCLUDED.is_active, \
            badge_count = EXCLUDED.badge_count, \
            follower_count = EXCLUDED.follower_count, \
            mapping_followers = EXCLUDED.mapping_followers, \
            kudosu_total = EXCLUDED.kudosu_total, \
            ranked_beatmaps = EXCLUDED.ranked_beatmaps, \
            loved_beatmaps = EXCLUDED.loved_beatmaps, \
            pending_beatmaps = EXCLUDED.pending_beatmaps, \
            graveyard_beatmaps = EXCLUDED.graveyard_beatmaps, \
            mapping_playcount = EXCLUDED.mapping_playcount, \
            replays_watched_others = EXCLUDED.replays_watched_others, \
            favourite_beatmapsets = EXCLUDED.favourite_beatmapsets, \
            playstyles = EXCLUDED.playstyles, \
            groups = EXCLUDED.groups, \
            profile = EXCLUDED.profile, \
            refreshed_at = now(), \
            next_refresh_at = now() + interval '6 hours', \
            refresh_failures = 0",
    )
    .bind(discord_id)
    .bind(u.id)
    .bind(&u.username)
    .bind(discord_name)
    .bind(country_code.as_deref())
    .bind(country_name.as_deref())
    .bind(u.profile_colour.as_deref())
    .bind(u.avatar_url.as_deref())
    .bind(join_date)
    .bind(last_visit)
    .bind(u.is_supporter)
    .bind(u.support_level as i32)
    .bind(u.is_restricted)
    .bind(u.is_active)
    .bind(badge_count)
    .bind(u.follower_count.unwrap_or(0) as i32)
    .bind(u.mapping_follower_count.unwrap_or(0) as i32)
    .bind(kudosu)
    .bind(u.ranked_beatmapset_count.unwrap_or(0) as i32)
    .bind(u.loved_beatmapset_count.unwrap_or(0) as i32)
    .bind(u.pending_beatmapset_count.unwrap_or(0) as i32)
    .bind(u.graveyard_beatmapset_count.unwrap_or(0) as i32)
    .bind(u.beatmap_playcounts_count.unwrap_or(0) as i32)
    .bind(u.replays_watched_by_others.unwrap_or(0) as i32)
    .bind(u.favourite_beatmapset_count.unwrap_or(0) as i32)
    .bind(&playstyles)
    .bind(&groups)
    .bind(serde_json::to_value(u).unwrap_or_default())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn upsert_stats(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    osu_user_id: i64,
    mode: Mode,
    u: &OsuUser,
) -> Result<(), AppError> {
    let s = u.statistics.as_ref();
    let pp = s.and_then(|s| s.pp).map(|p| p.round() as i32).unwrap_or(0);
    let global_rank = s.and_then(|s| s.global_rank).map(|r| r as i32);
    let country_rank = s.and_then(|s| s.country_rank).map(|r| r as i32);
    let play_count = s.and_then(|s| s.play_count).unwrap_or(0) as i32;
    let play_time_hours = s.and_then(|s| s.play_time).map(|s| s / 3600).unwrap_or(0) as i32;
    let total_score = s.and_then(|s| s.total_score).unwrap_or(0);
    let ranked_score = s.and_then(|s| s.ranked_score).unwrap_or(0);
    let hit_accuracy = s
        .and_then(|s| s.hit_accuracy)
        .map(|a| a.floor() as i32)
        .unwrap_or(0);
    let max_combo = s.and_then(|s| s.maximum_combo).unwrap_or(0) as i32;
    let level_int = s
        .and_then(|s| s.level.as_ref())
        .and_then(|l| l.current)
        .unwrap_or(0) as i32;
    let gc = s.and_then(|s| s.grade_counts.as_ref());
    let count_ss_silver = gc.map(|g| g.ssh as i32).unwrap_or(0);
    let count_ss = gc.map(|g| g.ss as i32).unwrap_or(0);
    let count_s_silver = gc.map(|g| g.sh as i32).unwrap_or(0);
    let count_s = gc.map(|g| g.s as i32).unwrap_or(0);
    let count_a = gc.map(|g| g.a as i32).unwrap_or(0);

    sqlx::query(
        "INSERT INTO osu_stats ( \
            osu_user_id, mode, global_rank, country_rank, performance_points, \
            play_count, play_time_hours, total_score, ranked_score, \
            hit_accuracy, max_combo, level_int, \
            count_ss_silver, count_ss, count_s_silver, count_s, count_a, \
            refreshed_at \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                   $13, $14, $15, $16, $17, now()) \
         ON CONFLICT (osu_user_id, mode) DO UPDATE SET \
            global_rank = EXCLUDED.global_rank, \
            country_rank = EXCLUDED.country_rank, \
            performance_points = EXCLUDED.performance_points, \
            play_count = EXCLUDED.play_count, \
            play_time_hours = EXCLUDED.play_time_hours, \
            total_score = EXCLUDED.total_score, \
            ranked_score = EXCLUDED.ranked_score, \
            hit_accuracy = EXCLUDED.hit_accuracy, \
            max_combo = EXCLUDED.max_combo, \
            level_int = EXCLUDED.level_int, \
            count_ss_silver = EXCLUDED.count_ss_silver, \
            count_ss = EXCLUDED.count_ss, \
            count_s_silver = EXCLUDED.count_s_silver, \
            count_s = EXCLUDED.count_s, \
            count_a = EXCLUDED.count_a, \
            refreshed_at = now()",
    )
    .bind(osu_user_id)
    .bind(mode.as_str())
    .bind(global_rank)
    .bind(country_rank)
    .bind(pp)
    .bind(play_count)
    .bind(play_time_hours)
    .bind(total_score)
    .bind(ranked_score)
    .bind(hit_accuracy)
    .bind(max_combo)
    .bind(level_int)
    .bind(count_ss_silver)
    .bind(count_ss)
    .bind(count_s_silver)
    .bind(count_s)
    .bind(count_a)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Refresh a single linked user — used by the refresh worker. Splits into
/// this module rather than `tasks/` because the upsert logic lives here.
pub(crate) async fn refresh_user_full(
    state: &Arc<AppState>,
    discord_id: &str,
    osu_user_id: i64,
) -> Result<(), AppError> {
    let client = build_osu_client(state)?;
    let app_tokens = client.client_credentials_token().await?;
    // Use the user's default mode for the primary profile fetch (it returns
    // the same shape regardless of mode; per-mode stats come from the
    // per-mode loop below).
    let primary = client
        .get_user(&app_tokens.access_token, osu_user_id, Mode::Osu)
        .await?;

    // Verify session display name is unavailable in this background path,
    // so we never write a new value here (the COALESCE in the UPSERT keeps
    // any prior one).
    let mut tx = state.pool.begin().await?;
    upsert_user_profile(&mut tx, discord_id, &primary, None).await?;
    for mode in Mode::ALL {
        match client
            .get_user(&app_tokens.access_token, osu_user_id, mode)
            .await
        {
            Ok(u) => upsert_stats(&mut tx, osu_user_id, mode, &u).await?,
            Err(e) => {
                tracing::warn!(
                    osu_user_id,
                    mode = mode.as_str(),
                    "refresh stats failed: {e}"
                )
            }
        }
    }
    tx.commit().await?;
    jobs::enqueue_player_sync(&state.pool, discord_id).await?;
    Ok(())
}
