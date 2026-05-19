//! Public "linked players" listing — every server member who linked an
//! osu! account. Useful for admins to see who's actually playing.
//!
//! Gated by `guild_settings.view_permission`:
//!   * 'disabled' — nobody (page renders an explanatory notice)
//!   * 'managers' — Manage-Server only
//!   * 'members'  — any member of the guild

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::auth::{extract_bearer, guild_members, guild_permission, require_guild_admin};
use crate::services::csrf;
use crate::AppState;

const USERS_PAGE: &str = include_str!("../../templates/users.html");

pub async fn users_page(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
) -> impl IntoResponse {
    let html = USERS_PAGE
        .replace("{{BASE_URL}}", &state.config.base_url)
        .replace("{{GUILD_ID}}", &guild_id);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

#[allow(clippy::type_complexity)]
pub async fn users_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(guild_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    if view_permission == "disabled" {
        return Err(AppError::Forbidden(
            "The player list is disabled for this server.".into(),
        ));
    }

    let perm = guild_permission(&state, &jar, &guild_id).await?;
    if !perm.is_member {
        return Err(AppError::Forbidden(
            "You're not a member of this server.".into(),
        ));
    }
    if view_permission == "managers" && !perm.is_manager {
        return Err(AppError::Forbidden(
            "This list is visible to server managers only.".into(),
        ));
    }

    // "Who is in this guild" comes from the Auth Gateway, not a local table.
    let (member_ids, guild_name) = guild_members(&state, &jar, &guild_id).await?;

    // For each linked guild member, surface profile + their *default-mode*
    // (osu) per-mode stats. The page is intentionally one-line-per-player;
    // a richer mode picker on the page would be nice future work.
    let rows = sqlx::query_as::<
        _,
        (
            String,                                // discord_id
            Option<String>,                        // discord_name
            String,                                // osu_username
            i64,                                   // osu_user_id
            Option<String>,                        // country_code
            bool,                                  // is_supporter
            i32,                                   // badge_count
            Option<i32>,                           // global_rank (osu)
            i32,                                   // performance_points (osu)
            i32,                                   // play_count (osu)
            Option<chrono::DateTime<chrono::Utc>>, // last_visit_at
            chrono::DateTime<chrono::Utc>,         // linked_at
        ),
    >(
        "SELECT ou.discord_id, ou.discord_name, ou.osu_username, ou.osu_user_id, \
                ou.country_code, ou.is_supporter, ou.badge_count, \
                os.global_rank, COALESCE(os.performance_points, 0), COALESCE(os.play_count, 0), \
                ou.last_visit_at, ou.linked_at \
         FROM osu_users ou \
         LEFT JOIN osu_stats os \
           ON os.osu_user_id = ou.osu_user_id AND os.mode = 'osu' \
         WHERE ou.discord_id = ANY($1) \
         ORDER BY ou.osu_username ASC \
         LIMIT 1000",
    )
    .bind(&member_ids)
    .fetch_all(&state.pool)
    .await?;

    let users = rows
        .into_iter()
        .map(
            |(
                discord_id,
                discord_name,
                osu_username,
                osu_user_id,
                country_code,
                is_supporter,
                badge_count,
                global_rank,
                performance_points,
                play_count,
                last_visit_at,
                linked_at,
            )| {
                json!({
                    "discord_id": discord_id,
                    "discord_name": discord_name,
                    "osu_username": osu_username,
                    "osu_user_id": osu_user_id,
                    "osu_profile_url": format!("https://osu.ppy.sh/users/{}", osu_user_id),
                    "country_code": country_code,
                    "is_supporter": is_supporter,
                    "badge_count": badge_count,
                    "global_rank": global_rank,
                    "performance_points": performance_points,
                    "play_count": play_count,
                    "last_visit_at": last_visit_at.map(|x| x.to_rfc3339()),
                    "linked_at": linked_at.to_rfc3339(),
                })
            },
        )
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "guild_id": guild_id,
        "guild_name": guild_name,
        "count": users.len(),
        "users": users,
    })))
}

#[derive(serde::Deserialize)]
pub struct ViewPermBody {
    pub view_permission: String,
}

pub async fn set_view_permission(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(body): Json<ViewPermBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let vp = match body.view_permission.as_str() {
        "disabled" | "managers" | "members" => body.view_permission.as_str(),
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown view_permission '{other}' (expected disabled|managers|members)."
            )))
        }
    };

    sqlx::query(
        "INSERT INTO guild_settings (guild_id, view_permission, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (guild_id) DO UPDATE SET view_permission = EXCLUDED.view_permission, \
                                              updated_at = now()",
    )
    .bind(&guild_id)
    .bind(vp)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "success": true, "view_permission": vp })))
}
