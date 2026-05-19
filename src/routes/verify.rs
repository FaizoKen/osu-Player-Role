//! Member-facing verification flow: link an osu! account to a Discord ID.
//!
//! Routes:
//!   GET  /verify         — landing page (HTML)
//!   POST /verify/login   — redirect to Auth Gateway Discord login
//!   POST /verify/osu     — start osu! OAuth (PKCE)
//!   GET  /verify/status  — JSON status the page's JS reads
//!   POST /verify/unlink  — self-service unlink

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::AppError;
use crate::routes::oauth;
use crate::services::auth::read_session;
use crate::services::csrf;
use crate::services::osu;
use crate::AppState;

const VERIFY_PAGE: &str = include_str!("../../templates/verify.html");

pub async fn verify_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let html = VERIFY_PAGE.replace("{{BASE_URL}}", &state.config.base_url);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

pub async fn verify_status(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Value>, AppError> {
    let discord = read_session(&jar, &state.config.session_secret).ok();

    let osu_link: Option<(i64, String)> = match &discord {
        Some((did, _)) => {
            sqlx::query_as("SELECT osu_user_id, osu_username FROM osu_users WHERE discord_id = $1")
                .bind(did)
                .fetch_optional(&state.pool)
                .await?
        }
        None => None,
    };

    Ok(Json(json!({
        "signed_in_discord": discord.is_some(),
        "discord_username": discord.as_ref().map(|(_, n)| n.clone()),
        "linked_osu": osu_link.is_some(),
        "osu_user_id": osu_link.as_ref().map(|(id, _)| id),
        "osu_username": osu_link.as_ref().map(|(_, u)| u.clone()),
        "osu_oauth_configured": state.config.osu.client_id.is_some(),
    })))
}

pub async fn verify_unlink(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, _) = read_session(&jar, &state.config.session_secret)?;

    let removed: Option<(i64,)> =
        sqlx::query_as("DELETE FROM osu_users WHERE discord_id = $1 RETURNING osu_user_id")
            .bind(&discord_id)
            .fetch_optional(&state.pool)
            .await?;

    let Some((osu_user_id,)) = removed else {
        return Err(AppError::NotFound(
            "No linked osu! account to unlink.".into(),
        ));
    };

    // `osu_stats` cascade-deletes via the FK on `osu_user_id`, so nothing
    // to do there. Just kick the role re-evaluation.
    crate::services::jobs::enqueue_player_sync(&state.pool, &discord_id).await?;

    tracing::info!(discord_id = %discord_id, osu_user_id, "Player unlinked");

    Ok(Json(json!({ "success": true })))
}

/// Convention 27: login redirects use a *relative* `return_to=`.
pub async fn verify_login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let path = path_only(&state.config.base_url);
    let return_to = format!("{path}/verify");
    let url = format!(
        "{}/auth/login?return_to={}",
        state.config.auth_gateway_url,
        urlencoding::encode(&return_to)
    );
    Redirect::to(&url)
}

fn path_only(base_url: &str) -> String {
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(slash) = base_url[after_scheme..].find('/') {
            return base_url[after_scheme + slash..]
                .trim_end_matches('/')
                .to_string();
        }
    }
    String::new()
}

/// Start the osu! OAuth flow. Returns `{authorize_url}` — the page JS does
/// the redirect so the click is unmistakably a user action.
pub async fn verify_osu(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, _) = read_session(&jar, &state.config.session_secret)?;

    let client_id = state.config.osu.client_id.as_deref().ok_or_else(|| {
        AppError::Internal(
            "OSU_CLIENT_ID is not configured on this server. Ask the operator to set it.".into(),
        )
    })?;
    // We need the secret at exchange time, but reject early here so the
    // user gets a clean error instead of "Internal Server Error" after the
    // redirect dance.
    if state.config.osu.client_secret.is_none() {
        return Err(AppError::Internal(
            "OSU_CLIENT_SECRET is not configured on this server.".into(),
        ));
    }

    let state_token = Uuid::new_v4().to_string();
    let code_verifier = osu::new_code_verifier();
    oauth::insert_state(&state, &state_token, &code_verifier, &discord_id, None).await?;

    let url = build_authorize_url(
        client_id,
        &oauth::redirect_uri(&state.config.base_url),
        &state_token,
        &code_verifier,
    );
    Ok(Json(json!({ "authorize_url": url })))
}

fn build_authorize_url(client_id: &str, redirect_uri: &str, state: &str, verifier: &str) -> String {
    let challenge = osu::pkce_s256(verifier);
    let qs = serde_urlencoded::to_string([
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", osu::USER_OAUTH_SCOPES),
        ("state", state),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ])
    .expect("urlencoded never fails for &str");
    format!("{}?{}", osu::AUTHORIZE_URL, qs)
}
