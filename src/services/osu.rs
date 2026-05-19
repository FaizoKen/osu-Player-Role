//! osu! API v2 client.
//!
//! Implements:
//!   * **Authorization code flow + PKCE** for the user verification path
//!     (`/verify` → "Link with osu!"). Scope: `identify` (read public
//!     profile + statistics).
//!   * **Client-credentials flow** for our background refresh worker — the
//!     `/users/{id}/{mode}` endpoint is happy to return any user's public
//!     profile authenticated as an app, no per-user token storage needed.
//!     This keeps the surface area small (no token rotation, no encrypted
//!     refresh_token at rest).
//!
//! Endpoints (from <https://osu.ppy.sh/docs/index.html>):
//!   * authorize:    https://osu.ppy.sh/oauth/authorize
//!   * token:        https://osu.ppy.sh/oauth/token
//!   * /me/{mode?}:  https://osu.ppy.sh/api/v2/me/{mode}
//!   * /users/{id}/{mode?}: https://osu.ppy.sh/api/v2/users/{id}/{mode}

#![allow(dead_code)] // a couple of helpers are wired for future use

use base64::Engine;
use governor::{Quota, RateLimiter};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::error::AppError;
use crate::models::mode::Mode;

pub const AUTHORIZE_URL: &str = "https://osu.ppy.sh/oauth/authorize";
pub const TOKEN_URL: &str = "https://osu.ppy.sh/oauth/token";
pub const API_BASE: &str = "https://osu.ppy.sh/api/v2";

/// Scope requested at user-OAuth authorize. `identify` returns basic
/// profile info; `public` lets us read user statistics endpoints.
pub const USER_OAUTH_SCOPES: &str = "identify public";

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

/// Decoded subset of the osu! `/me` and `/users/{id}` shapes we actually
/// read. Many fields are optional because the API omits them for fresh /
/// restricted accounts.
///
/// Also `Serialize` so we can store the raw payload in `osu_users.profile`
/// JSONB for forensics / future targets without a schema migration.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct OsuUser {
    pub id: i64,
    pub username: String,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub country: Option<Country>,
    #[serde(default)]
    pub profile_colour: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    pub join_date: String,
    #[serde(default)]
    pub last_visit: Option<String>,
    #[serde(default)]
    pub is_supporter: bool,
    #[serde(default)]
    pub support_level: i64,
    #[serde(default)]
    pub is_restricted: bool,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default)]
    pub playstyle: Option<Vec<String>>,
    #[serde(default)]
    pub badges: Option<Vec<Badge>>,
    #[serde(default)]
    pub groups: Option<Vec<Group>>,
    #[serde(default)]
    pub follower_count: Option<i64>,
    #[serde(default)]
    pub mapping_follower_count: Option<i64>,
    #[serde(default)]
    pub kudosu: Option<Kudosu>,
    #[serde(default)]
    pub ranked_beatmapset_count: Option<i64>,
    #[serde(default)]
    pub loved_beatmapset_count: Option<i64>,
    #[serde(default)]
    pub pending_beatmapset_count: Option<i64>,
    #[serde(default)]
    pub graveyard_beatmapset_count: Option<i64>,
    #[serde(default)]
    pub favourite_beatmapset_count: Option<i64>,
    #[serde(default)]
    pub mapping_follower_count_total: Option<i64>,
    /// `replays_watched_counts` is per-mode in the API; the totals come
    /// from the profile-level `replays_watched_by_others` field below.
    #[serde(default)]
    pub replays_watched_by_others: Option<i64>,
    /// `statistics` returns the user's stats for the *requested* mode (or
    /// their default mode if none was specified). The refresh worker calls
    /// `/users/{id}/{mode}` for each of the four modes and stores them
    /// individually in `osu_stats`.
    #[serde(default)]
    pub statistics: Option<UserStatistics>,
    /// Total plays across all of this user's *own* beatmaps. The
    /// /users/{id} payload exposes this as `mapping_followers` adjacent in
    /// recent API versions; we fall back to 0 if absent.
    #[serde(default)]
    pub beatmap_playcounts_count: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Country {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Badge {
    #[serde(default)]
    pub awarded_at: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub image_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Group {
    #[serde(default)]
    pub id: Option<i64>,
    /// Short identifier like "BN", "GMT", "NAT", "DEV", "ALM".
    #[serde(default)]
    pub identifier: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Kudosu {
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub available: i64,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Default)]
pub struct UserStatistics {
    /// Float pp; we round to integer at sync time.
    #[serde(default)]
    pub pp: Option<f64>,
    #[serde(default)]
    pub global_rank: Option<i64>,
    #[serde(default)]
    pub country_rank: Option<i64>,
    #[serde(default)]
    pub ranked_score: Option<i64>,
    #[serde(default)]
    pub total_score: Option<i64>,
    #[serde(default)]
    pub play_count: Option<i64>,
    /// In seconds. Convert to hours at sync time.
    #[serde(default)]
    pub play_time: Option<i64>,
    /// Float 0..100, can have decimals. Floored to int at sync time.
    #[serde(default)]
    pub hit_accuracy: Option<f64>,
    #[serde(default)]
    pub maximum_combo: Option<i64>,
    #[serde(default)]
    pub level: Option<Level>,
    #[serde(default)]
    pub grade_counts: Option<GradeCounts>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Default)]
pub struct Level {
    #[serde(default)]
    pub current: Option<i64>,
    #[serde(default)]
    pub progress: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Default)]
pub struct GradeCounts {
    #[serde(default)]
    pub ss: i64,
    #[serde(default)]
    pub ssh: i64,
    #[serde(default)]
    pub s: i64,
    #[serde(default)]
    pub sh: i64,
    #[serde(default)]
    pub a: i64,
}

#[derive(Clone)]
pub struct OsuClient {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
    /// ~60 req/min ceiling (osu! recommends keeping under that for public apps).
    rate_limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
}

impl OsuClient {
    pub fn new(client_id: String, client_secret: String) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("osu-player-role/0.1 (+https://plugin-rolelogic.faizo.net)")
            .timeout(Duration::from_secs(15))
            .build()
            .expect("Failed to build HTTP client");
        let quota = Quota::per_minute(NonZeroU32::new(50).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        Self {
            http,
            client_id,
            client_secret,
            rate_limiter,
        }
    }

    async fn permit(&self) {
        self.rate_limiter.until_ready().await;
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    // ---- OAuth ----

    /// Build the user-OAuth authorize URL with PKCE.
    pub fn authorize_url(&self, redirect_uri: &str, state: &str, code_verifier: &str) -> String {
        let challenge = pkce_s256(code_verifier);
        let qs = serde_urlencoded::to_string([
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", USER_OAUTH_SCOPES),
            ("state", state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
        .expect("urlencoded never fails for &str");
        format!("{AUTHORIZE_URL}?{qs}")
    }

    /// Exchange an authorization code + PKCE verifier for an access token.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, AppError> {
        self.permit().await;
        let resp = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", redirect_uri),
                ("code", code),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|e| AppError::OsuApi(format!("token exchange failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::OsuApi(format!(
                "token exchange returned {status}: {body}"
            )));
        }
        resp.json::<TokenResponse>()
            .await
            .map_err(|e| AppError::OsuApi(format!("token response not JSON: {e}")))
    }

    /// Obtain a client-credentials token for app-authenticated reads of
    /// arbitrary users' public profiles. Scope `public` is the only one
    /// allowed on this grant type.
    pub async fn client_credentials_token(&self) -> Result<TokenResponse, AppError> {
        self.permit().await;
        let resp = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", "public"),
            ])
            .send()
            .await
            .map_err(|e| AppError::OsuApi(format!("client_credentials failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::OsuApi(format!(
                "client_credentials returned {status}: {body}"
            )));
        }
        resp.json::<TokenResponse>()
            .await
            .map_err(|e| AppError::OsuApi(format!("token response not JSON: {e}")))
    }

    // ---- Profile reads ----

    /// `/me/{mode}` — used during the verification callback. Returns the
    /// authenticated user. Mode defaults to the user's preferred mode.
    pub async fn get_me(
        &self,
        access_token: &str,
        mode: Option<Mode>,
    ) -> Result<OsuUser, AppError> {
        self.permit().await;
        let url = match mode {
            Some(m) => format!("{API_BASE}/me/{}", m.as_str()),
            None => format!("{API_BASE}/me"),
        };
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|e| AppError::OsuApi(format!("/me failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::OsuApi(format!("/me returned {status}: {body}")));
        }
        resp.json::<OsuUser>()
            .await
            .map_err(|e| AppError::OsuApi(format!("/me response not JSON: {e}")))
    }

    /// `/users/{id}/{mode}` — used by the refresh worker, app-authenticated.
    pub async fn get_user(
        &self,
        access_token: &str,
        user_id: i64,
        mode: Mode,
    ) -> Result<OsuUser, AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/users/{user_id}/{}", mode.as_str());
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|e| AppError::OsuApi(format!("/users/{user_id} failed: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(AppError::OsuApi(format!("user {user_id} not found")));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::OsuApi(format!(
                "/users/{user_id} returned {status}: {body}"
            )));
        }
        resp.json::<OsuUser>()
            .await
            .map_err(|e| AppError::OsuApi(format!("/users response not JSON: {e}")))
    }
}

// -------------------------------------------------------------------------
// PKCE helpers
// -------------------------------------------------------------------------

/// Generate a fresh PKCE code_verifier. 43–128 chars from the unreserved
/// set; we use 64 random bytes encoded as URL-safe-no-pad base64.
pub fn new_code_verifier() -> String {
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256(verifier) → URL-safe-no-pad base64. Per RFC 7636 §4.2.
pub fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_known_vector() {
        // RFC 7636 §B example
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn code_verifier_charset() {
        let v = new_code_verifier();
        assert!(v.len() >= 43);
        assert!(v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')));
    }
}
