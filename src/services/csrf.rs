//! Origin-based CSRF defense for cookie-authenticated state-changing routes.
//!
//! The browser-side `CorsLayer` allowlist already prevents cross-origin XHR
//! with credentials from non-allowlisted sites, but it relies on the
//! browser honoring CORS. This server-side check is a second wall: it
//! inspects `Origin` on every state-changing admin request and rejects when
//! the value isn't on our allowlist. A browser always sets `Origin` on
//! POST/PUT/DELETE from a real page; curl / server-to-server calls don't,
//! which is exactly what we want to reject on admin write paths.
//!
//! Routes authenticated via `Authorization: Bearer ifs:…` (iframe session)
//! do NOT need Origin checks — the token's HMAC binding to
//! `(discord_id, guild_id, role_id)` is itself the CSRF defense.

use axum::http::HeaderMap;

use crate::error::AppError;

pub fn verify_origin(headers: &HeaderMap, allowed_origins: &[String]) -> Result<(), AppError> {
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::Forbidden("State-changing requests must include an Origin header.".into())
        })?;

    let origin_norm = origin.trim_end_matches('/');
    for allowed in allowed_origins {
        if origin_norm == allowed.trim_end_matches('/') {
            return Ok(());
        }
    }
    Err(AppError::Forbidden(format!(
        "Origin '{origin}' is not allowed for state-changing requests."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn with(origin: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("origin", HeaderValue::from_str(origin).unwrap());
        h
    }

    fn allowed() -> Vec<String> {
        vec![
            "https://app.rolelogic.com".into(),
            "https://plugin.example.com".into(),
        ]
    }

    #[test]
    fn accepts_exact_match() {
        assert!(verify_origin(&with("https://app.rolelogic.com"), &allowed()).is_ok());
    }
    #[test]
    fn accepts_trailing_slash() {
        assert!(verify_origin(&with("https://app.rolelogic.com/"), &allowed()).is_ok());
    }
    #[test]
    fn rejects_missing() {
        assert!(verify_origin(&HeaderMap::new(), &allowed()).is_err());
    }
    #[test]
    fn rejects_attacker_origin() {
        assert!(verify_origin(&with("https://evil.example"), &allowed()).is_err());
    }
    #[test]
    fn rejects_subdomain_of_allowed() {
        assert!(verify_origin(&with("https://attacker.rolelogic.com"), &allowed()).is_err());
    }
}
