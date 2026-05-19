//! Default-deny security headers applied to every response. Per-route
//! handlers can override individual headers (e.g. admin pages that need to
//! be iframed by the RoleLogic dashboard set their own
//! `Content-Security-Policy` *before* this layer runs — those values are
//! preserved via `entry().or_insert()`).

use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// CSP for any HTML that should never be embedded in a frame (member-
/// facing verify page, users list, error pages).
pub const PUBLIC_PAGE_CSP: &str = "frame-ancestors 'none'";

/// Build the `Content-Security-Policy` value for admin pages embedded
/// inside the RoleLogic dashboard iframe. Falls back to `*` only when the
/// operator hasn't configured `RL_DASHBOARD_ORIGIN` (dev / self-hosted).
pub fn admin_iframe_csp(dashboard_origin: Option<&str>) -> String {
    let ancestor = dashboard_origin.unwrap_or("*");
    format!("frame-ancestors {ancestor}")
}

pub async fn baseline(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();

    h.entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(PUBLIC_PAGE_CSP));
    h.entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    h.entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("strict-origin-when-cross-origin"));
    h.entry(header::STRICT_TRANSPORT_SECURITY)
        .or_insert(HeaderValue::from_static(
            "max-age=31536000; includeSubDomains",
        ));

    resp
}
