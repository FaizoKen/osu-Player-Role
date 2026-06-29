//! Admin routes for the iframe role-config page and per-guild settings.
//!
//! Dual-mode access (Convention 45): every protected handler accepts EITHER
//! a `Bearer ifs:…` iframe-session token (RoleLogic dashboard embed) OR an
//! `rl_session` cookie + Manage-Server check (direct nav).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::models::condition::{ConditionOperator, ConditionTarget, TargetKind};
use crate::models::mode::Mode;
use crate::models::rule::{RuleTree, MAX_CONDITIONS_PER_GROUP, MAX_GROUPS};
use crate::services::auth::{extract_bearer, require_manager};
use crate::services::rule_sql::{self, Bind};
use crate::services::rule_validator::{self, RuleTreeBody};
use crate::services::security_headers::admin_iframe_csp;
use crate::services::{auth_gateway, csrf, jobs, rl_token};
use crate::AppState;

const ROLE_CONFIG_TEMPLATE: &str = include_str!("../../templates/role_config.html");

// ---------------------------------------------------------------------
// Iframe role-config page (dual-mode: rl_token JWT entry OR cookie+manager)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RoleConfigPageQuery {
    #[serde(default)]
    rl_token: Option<String>,
}

pub async fn role_config_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Query(query): Query<RoleConfigPageQuery>,
) -> Response {
    let has_rl_token = query
        .rl_token
        .as_deref()
        .map(|t| !t.is_empty())
        .unwrap_or(false);

    // `read_only` is true when a developer is impersonating the user.
    let (iframe_session, read_only) = match query.rl_token.as_deref() {
        Some(token) if !token.is_empty() => {
            match verify_iframe_entry(&state, &guild_id, &role_id, token).await {
                Ok((t, ro)) => (Some(t), ro),
                Err(resp) => return resp,
            }
        }
        _ => (None, false),
    };

    // Direct-nav path: cookie + Manage Server. A cross-site iframe will NOT
    // carry our first-party `rl_session` cookie, so landing here with no
    // rl_token while the request smells like a frame load almost always
    // means RoleLogic never appended `?rl_token=`. Surface that precisely
    // instead of a dead-end "sign in" the user can't action.
    if iframe_session.is_none() {
        if let Err(e) = require_manager(&state, &jar, &guild_id).await {
            if !has_rl_token && looks_embedded(&headers) {
                tracing::warn!(
                    guild_id,
                    role_id,
                    base_url = %state.config.base_url,
                    "role_config_page reached inside an iframe with no rl_token — \
                     RoleLogic did not pass an auth token. Verify BASE_URL exactly \
                     matches the plugin URL registered in RoleLogic."
                );
                return render_iframe_no_token(&state);
            }
            return render_signin_page(&state, &e.to_string());
        }
    }

    let body = ROLE_CONFIG_TEMPLATE
        .replace("__BASE_URL__", &state.config.base_url)
        .replace("__GUILD_ID__", &guild_id)
        .replace("__ROLE_ID__", &role_id)
        .replace("__IFRAME_TOKEN__", iframe_session.as_deref().unwrap_or(""))
        .replace("__READ_ONLY__", if read_only { "1" } else { "0" });

    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
            (
                header::CACHE_CONTROL,
                "private, max-age=300, must-revalidate".to_string(),
            ),
        ],
        body,
    )
        .into_response()
}

/// Verify `?rl_token=…` and return a freshly minted iframe-session token.
/// On failure returns a rendered error page so the iframe shows something
/// useful instead of an empty body.
async fn verify_iframe_entry(
    state: &AppState,
    guild_id: &str,
    role_id: &str,
    rl_token_str: &str,
) -> Result<(String, bool), Response> {
    let api_token: Option<String> =
        sqlx::query_scalar("SELECT api_token FROM role_links WHERE guild_id = $1 AND role_id = $2")
            .bind(guild_id)
            .bind(role_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| render_inline_error(state, &format!("Database error: {e}")))?;

    let Some(api_token) = api_token else {
        return Err(render_inline_error(
            state,
            "This role link isn't registered with this plugin yet.",
        ));
    };

    let verified =
        rl_token::verify(rl_token_str, &api_token, &state.config.base_url).map_err(|e| {
            let msg = match e {
                rl_token::RlTokenError::Expired => {
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard."
                }
                rl_token::RlTokenError::BadSignature | rl_token::RlTokenError::Malformed => {
                    "Invalid auth token."
                }
                rl_token::RlTokenError::WrongAudience => "Token is for a different plugin.",
                rl_token::RlTokenError::WrongIssuer => "Token was not issued by RoleLogic.",
            };
            render_inline_error(state, msg)
        })?;

    if verified.guild_id != guild_id || verified.role_id != role_id {
        return Err(render_inline_error(
            state,
            "Token does not match this role link.",
        ));
    }

    if verified.read_only {
        tracing::info!(
            guild_id,
            role_id,
            target = %verified.discord_id,
            actor = verified.actor_id.as_deref().unwrap_or("?"),
            "Role config opened read-only (developer impersonation)"
        );
    }

    // Carry the read-only flag into the minted iframe-session so every XHR is
    // gated; return it too so the page renders in read-only mode.
    let token = rl_token::mint_iframe_session(
        &verified.discord_id,
        guild_id,
        role_id,
        verified.read_only,
        &state.config.session_secret,
    );
    Ok((token, verified.read_only))
}

fn render_inline_error(state: &AppState, message: &str) -> Response {
    let base_url = &state.config.base_url;
    let msg = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cannot load configuration</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:32px 24px;line-height:1.5}}
h1{{color:#fca5a5;font-size:18px;margin-bottom:10px}}p{{color:#9aa3b2}}</style>
</head><body><h1>Cannot load configuration</h1><p>{msg}</p>
<p style="margin-top:14px;color:#7a8497">If you opened this from the RoleLogic dashboard, close and reopen the role's plugin tab.</p>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

fn looks_embedded(headers: &HeaderMap) -> bool {
    let h = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let dest = h("sec-fetch-dest");
    dest == "iframe" || dest == "frame" || h("sec-fetch-site") == "cross-site"
}

fn render_iframe_no_token(state: &AppState) -> Response {
    let base_url = &state.config.base_url;
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configuration unavailable</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:32px 24px;line-height:1.55;max-width:560px}}
h1{{color:#fbbf24;font-size:18px;margin:0 0 10px}}p{{color:#9aa3b2;margin:8px 0}}
code{{background:#0b0d12;padding:2px 6px;border-radius:4px;font-size:12px}}</style>
</head><body>
<h1>RoleLogic didn't pass an authentication token</h1>
<p>This plugin page must be opened from inside the RoleLogic dashboard, which
attaches a one-time token. None arrived with this request.</p>
<p><strong>If you're the server admin:</strong> close this tab and reopen the
role's plugin tab from RoleLogic. If it keeps happening, the plugin is
mis-registered — its <code>BASE_URL</code> must exactly match the URL
configured for this plugin in RoleLogic: HTTPS, no trailing slash, and
including the <code>/osu-player-role</code> path prefix.</p>
<p style="color:#7a8497;font-size:12px;margin-top:16px">Configured BASE_URL:
<code>{base_url}</code></p>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

fn render_signin_page(state: &AppState, reason: &str) -> Response {
    let base_url = &state.config.base_url;
    let reason = reason
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — osu! Player Role</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:48px 24px;max-width:520px;margin:0 auto;line-height:1.55}}
h1{{font-size:22px;margin:0 0 12px}}p{{color:#9aa3b2}}
a.btn{{display:inline-block;margin-top:18px;background:#ff66aa;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600}}
.actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:18px}}
.actions a.btn{{margin-top:0}}
form.logout-form{{margin:0}}
button.logout{{background:none;color:#8a93a4;border:1px solid #2a2f3a;padding:10px 16px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit}}
button.logout:hover{{color:#fca5a5;border-color:#5c2630}}</style>
</head><body>
<h1>Sign in to continue</h1>
<p>You need <strong>Manage Server</strong> on this guild to edit its
osu! Player Role configuration.</p>
<p style="color:#7a8497;font-size:12px">{reason}</p>
<div class="actions">
  <a class="btn" id="login">Sign in with Discord</a>
  <form class="logout-form" method="POST" action="/auth/logout">
    <button type="submit" class="logout">Sign out &amp; try another account</button>
  </form>
</div>
<script>
const ORIGIN=new URL("{base_url}").origin;
const RET=encodeURIComponent(location.pathname);
document.getElementById('login').href=ORIGIN+'/auth/login?return_to='+RET;
document.querySelectorAll('form.logout-form').forEach(f=>{{
  f.action=ORIGIN+'/auth/logout?return_to='+RET;
}});
</script>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

/// Dual gate for role-link-scoped admin XHRs.
/// Outcome of an access check for the role-config endpoints: who is calling and
/// whether the session is read-only (a developer impersonating the user).
struct RoleConfigAccess {
    #[allow(dead_code)]
    discord_id: String,
    read_only: bool,
}

async fn require_role_config_access(
    state: &Arc<AppState>,
    jar: &CookieJar,
    headers: &HeaderMap,
    guild_id: &str,
    role_id: &str,
) -> Result<RoleConfigAccess, AppError> {
    if let Some(bearer) = extract_bearer(headers) {
        let s = rl_token::verify_iframe_session(&bearer, &state.config.session_secret).ok_or_else(
            || {
                AppError::UnauthorizedWith(
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard.".into(),
                )
            },
        )?;
        if s.guild_id != guild_id || s.role_id != role_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this role link.".into(),
            ));
        }
        return Ok(RoleConfigAccess { discord_id: s.discord_id, read_only: s.read_only });
    }
    let discord_id = require_manager(state, jar, guild_id).await?;
    Ok(RoleConfigAccess { discord_id, read_only: false })
}

// ---------------------------------------------------------------------
// GET /admin/{guild_id}/role/{role_id}/data
// ---------------------------------------------------------------------

pub async fn role_config_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Value, i32)>(
        "SELECT rule_tree, rule_tree_version \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        AppError::NotFound("This role link doesn't exist. Has it been added in RoleLogic?".into())
    })?;
    let (rule_tree, rule_tree_version) = link;
    let tree: RuleTree = serde_json::from_value(rule_tree).unwrap_or_default();

    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    Ok(Json(json!({
        "guild_id": guild_id,
        "role_id": role_id,
        "config": {
            "grant_on_any_player": tree.grant_on_any_player,
            "default_mode": tree.default_mode.as_str(),
            "groups": tree.groups,
        },
        "rule_tree_version": rule_tree_version,
        "modes": mode_catalog(),
        "targets": target_catalog(),
        "operators": operator_catalog(),
        "limits": {
            "max_groups": MAX_GROUPS,
            "max_conditions_per_group": MAX_CONDITIONS_PER_GROUP,
        },
        // Per-guild verify URL. The `?guild=<id>` query param is what the
        // verify page reads to (a) show "Linking for <Server>" context and
        // (b) auto-clear any existing opt-out so users who previously
        // disabled this server are re-enrolled in one click — no detour
        // through /auth/my_servers, no re-running the osu! OAuth flow.
        //
        // Guild IDs are Discord snowflakes (digits only) so they're safe to
        // splice directly into the query string without percent-encoding.
        "verify_url": format!("{}/verify?guild={}", state.config.base_url, guild_id),
        "users": {
            "url": format!("{}/users/{}", state.config.base_url, guild_id),
            "view_permission": view_permission,
        },
        "osu_oauth_configured": state.config.osu.client_id.is_some(),
    })))
}

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/role/{role_id}/save  (optimistic-locked)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RoleConfigSaveBody {
    pub rule_tree_version: i32,
    #[serde(flatten)]
    pub tree: RuleTreeBody,
}

pub async fn role_config_save(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RoleConfigSaveBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    let access = require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;
    // Read-only sessions (a developer impersonating the user) may view but not
    // write — the server-side half of the read-only contract.
    if access.read_only {
        return Err(AppError::Forbidden(
            "This configuration is read-only while impersonating a user.".into(),
        ));
    }

    let expected_version = body.rule_tree_version;
    let parsed = rule_validator::parse_rule_tree(body.tree)?;
    let tree_json = serde_json::to_value(&parsed.rule_tree)
        .map_err(|e| AppError::Internal(format!("serialize rule_tree: {e}")))?;

    let result = sqlx::query(
        "UPDATE role_links \
         SET rule_tree = $1, rule_tree_version = rule_tree_version + 1, updated_at = now() \
         WHERE guild_id = $2 AND role_id = $3 AND rule_tree_version = $4",
    )
    .bind(&tree_json)
    .bind(&guild_id)
    .bind(&role_id)
    .bind(expected_version)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT rule_tree_version FROM role_links WHERE guild_id=$1 AND role_id=$2",
        )
        .bind(&guild_id)
        .bind(&role_id)
        .fetch_optional(&state.pool)
        .await?;
        return match exists {
            None => Err(AppError::NotFound(
                "This role link doesn't exist. Has it been added in RoleLogic?".into(),
            )),
            Some(_) => Err(AppError::StaleVersion),
        };
    }

    let new_version: i32 = sqlx::query_scalar(
        "SELECT rule_tree_version FROM role_links WHERE guild_id=$1 AND role_id=$2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_one(&state.pool)
    .await?;

    if let Err(e) = jobs::enqueue_config_sync(&state.pool, &guild_id, &role_id).await {
        tracing::warn!(
            guild_id,
            role_id,
            "enqueue config_sync after save failed: {e}"
        );
    }

    tracing::info!(
        guild_id,
        role_id,
        groups = parsed.rule_tree.groups.len(),
        mode = parsed.rule_tree.default_mode.as_str(),
        grant_on_any = parsed.rule_tree.grant_on_any_player,
        "Role rule_tree updated"
    );

    Ok(Json(
        json!({ "success": true, "rule_tree_version": new_version }),
    ))
}

// ---------------------------------------------------------------------
// GET /admin/{guild_id}/role/{role_id}/preview  — count without saving
// POST same path with a proposed tree body — preview an unsaved rule
// ---------------------------------------------------------------------

pub async fn role_config_preview(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Value,)>(
        "SELECT rule_tree FROM role_links WHERE guild_id=$1 AND role_id=$2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Role link not found.".into()))?;
    let tree: RuleTree = serde_json::from_value(link.0).unwrap_or_default();

    preview_count_for(&state, &guild_id, &tree).await
}

pub async fn role_config_preview_edit(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RuleTreeBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;
    let parsed = rule_validator::parse_rule_tree(body)?;
    preview_count_for(&state, &guild_id, &parsed.rule_tree).await
}

async fn preview_count_for(
    state: &Arc<AppState>,
    guild_id: &str,
    tree: &RuleTree,
) -> Result<Json<Value>, AppError> {
    let nobody = !tree.grant_on_any_player && tree.groups.is_empty();
    if nobody {
        return Ok(Json(
            json!({ "matching": 0, "linked": 0, "available": true }),
        ));
    }

    let member_ids = match auth_gateway::fetch_guild_member_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => {
            return Ok(Json(json!({
                "available": false,
                "reason": "Member list temporarily unavailable; preview will work once the Auth Gateway responds."
            })))
        }
    };
    if member_ids.is_empty() {
        return Ok(Json(
            json!({ "matching": 0, "linked": 0, "available": true }),
        ));
    }

    let linked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM osu_users WHERE discord_id = ANY($1::text[])")
            .bind(&member_ids)
            .fetch_one(&state.pool)
            .await?;

    let matching: i64 = if tree.grant_on_any_player {
        linked
    } else {
        let (rule_where, binds) = rule_sql::build_rule_where(tree, 2);
        let query = format!(
            "SELECT count(DISTINCT ou.discord_id) \
             FROM osu_users ou \
             LEFT JOIN osu_stats os \
               ON os.osu_user_id = ou.osu_user_id AND os.mode = $1 \
             WHERE ou.discord_id = ANY($2::text[]) AND ({rule_where})"
        );
        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tree.default_mode.as_str())
            .bind(&member_ids);
        for b in &binds {
            q = match b {
                Bind::Bool(v) => q.bind(*v),
                Bind::Int(v) => q.bind(*v),
                Bind::Text(v) => q.bind(v.clone()),
                Bind::TextArray(v) => q.bind(v.clone()),
            };
        }
        q.fetch_one(&state.pool).await?
    };

    Ok(Json(json!({
        "available": true,
        "matching": matching,
        "linked": linked,
    })))
}

// ---------------------------------------------------------------------
// Catalogs consumed by the rule-builder front-end
// ---------------------------------------------------------------------

fn kind_str(k: TargetKind) -> &'static str {
    match k {
        TargetKind::Bool => "bool",
        TargetKind::Int => "int",
        TargetKind::String => "string",
    }
}

fn mode_catalog() -> Vec<Value> {
    Mode::ALL
        .iter()
        .map(|m| json!({"key": m.as_str(), "label": m.label()}))
        .collect()
}

fn target_catalog() -> Vec<Value> {
    use ConditionTarget::*;
    // Order matters — the UI renders in this order.
    let entries: &[(ConditionTarget, &str, &str, &str)] = &[
        // Per-mode (the rich osu! gameplay stats — most useful first)
        (
            GlobalRank,
            "Global rank",
            "per_mode",
            "Worldwide PP rank in the chosen mode. Lower is better (use \"at most 1000\" for top-1k).",
        ),
        (
            CountryRank,
            "Country rank",
            "per_mode",
            "PP rank within the user's country in the chosen mode.",
        ),
        (
            PerformancePoints,
            "Performance points (pp)",
            "per_mode",
            "Total pp in the chosen mode (rounded to whole pp).",
        ),
        (
            PlayCount,
            "Play count",
            "per_mode",
            "Total ranked plays in the chosen mode.",
        ),
        (
            PlayTimeHours,
            "Play time (hours)",
            "per_mode",
            "Total time spent playing this mode, in whole hours.",
        ),
        (
            HitAccuracy,
            "Hit accuracy (%)",
            "per_mode",
            "Whole-percent accuracy in this mode. \"At least 98\" means 98% or higher.",
        ),
        (
            LevelInt,
            "Level",
            "per_mode",
            "Profile level in this mode (ignores the level-progress fraction).",
        ),
        (
            TotalScore,
            "Total score",
            "per_mode",
            "Lifetime score in this mode (all plays, ranked or not).",
        ),
        (
            RankedScore,
            "Ranked score",
            "per_mode",
            "Lifetime ranked-only score in this mode.",
        ),
        (
            MaxCombo,
            "Max combo",
            "per_mode",
            "Highest combo achieved on any play in this mode.",
        ),
        (
            SsCount,
            "SS / X grade count",
            "per_mode",
            "Total SS (X) grades in this mode (silver and regular combined).",
        ),
        (
            SCount,
            "S grade count",
            "per_mode",
            "Total S grades in this mode (silver and regular combined).",
        ),
        (
            ACount,
            "A grade count",
            "per_mode",
            "Total A grades in this mode.",
        ),
        // Profile bools
        (
            IsSupporter,
            "Has osu!supporter tag",
            "profile",
            "True if the player currently has an active supporter tag.",
        ),
        (
            IsActive,
            "Is active (recently online)",
            "profile",
            "True if the user has visited osu! in the last 30 days.",
        ),
        (
            IsRestricted,
            "Is restricted",
            "profile",
            "True if the account is silenced / banned / restricted.",
        ),
        (
            HasBadge,
            "Has at least one badge",
            "profile",
            "True if the profile has any badge from osu! staff.",
        ),
        (
            HasGroupBadge,
            "Is in a user group",
            "profile",
            "True if the player belongs to any user group (BN, GMT, NAT, DEV, ALM, ...).",
        ),
        // Profile ints
        (
            AccountAgeDays,
            "Account age (days)",
            "profile",
            "Days since the osu! account was created. Use \"at least 365\" for \"1+ year old\".",
        ),
        (
            DaysSinceLastVisit,
            "Days since last visit",
            "profile",
            "Days since the last recorded visit. \"At most 7\" = active in last week.",
        ),
        (
            BadgeCount,
            "Badge count",
            "profile",
            "Number of profile badges. Use for tiered \"Elite Mapper\" / \"3+ badges\" roles.",
        ),
        (
            FollowerCount,
            "Followers",
            "profile",
            "Number of users following this player.",
        ),
        (
            MappingSubscribers,
            "Mapping followers",
            "profile",
            "People subscribed to this user's beatmaps.",
        ),
        (
            Kudosu,
            "Kudosu (total)",
            "profile",
            "Lifetime kudosu — mapping reputation.",
        ),
        (
            RankedBeatmaps,
            "Ranked beatmapsets",
            "profile",
            "Beatmapsets this user has authored that reached Ranked/Approved.",
        ),
        (
            LovedBeatmaps,
            "Loved beatmapsets",
            "profile",
            "Beatmapsets this user has authored that reached Loved.",
        ),
        (
            MappingPlaycount,
            "Mapping playcount (total)",
            "profile",
            "How often other players have played this user's maps.",
        ),
        (
            ReplaysWatchedByOthers,
            "Replays watched by others",
            "profile",
            "How often other players have watched this user's replays.",
        ),
        (
            FavouriteCount,
            "Favourited beatmapsets",
            "profile",
            "How many beatmapsets this player has favourited.",
        ),
        // Profile strings
        (
            CountryCode,
            "Country code (ISO)",
            "profile",
            "ISO-3166 two-letter country code (e.g. JP, KR, US, BR).",
        ),
        (
            Username,
            "osu! username",
            "profile",
            "Use for specific-username matches or regex patterns.",
        ),
        (
            GroupName,
            "User group identifier",
            "profile",
            "Short group ID: BN, NAT, GMT, DEV, ALM, BSC, LVD. Use \"is one of\" for several.",
        ),
        (
            Playstyle,
            "Playstyle",
            "profile",
            "mouse / keyboard / tablet / touch. Multi-valued — use \"is one of\".",
        ),
    ];
    entries
        .iter()
        .map(|(t, label, group, help)| {
            json!({
                "key": t.as_str(),
                "label": label,
                "kind": kind_str(t.kind()),
                "group": group,
                "help": help,
                "is_per_mode": t.is_per_mode(),
            })
        })
        .collect()
}

fn operator_catalog() -> Vec<Value> {
    use ConditionOperator::*;
    let all = [
        (Eq, "equals"),
        (Neq, "not equals"),
        (Gt, "greater than"),
        (Gte, "at least"),
        (Lt, "less than"),
        (Lte, "at most"),
        (Between, "between"),
        (Contains, "contains"),
        (Regex, "matches regex"),
        (In, "is one of"),
        (NotIn, "is not one of"),
    ];
    all.iter()
        .map(|(op, label)| {
            json!({
                "key": op.as_str(),
                "label": label,
                "valid_for": {
                    "bool": op.valid_for(TargetKind::Bool),
                    "int": op.valid_for(TargetKind::Int),
                    "string": op.valid_for(TargetKind::String),
                },
                "needs_value_end": matches!(op, Between),
                "value_is_list": matches!(op, In | NotIn),
            })
        })
        .collect()
}

// Rule presets now live client-side in templates/role_config.html (the
// "Who should get this role?" options), mirroring the Kick-Channel-Role
// reference. The server no longer ships a preset catalog — the data
// endpoint provides only modes/targets/operators/limits, which the
// Advanced builder needs.
