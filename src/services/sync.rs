//! Sync engine — per-player (lightweight) and per-role-link (bulk).
//!
//! Dispatch targets for jobs claimed by [`crate::tasks::job_worker`].
//!
//! - Guild membership comes from the Auth Gateway `/auth/internal/*`,
//!   never a local JOIN.
//! - Gateway HTTP failures bubble up (the worker retries) — we never clear
//!   a role on a transient lookup failure.
//! - A `RoleLinkNotFound` from RoleLogic deletes the orphan local row
//!   instead of retrying forever (Convention 47).

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use futures_util::stream::{self, StreamExt};

use crate::error::AppError;
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;
use crate::services::auth_gateway;
use crate::services::condition_eval;
use crate::services::rule_sql::{self, Bind};
use crate::AppState;

/// JOINs `osu_users` with the per-mode row of `osu_stats`. Mirrors the
/// builder in [`rule_sql::target_expr`] one-for-one — every column the
/// builder reads is produced here, defaulted via COALESCE where the SQL
/// expression COALESCEs.
const FACTS_SELECT: &str = "SELECT \
    ou.is_supporter                        AS is_supporter, \
    ou.is_active                           AS is_active, \
    ou.is_restricted                       AS is_restricted, \
    (COALESCE(ou.badge_count, 0) > 0)      AS has_badge, \
    (COALESCE(array_length(ou.groups, 1), 0) > 0) AS has_group_badge, \
    ou.osu_joined_at                       AS osu_joined_at, \
    ou.last_visit_at                       AS last_visit_at, \
    COALESCE(ou.badge_count, 0)            AS badge_count, \
    COALESCE(ou.follower_count, 0)         AS follower_count, \
    COALESCE(ou.mapping_followers, 0)      AS mapping_subscribers, \
    COALESCE(ou.kudosu_total, 0)           AS kudosu, \
    COALESCE(ou.ranked_beatmaps, 0)        AS ranked_beatmaps, \
    COALESCE(ou.loved_beatmaps, 0)         AS loved_beatmaps, \
    COALESCE(ou.mapping_playcount, 0)      AS mapping_playcount, \
    COALESCE(ou.replays_watched_others, 0) AS replays_watched_by_others, \
    COALESCE(ou.favourite_beatmapsets, 0)  AS favourite_count, \
    ou.country_code                        AS country_code, \
    ou.osu_username                        AS username, \
    ou.groups                              AS groups, \
    ou.playstyles                          AS playstyles, \
    os.global_rank                         AS global_rank, \
    os.country_rank                        AS country_rank, \
    COALESCE(os.performance_points, 0)     AS performance_points, \
    COALESCE(os.play_count, 0)             AS play_count, \
    COALESCE(os.play_time_hours, 0)        AS play_time_hours, \
    COALESCE(os.total_score, 0)::bigint    AS total_score, \
    COALESCE(os.ranked_score, 0)::bigint   AS ranked_score, \
    COALESCE(os.hit_accuracy, 0)           AS hit_accuracy, \
    COALESCE(os.max_combo, 0)              AS max_combo, \
    COALESCE(os.level_int, 0)              AS level_int, \
    COALESCE(os.count_ss + os.count_ss_silver, 0) AS ss_count, \
    COALESCE(os.count_s + os.count_s_silver, 0)   AS s_count, \
    COALESCE(os.count_a, 0)                AS a_count \
  FROM osu_users ou \
  LEFT JOIN osu_stats os \
    ON os.osu_user_id = ou.osu_user_id AND os.mode = $2 \
  WHERE ou.discord_id = $1";

#[derive(sqlx::FromRow)]
struct FactsRow {
    is_supporter: bool,
    is_active: bool,
    is_restricted: bool,
    has_badge: bool,
    has_group_badge: bool,
    osu_joined_at: DateTime<Utc>,
    last_visit_at: Option<DateTime<Utc>>,
    badge_count: i32,
    follower_count: i32,
    mapping_subscribers: i32,
    kudosu: i32,
    ranked_beatmaps: i32,
    loved_beatmaps: i32,
    mapping_playcount: i32,
    replays_watched_by_others: i32,
    favourite_count: i32,
    country_code: Option<String>,
    username: String,
    groups: Vec<String>,
    playstyles: Vec<String>,
    global_rank: Option<i32>,
    country_rank: Option<i32>,
    performance_points: i32,
    play_count: i32,
    play_time_hours: i32,
    total_score: i64,
    ranked_score: i64,
    hit_accuracy: i32,
    max_combo: i32,
    level_int: i32,
    ss_count: i32,
    s_count: i32,
    a_count: i32,
}

impl From<FactsRow> for Facts {
    fn from(r: FactsRow) -> Self {
        Facts {
            is_supporter: r.is_supporter,
            is_active: r.is_active,
            is_restricted: r.is_restricted,
            has_badge: r.has_badge,
            has_group_badge: r.has_group_badge,
            osu_joined_at: Some(r.osu_joined_at),
            last_visit_at: r.last_visit_at,
            badge_count: r.badge_count as i64,
            follower_count: r.follower_count as i64,
            mapping_subscribers: r.mapping_subscribers as i64,
            kudosu: r.kudosu as i64,
            ranked_beatmaps: r.ranked_beatmaps as i64,
            loved_beatmaps: r.loved_beatmaps as i64,
            mapping_playcount: r.mapping_playcount as i64,
            replays_watched_by_others: r.replays_watched_by_others as i64,
            favourite_count: r.favourite_count as i64,
            country_code: r.country_code,
            username: r.username,
            groups: r.groups,
            playstyles: r.playstyles,
            global_rank: r.global_rank.map(i64::from),
            country_rank: r.country_rank.map(i64::from),
            performance_points: r.performance_points as i64,
            play_count: r.play_count as i64,
            play_time_hours: r.play_time_hours as i64,
            total_score: r.total_score,
            ranked_score: r.ranked_score,
            hit_accuracy: r.hit_accuracy as i64,
            max_combo: r.max_combo as i64,
            level_int: r.level_int as i64,
            ss_count: r.ss_count as i64,
            s_count: r.s_count as i64,
            a_count: r.a_count as i64,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-player sync — fired after link / unlink / refresh / unlink.
// ---------------------------------------------------------------------------

pub async fn sync_for_player(discord_id: &str, state: &AppState) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let guild_ids = auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        discord_id,
    )
    .await?;
    if guild_ids.is_empty() {
        return Ok(());
    }

    let role_links = sqlx::query_as::<_, (String, String, String, serde_json::Value)>(
        "SELECT guild_id, role_id, api_token, rule_tree \
         FROM role_links WHERE guild_id = ANY($1)",
    )
    .bind(&guild_ids[..])
    .fetch_all(pool)
    .await?;
    if role_links.is_empty() {
        return Ok(());
    }

    // "Linked" = the member connected an osu! account at all. This is the
    // only fact a `grant_on_any_player` rule needs.
    let is_linked: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM osu_users WHERE discord_id = $1)")
            .bind(discord_id)
            .fetch_one(pool)
            .await?;

    let existing: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_assignments WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    enum Action {
        Add(String, String, String),
        Remove(String, String, String),
    }

    let mut actions: Vec<Action> = Vec::new();
    for (guild_id, role_id, api_token, raw_tree) in &role_links {
        let tree: RuleTree = serde_json::from_value(raw_tree.clone()).unwrap_or_default();

        let qualifies = if tree.grant_on_any_player {
            is_linked
        } else if tree.groups.is_empty() {
            // Convention 42: unconfigured rule grants the role to nobody.
            false
        } else {
            let facts_row: Option<FactsRow> = sqlx::query_as(FACTS_SELECT)
                .bind(discord_id)
                .bind(tree.default_mode.as_str())
                .fetch_optional(pool)
                .await?;
            match facts_row {
                Some(row) => condition_eval::evaluate(&tree, &Facts::from(row)),
                None => false, // not linked → qualifies for nothing
            }
        };

        let assigned = existing.contains(&(guild_id.clone(), role_id.clone()));
        match (qualifies, assigned) {
            (true, false) => actions.push(Action::Add(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            (false, true) => actions.push(Action::Remove(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            _ => {}
        }
    }

    if actions.is_empty() {
        return Ok(());
    }

    let did = discord_id.to_string();
    stream::iter(actions)
        .for_each_concurrent(10, |action| {
            let pool = pool.clone();
            let rl = rl_client.clone();
            let did = did.clone();
            async move {
                match action {
                    Action::Add(g, r, tok) => {
                        match rl.add_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(AppError::UserLimitReached { limit }) => {
                                tracing::warn!(g, r, did, limit, "user limit reached");
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "add_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
                             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                    Action::Remove(g, r, tok) => {
                        match rl.remove_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "remove_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "DELETE FROM role_assignments \
                             WHERE guild_id=$1 AND role_id=$2 AND discord_id=$3",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                }
            }
        })
        .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-role-link sync (bulk).
// ---------------------------------------------------------------------------

pub async fn sync_for_role_link(
    guild_id: &str,
    role_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl = &state.rl_client;

    let link = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT api_token, rule_tree FROM role_links \
         WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let Some((api_token, raw_tree)) = link else {
        return Ok(());
    };
    let tree: RuleTree = serde_json::from_value(raw_tree).unwrap_or_default();

    // Convention 42: NOT grant_on_any AND no groups ⇒ grant to nobody. The
    // SQL builder would also return "FALSE" here, but draining short-
    // circuits the gateway call + a PUT round-trip.
    if !tree.grant_on_any_player && tree.groups.is_empty() {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }

    let member_ids = auth_gateway::fetch_guild_member_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await?;
    if member_ids.is_empty() {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }

    let (_count, user_limit) = match rl.get_user_info(guild_id, role_id, &api_token).await {
        Ok(v) => v,
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(AppError::RoleLinkDisabled) => return Ok(()),
        Err(e) => return Err(e),
    };

    let qualifying: Vec<String> = if tree.grant_on_any_player {
        sqlx::query_scalar(
            "SELECT discord_id FROM osu_users \
             WHERE discord_id = ANY($1::text[]) \
             ORDER BY discord_id LIMIT $2",
        )
        .bind(&member_ids)
        .bind(user_limit as i64)
        .fetch_all(pool)
        .await?
    } else {
        // $1 = mode (text), $2 = member_ids, rule binds from $3, limit last.
        let (rule_where, binds) = rule_sql::build_rule_where(&tree, 2);
        let limit_idx = 2 + binds.len() + 1;
        let query = format!(
            "SELECT DISTINCT ou.discord_id \
             FROM osu_users ou \
             LEFT JOIN osu_stats os \
               ON os.osu_user_id = ou.osu_user_id AND os.mode = $1 \
             WHERE ou.discord_id = ANY($2::text[]) \
               AND ({rule_where}) \
             ORDER BY ou.discord_id \
             LIMIT ${limit_idx}"
        );
        let mut q = sqlx::query_scalar::<_, String>(&query)
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
        q = q.bind(user_limit as i64);
        q.fetch_all(pool).await?
    };

    // Skip the RoleLogic PUT entirely when the computed set already equals
    // what's assigned. Both lists are ordered + de-duped, so `==` is an
    // exact set comparison.
    let current: Vec<String> = sqlx::query_scalar(
        "SELECT discord_id FROM role_assignments \
         WHERE guild_id = $1 AND role_id = $2 ORDER BY discord_id",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_all(pool)
    .await?;
    if current == qualifying {
        return Ok(());
    }

    match rl
        .upload_users(guild_id, role_id, &qualifying, &api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    if !qualifying.is_empty() {
        sqlx::query(
            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
             SELECT $1, $2, UNNEST($3::text[])",
        )
        .bind(guild_id)
        .bind(role_id)
        .bind(&qualifying)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn drain_to_empty(
    guild_id: &str,
    role_id: &str,
    api_token: &str,
    state: &AppState,
) -> Result<(), AppError> {
    // Already empty? Skip the PUT — stops a repeated "grant nobody" sync
    // from re-PUTting an empty set every cycle.
    let any: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE guild_id=$1 AND role_id=$2)",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_one(&state.pool)
    .await?;
    if !any {
        return Ok(());
    }

    match state
        .rl_client
        .upload_users(guild_id, role_id, &[], api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, &state.pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    Ok(())
}

/// Delete a role_link the RoleLogic API reports as gone. CASCADE clears
/// role_assignments. Best-effort: never propagates DB errors.
async fn delete_orphan_role_link(guild_id: &str, role_id: &str, pool: &sqlx::PgPool) {
    tracing::warn!(
        guild_id,
        role_id,
        "Role link not found on RoleLogic; removing orphaned local row"
    );
    if let Err(e) = sqlx::query("DELETE FROM role_links WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(pool)
        .await
    {
        tracing::error!(guild_id, role_id, "Failed to delete orphan role_link: {e}");
    }
}
