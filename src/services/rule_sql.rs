//! SQL WHERE-clause builder for bulk per-role-link sync.
//!
//! Pushes the same DNF semantics as [`crate::services::condition_eval::evaluate`]
//! down into Postgres so `sync_for_role_link` filters server-side instead
//! of loading every linked viewer's facts into memory.
//!
//! The clause references two aliases the caller must provide:
//!   * `ou` — osu_users
//!   * `os` — osu_stats (LEFT JOINed on the rule's `default_mode`; columns
//!     may be NULL for a player who never played the mode)
//!
//! NULL-handling mirrors the Rust evaluator's fail-closed behavior:
//! missing per-mode rows COALESCE numeric columns to 0 and leave nullable
//! columns (global_rank, country_rank) NULL so comparisons fail closed.

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::rule::RuleTree;

#[derive(Debug, Clone)]
pub enum Bind {
    Bool(bool),
    Int(i64),
    Text(String),
    TextArray(Vec<String>),
}

/// Returns ("clause", binds). Binds use parameter indices starting at
/// `bind_offset + 1`. Convention 42: `grant_on_any_player = false` AND no
/// groups ⇒ "FALSE" (match nobody). `grant_on_any_player = true` ⇒ "TRUE".
pub fn build_rule_where(tree: &RuleTree, bind_offset: usize) -> (String, Vec<Bind>) {
    if tree.grant_on_any_player {
        return ("TRUE".to_string(), vec![]);
    }
    if tree.groups.is_empty() {
        return ("FALSE".to_string(), vec![]);
    }

    let mut binds: Vec<Bind> = Vec::new();
    let mut group_clauses: Vec<String> = Vec::new();

    for group in &tree.groups {
        if group.conditions.is_empty() {
            group_clauses.push("FALSE".to_string());
            continue;
        }
        let mut cond_clauses: Vec<String> = Vec::new();
        for c in &group.conditions {
            cond_clauses.push(build_condition(c, bind_offset, &mut binds));
        }
        group_clauses.push(format!("({})", cond_clauses.join(" AND ")));
    }

    (format!("({})", group_clauses.join(" OR ")), binds)
}

/// SQL expression for a target. Bools COALESCE to false, ints to 0,
/// nullable strings/age expressions stay NULL-able (so comparisons fail
/// closed). Per-mode targets come off `os` (the LEFT-joined `osu_stats`
/// row scoped to the rule's `default_mode`).
fn target_expr(target: ConditionTarget) -> &'static str {
    use ConditionTarget::*;
    match target {
        // -- bool --
        IsSupporter => "COALESCE(ou.is_supporter, false)",
        IsActive => "COALESCE(ou.is_active, false)",
        IsRestricted => "COALESCE(ou.is_restricted, false)",
        HasBadge => "(COALESCE(ou.badge_count, 0) > 0)",
        HasGroupBadge => "(COALESCE(array_length(ou.groups, 1), 0) > 0)",

        // -- profile int --
        AccountAgeDays => "FLOOR(EXTRACT(EPOCH FROM (now() - ou.osu_joined_at)) / 86400)",
        DaysSinceLastVisit => "FLOOR(EXTRACT(EPOCH FROM (now() - ou.last_visit_at)) / 86400)",
        BadgeCount => "COALESCE(ou.badge_count, 0)",
        FollowerCount => "COALESCE(ou.follower_count, 0)",
        MappingSubscribers => "COALESCE(ou.mapping_followers, 0)",
        Kudosu => "COALESCE(ou.kudosu_total, 0)",
        RankedBeatmaps => "COALESCE(ou.ranked_beatmaps, 0)",
        LovedBeatmaps => "COALESCE(ou.loved_beatmaps, 0)",
        MappingPlaycount => "COALESCE(ou.mapping_playcount, 0)",
        ReplaysWatchedByOthers => "COALESCE(ou.replays_watched_others, 0)",
        FavouriteCount => "COALESCE(ou.favourite_beatmapsets, 0)",

        // -- profile string --
        CountryCode => "ou.country_code",
        Username => "ou.osu_username",
        // GroupName / Playstyle are list-valued (TEXT[]); we emit clauses
        // that operate on the array directly.
        GroupName => "ou.groups",
        Playstyle => "ou.playstyles",

        // -- per-mode int (NULL when the user has no row for default_mode) --
        GlobalRank => "os.global_rank",
        CountryRank => "os.country_rank",
        PerformancePoints => "COALESCE(os.performance_points, 0)",
        PlayCount => "COALESCE(os.play_count, 0)",
        PlayTimeHours => "COALESCE(os.play_time_hours, 0)",
        TotalScore => "COALESCE(os.total_score, 0)",
        RankedScore => "COALESCE(os.ranked_score, 0)",
        HitAccuracy => "COALESCE(os.hit_accuracy, 0)",
        MaxCombo => "COALESCE(os.max_combo, 0)",
        LevelInt => "COALESCE(os.level_int, 0)",
        SsCount => "COALESCE(os.count_ss + os.count_ss_silver, 0)",
        SCount => "COALESCE(os.count_s + os.count_s_silver, 0)",
        ACount => "COALESCE(os.count_a, 0)",
    }
}

fn build_condition(c: &Condition, bind_offset: usize, binds: &mut Vec<Bind>) -> String {
    use ConditionOperator::*;
    let target = c.target;
    let expr = target_expr(target);

    let next = |binds: &Vec<Bind>| bind_offset + binds.len() + 1;

    // GroupName / Playstyle are array-valued and need array-aware operators.
    if matches!(
        target,
        ConditionTarget::GroupName | ConditionTarget::Playstyle
    ) {
        return build_array_condition(c, expr, bind_offset, binds);
    }

    match c.operator {
        Eq => {
            if let Some(b) = c.value.as_bool() {
                let i = next(binds);
                binds.push(Bind::Bool(b));
                format!("{expr} = ${i}")
            } else if let Some(n) = c.value.as_i64() {
                let i = next(binds);
                binds.push(Bind::Int(n));
                format!("{expr} = ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                format!("{expr} = ${i}")
            }
        }
        Neq => {
            if let Some(n) = c.value.as_i64() {
                let i = next(binds);
                binds.push(Bind::Int(n));
                // Plain <> so NULL int (missing data) is NOT matched —
                // mirrors the Rust evaluator's fail-closed int behavior.
                format!("{expr} <> ${i}")
            } else {
                let i = next(binds);
                binds.push(Bind::Text(c.value.as_str().unwrap_or("").to_string()));
                // IS DISTINCT FROM so NULL string (unset country) DOES
                // satisfy `neq` — mirrors the Rust evaluator's string path.
                format!("{expr} IS DISTINCT FROM ${i}")
            }
        }
        Gt | Gte | Lt | Lte => {
            let n = c.value.as_i64().unwrap_or(0);
            let i = next(binds);
            binds.push(Bind::Int(n));
            let op = match c.operator {
                Gt => ">",
                Gte => ">=",
                Lt => "<",
                Lte => "<=",
                _ => unreachable!(),
            };
            format!("({expr}) {op} ${i}")
        }
        Between => {
            let lo = c.value.as_i64().unwrap_or(0);
            let hi = c.value_end.as_ref().and_then(|v| v.as_i64()).unwrap_or(lo);
            let ia = next(binds);
            binds.push(Bind::Int(lo));
            let ib = next(binds);
            binds.push(Bind::Int(hi));
            format!("(({expr}) >= ${ia} AND ({expr}) <= ${ib})")
        }
        Contains => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(format!("%{}%", escape_like(v))));
            format!("{expr} LIKE ${i}")
        }
        Regex => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(v.to_string()));
            format!("{expr} ~ ${i}")
        }
        In => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "FALSE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("{expr} = ANY(${i}::text[])")
        }
        NotIn => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "TRUE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("({expr} IS NOT NULL AND {expr} <> ALL(${i}::text[]))")
        }
    }
}

/// Array-valued targets (`groups`, `playstyles`). The TEXT[] column is
/// compared with array operators (`@>`, `&&`, ANY/ALL on a regex/LIKE
/// over `unnest`).
fn build_array_condition(
    c: &Condition,
    expr: &str,
    bind_offset: usize,
    binds: &mut Vec<Bind>,
) -> String {
    use ConditionOperator::*;
    let next = |binds: &Vec<Bind>| bind_offset + binds.len() + 1;
    match c.operator {
        Eq => {
            let v = c.value.as_str().unwrap_or("").to_string();
            let i = next(binds);
            binds.push(Bind::Text(v));
            format!("({expr} @> ARRAY[${i}::text])")
        }
        Neq => {
            let v = c.value.as_str().unwrap_or("").to_string();
            let i = next(binds);
            binds.push(Bind::Text(v));
            // NOT @> covers both "doesn't contain" and "empty array".
            format!("NOT ({expr} @> ARRAY[${i}::text])")
        }
        Contains => {
            let v = c.value.as_str().unwrap_or("");
            let i = next(binds);
            binds.push(Bind::Text(format!("%{}%", escape_like(v))));
            format!("EXISTS (SELECT 1 FROM unnest({expr}) AS x WHERE x LIKE ${i})")
        }
        Regex => {
            let v = c.value.as_str().unwrap_or("").to_string();
            let i = next(binds);
            binds.push(Bind::Text(v));
            format!("EXISTS (SELECT 1 FROM unnest({expr}) AS x WHERE x ~ ${i})")
        }
        In => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "FALSE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            // `&&` = arrays overlap. True iff any element of the user's
            // groups is in the admin's allowlist.
            format!("({expr} && ${i}::text[])")
        }
        NotIn => {
            let arr = str_array(c);
            if arr.is_empty() {
                return "TRUE".to_string();
            }
            let i = next(binds);
            binds.push(Bind::TextArray(arr));
            format!("NOT ({expr} && ${i}::text[])")
        }
        _ => "FALSE".to_string(),
    }
}

fn str_array(c: &Condition) -> Vec<String> {
    c.value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::condition::{Condition, ConditionOperator as Op, ConditionTarget as T};
    use crate::models::mode::Mode;
    use crate::models::rule::{ConditionGroup, RuleTree};
    use serde_json::json;

    fn cond(t: T, op: Op, v: serde_json::Value) -> Condition {
        Condition {
            target: t,
            operator: op,
            value: v,
            value_end: None,
        }
    }

    #[test]
    fn grant_on_any_is_true() {
        let t = RuleTree {
            grant_on_any_player: true,
            ..Default::default()
        };
        let (sql, binds) = build_rule_where(&t, 1);
        assert_eq!(sql, "TRUE");
        assert!(binds.is_empty());
    }

    #[test]
    fn convention_42_empty_is_false() {
        let t = RuleTree::default();
        let (sql, _) = build_rule_where(&t, 1);
        assert_eq!(sql, "FALSE");
    }

    #[test]
    fn top_1k_pp_clause() {
        let t = RuleTree {
            grant_on_any_player: false,
            default_mode: Mode::Mania,
            groups: vec![ConditionGroup {
                conditions: vec![cond(T::GlobalRank, Op::Lte, json!(1000))],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 1);
        assert!(sql.contains("os.global_rank"));
        assert!(sql.contains("<= $2"));
        assert_eq!(binds.len(), 1);
        assert!(matches!(binds[0], Bind::Int(1000)));
    }

    #[test]
    fn supporter_or_jp_or() {
        let t = RuleTree {
            grant_on_any_player: false,
            default_mode: Mode::Osu,
            groups: vec![
                ConditionGroup {
                    conditions: vec![cond(T::IsSupporter, Op::Eq, json!(true))],
                },
                ConditionGroup {
                    conditions: vec![cond(T::CountryCode, Op::Eq, json!("JP"))],
                },
            ],
        };
        let (sql, _) = build_rule_where(&t, 1);
        assert!(sql.contains(" OR "));
        assert!(sql.contains("ou.is_supporter"));
        assert!(sql.contains("ou.country_code"));
    }

    #[test]
    fn group_in_uses_array_overlap() {
        let t = RuleTree {
            grant_on_any_player: false,
            default_mode: Mode::Osu,
            groups: vec![ConditionGroup {
                conditions: vec![cond(T::GroupName, Op::In, json!(["BN", "NAT"]))],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 1);
        assert!(sql.contains(" && $2::text[]"));
        match &binds[0] {
            Bind::TextArray(v) => assert_eq!(v, &vec!["BN".to_string(), "NAT".to_string()]),
            _ => panic!(),
        }
    }

    #[test]
    fn between_emits_two_binds() {
        let mut c = cond(T::PerformancePoints, Op::Between, json!(5000));
        c.value_end = Some(json!(10_000));
        let t = RuleTree {
            grant_on_any_player: false,
            default_mode: Mode::Osu,
            groups: vec![ConditionGroup {
                conditions: vec![c],
            }],
        };
        let (sql, binds) = build_rule_where(&t, 0);
        assert!(sql.contains(">= $1") && sql.contains("<= $2"));
        assert_eq!(binds.len(), 2);
    }

    #[test]
    fn like_escapes_wildcards() {
        let t = RuleTree {
            grant_on_any_player: false,
            default_mode: Mode::Osu,
            groups: vec![ConditionGroup {
                conditions: vec![cond(T::Username, Op::Contains, json!("100%_real"))],
            }],
        };
        let (_, binds) = build_rule_where(&t, 0);
        match &binds[0] {
            Bind::Text(s) => assert_eq!(s, "%100\\%\\_real%"),
            _ => panic!(),
        }
    }
}
