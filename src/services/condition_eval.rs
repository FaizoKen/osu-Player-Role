//! Rust-side condition evaluation. Sync, fast, no I/O.
//!
//! Used by the player sync worker for one-player decisions. The per-role-
//! link bulk path uses [`crate::services::rule_sql::build_rule_where`]
//! instead — it pushes the same predicates down into Postgres.

use serde_json::Value;

use crate::models::condition::{Condition, ConditionOperator, ConditionTarget};
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;

/// Evaluate the rule tree against a player's facts.
///
/// - `grant_on_any_player = true` short-circuits to `true`.
/// - Otherwise an empty `groups` slice returns `false` (Convention 42).
/// - Otherwise: ANY group matches (OR) and each group requires ALL of its
///   conditions to match (AND). Empty groups are FALSE (defensive; the
///   validator already rejects them at save).
pub fn evaluate(tree: &RuleTree, facts: &Facts) -> bool {
    if tree.grant_on_any_player {
        return true;
    }
    if tree.groups.is_empty() {
        return false;
    }
    tree.groups
        .iter()
        .any(|g| !g.conditions.is_empty() && g.conditions.iter().all(|c| evaluate_single(c, facts)))
}

fn evaluate_single(c: &Condition, f: &Facts) -> bool {
    use ConditionTarget::*;
    match c.target {
        // ---- booleans ----
        IsSupporter => bool_match(c, f.is_supporter),
        IsActive => bool_match(c, f.is_active),
        IsRestricted => bool_match(c, f.is_restricted),
        HasBadge => bool_match(c, f.has_badge),
        HasGroupBadge => bool_match(c, f.has_group_badge),

        // ---- profile ints ----
        AccountAgeDays => int_match(c, days_since(f.osu_joined_at)),
        DaysSinceLastVisit => int_match(c, days_since(f.last_visit_at)),
        BadgeCount => int_match(c, Some(f.badge_count)),
        FollowerCount => int_match(c, Some(f.follower_count)),
        MappingSubscribers => int_match(c, Some(f.mapping_subscribers)),
        Kudosu => int_match(c, Some(f.kudosu)),
        RankedBeatmaps => int_match(c, Some(f.ranked_beatmaps)),
        LovedBeatmaps => int_match(c, Some(f.loved_beatmaps)),
        MappingPlaycount => int_match(c, Some(f.mapping_playcount)),
        ReplaysWatchedByOthers => int_match(c, Some(f.replays_watched_by_others)),
        FavouriteCount => int_match(c, Some(f.favourite_count)),

        // ---- profile strings ----
        CountryCode => string_match(c, f.country_code.as_deref()),
        Username => string_match(c, Some(f.username.as_str())),
        // GroupName / Playstyle are list-valued on the facts side; match
        // against ANY element. `eq` / `contains` apply per-element; `in` /
        // `not_in` test whether any element appears in the allowlist.
        GroupName => list_string_match(c, &f.groups),
        Playstyle => list_string_match(c, &f.playstyles),

        // ---- per-mode ints ----
        GlobalRank => int_match(c, f.global_rank),
        CountryRank => int_match(c, f.country_rank),
        PerformancePoints => int_match(c, Some(f.performance_points)),
        PlayCount => int_match(c, Some(f.play_count)),
        PlayTimeHours => int_match(c, Some(f.play_time_hours)),
        TotalScore => int_match(c, Some(f.total_score)),
        RankedScore => int_match(c, Some(f.ranked_score)),
        HitAccuracy => int_match(c, Some(f.hit_accuracy)),
        MaxCombo => int_match(c, Some(f.max_combo)),
        LevelInt => int_match(c, Some(f.level_int)),
        SsCount => int_match(c, Some(f.ss_count)),
        SCount => int_match(c, Some(f.s_count)),
        ACount => int_match(c, Some(f.a_count)),
    }
}

fn bool_match(c: &Condition, actual: bool) -> bool {
    if !matches!(c.operator, ConditionOperator::Eq) {
        return false;
    }
    c.value.as_bool().map(|v| v == actual).unwrap_or(false)
}

fn int_match(c: &Condition, actual: Option<i64>) -> bool {
    let Some(a) = actual else {
        return false; // missing data ⇒ fail-closed
    };
    let v = c.value.as_i64();
    match c.operator {
        ConditionOperator::Eq => v.map(|n| a == n).unwrap_or(false),
        ConditionOperator::Neq => v.map(|n| a != n).unwrap_or(false),
        ConditionOperator::Gt => v.map(|n| a > n).unwrap_or(false),
        ConditionOperator::Gte => v.map(|n| a >= n).unwrap_or(false),
        ConditionOperator::Lt => v.map(|n| a < n).unwrap_or(false),
        ConditionOperator::Lte => v.map(|n| a <= n).unwrap_or(false),
        ConditionOperator::Between => {
            let lo = v;
            let hi = c.value_end.as_ref().and_then(|x| x.as_i64());
            match (lo, hi) {
                (Some(lo), Some(hi)) => a >= lo && a <= hi,
                _ => false,
            }
        }
        _ => false,
    }
}

fn string_match(c: &Condition, actual: Option<&str>) -> bool {
    let Some(a) = actual else {
        // `neq` against missing string passes (so "country ≠ US" lets
        // accounts without a country code through — admins use this for
        // "anyone NOT in X").
        return matches!(c.operator, ConditionOperator::Neq);
    };
    let v = c.value.as_str();
    match c.operator {
        ConditionOperator::Eq => v.map(|s| a == s).unwrap_or(false),
        ConditionOperator::Neq => v.map(|s| a != s).unwrap_or(false),
        ConditionOperator::Contains => v.map(|s| a.contains(s)).unwrap_or(false),
        ConditionOperator::Regex => {
            let Some(pattern) = v else { return false };
            // `regex` crate has linear-time matching (no catastrophic
            // backtracking). Cap compiled size + DFA cache so a malicious
            // pattern can't OOM us — same caps as the save-time validator.
            let Ok(re) = regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
            else {
                return false;
            };
            re.is_match(a)
        }
        ConditionOperator::In => list_contains(&c.value, a),
        ConditionOperator::NotIn => !list_contains(&c.value, a),
        _ => false,
    }
}

/// Match a condition against a list-valued field (groups, playstyles).
/// Semantics:
///   * `eq` / `contains` / `regex` — true if ANY element matches.
///   * `neq` — true if NO element exactly equals the value (empty list also passes).
///   * `in` — true if ANY element is in the allowlist.
///   * `not_in` — true if NO element is in the disallowlist.
fn list_string_match(c: &Condition, actuals: &[String]) -> bool {
    let needle = c.value.as_str();
    match c.operator {
        ConditionOperator::Eq => {
            let Some(n) = needle else { return false };
            actuals.iter().any(|s| s == n)
        }
        ConditionOperator::Neq => {
            let Some(n) = needle else { return true };
            actuals.iter().all(|s| s != n)
        }
        ConditionOperator::Contains => {
            let Some(n) = needle else { return false };
            actuals.iter().any(|s| s.contains(n))
        }
        ConditionOperator::Regex => {
            let Some(p) = needle else { return false };
            let Ok(re) = regex::RegexBuilder::new(p)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
            else {
                return false;
            };
            actuals.iter().any(|s| re.is_match(s))
        }
        ConditionOperator::In => actuals.iter().any(|s| list_contains(&c.value, s)),
        ConditionOperator::NotIn => actuals.iter().all(|s| !list_contains(&c.value, s)),
        _ => false,
    }
}

fn list_contains(value: &Value, needle: &str) -> bool {
    value
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).any(|s| s == needle))
        .unwrap_or(false)
}

fn days_since(ts: Option<chrono::DateTime<chrono::Utc>>) -> Option<i64> {
    ts.map(|t| (chrono::Utc::now() - t).num_days())
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::models::condition::ConditionTarget as T;
    use crate::models::mode::Mode;
    use crate::models::rule::{ConditionGroup, RuleTree};
    use chrono::Duration;
    use serde_json::json;

    fn c(target: T, op: ConditionOperator, value: Value) -> Condition {
        Condition {
            target,
            operator: op,
            value,
            value_end: None,
        }
    }

    fn one_group(conds: Vec<Condition>) -> RuleTree {
        RuleTree {
            grant_on_any_player: false,
            default_mode: Mode::Osu,
            groups: vec![ConditionGroup { conditions: conds }],
        }
    }

    fn or_groups(g: Vec<Vec<Condition>>) -> RuleTree {
        RuleTree {
            grant_on_any_player: false,
            default_mode: Mode::Osu,
            groups: g
                .into_iter()
                .map(|cs| ConditionGroup { conditions: cs })
                .collect(),
        }
    }

    #[test]
    fn convention_42_unconfigured_means_nobody() {
        assert!(!evaluate(&RuleTree::default(), &Facts::default()));
    }

    #[test]
    fn grant_on_any_short_circuits_true() {
        let t = RuleTree {
            grant_on_any_player: true,
            ..Default::default()
        };
        assert!(evaluate(&t, &Facts::default()));
    }

    #[test]
    fn top_1k_globally_rule() {
        // "GlobalRank ≤ 1000 in chosen mode"
        let t = one_group(vec![c(T::GlobalRank, ConditionOperator::Lte, json!(1000))]);
        let mut f = Facts::default();
        f.global_rank = Some(800);
        assert!(evaluate(&t, &f));
        f.global_rank = Some(2000);
        assert!(!evaluate(&t, &f));
        // Unranked player — no rank set — must NOT match.
        f.global_rank = None;
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn supporter_or_jp_rule() {
        let t = or_groups(vec![
            vec![c(T::IsSupporter, ConditionOperator::Eq, json!(true))],
            vec![c(T::CountryCode, ConditionOperator::Eq, json!("JP"))],
        ]);
        let mut f = Facts::default();
        f.is_supporter = true;
        assert!(evaluate(&t, &f));
        f.is_supporter = false;
        f.country_code = Some("JP".into());
        assert!(evaluate(&t, &f));
        f.country_code = Some("US".into());
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn between_pp_inclusive() {
        let mut cond = c(
            T::PerformancePoints,
            ConditionOperator::Between,
            json!(5000),
        );
        cond.value_end = Some(json!(10000));
        let t = one_group(vec![cond]);
        let mut f = Facts::default();
        f.performance_points = 5000;
        assert!(evaluate(&t, &f));
        f.performance_points = 10000;
        assert!(evaluate(&t, &f));
        f.performance_points = 4999;
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn account_age_days_from_join_date() {
        let t = one_group(vec![c(
            T::AccountAgeDays,
            ConditionOperator::Gte,
            json!(365),
        )]);
        let mut f = Facts::default();
        f.osu_joined_at = Some(chrono::Utc::now() - Duration::days(400));
        assert!(evaluate(&t, &f));
        f.osu_joined_at = Some(chrono::Utc::now() - Duration::days(100));
        assert!(!evaluate(&t, &f));
    }

    #[test]
    fn group_name_in_list() {
        let t = one_group(vec![c(
            T::GroupName,
            ConditionOperator::In,
            json!(["BN", "NAT"]),
        )]);
        let mut f = Facts::default();
        f.groups = vec!["GMT".into()];
        assert!(!evaluate(&t, &f));
        f.groups = vec!["BN".into(), "GMT".into()];
        assert!(evaluate(&t, &f));
    }

    #[test]
    fn realistic_tiered_rule() {
        // Top 1k globally OR (supporter AND ≥10k plays in the mode) OR
        // (group ∈ {BN, GMT, NAT, DEV})
        let t = or_groups(vec![
            vec![c(T::GlobalRank, ConditionOperator::Lte, json!(1000))],
            vec![
                c(T::IsSupporter, ConditionOperator::Eq, json!(true)),
                c(T::PlayCount, ConditionOperator::Gte, json!(10_000)),
            ],
            vec![c(
                T::GroupName,
                ConditionOperator::In,
                json!(["BN", "GMT", "NAT", "DEV"]),
            )],
        ]);
        let mut f = Facts::default();
        f.global_rank = Some(500);
        assert!(evaluate(&t, &f));

        let mut f = Facts::default();
        f.is_supporter = true;
        f.play_count = 12_000;
        assert!(evaluate(&t, &f));

        let mut f = Facts::default();
        f.groups = vec!["BN".into()];
        assert!(evaluate(&t, &f));

        // Plain unranked viewer — nothing matches.
        assert!(!evaluate(&t, &Facts::default()));
    }

    #[test]
    fn bad_regex_returns_false_not_panic() {
        let t = one_group(vec![c(T::Username, ConditionOperator::Regex, json!("(("))]);
        let mut f = Facts::default();
        f.username = "anything".into();
        assert!(!evaluate(&t, &f));
    }
}
