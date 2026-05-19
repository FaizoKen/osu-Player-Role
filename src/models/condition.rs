//! Condition target / operator types used in the rule tree.
//!
//! - [`ConditionTarget`] names a fact we can read from a linked osu! user.
//! - [`ConditionOperator`] names a comparison.
//! - Validity of an (target, operator) combination is enforced at save time
//!   in [`crate::services::rule_validator`] using each target's `kind()`.
//!
//! Targets split into two groups (see `is_per_mode`):
//!   * **profile** — mode-independent (supporter status, country, badges, …)
//!   * **per-mode** — uses the rule's `default_mode` (rank, PP, plays, …)

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What kind of data this target produces. Drives which operators are valid
/// and how the rule_validator coerces literal values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Bool,
    Int,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionTarget {
    // ---- Profile facts (mode-independent) ----
    /// User has an active osu!supporter tag.
    IsSupporter,
    /// `last_visit` within the last 30 days. Pre-baked because comparing
    /// timestamps inside the evaluator is fiddly.
    IsActive,
    /// Account is silenced / banned / restricted.
    IsRestricted,
    /// `badge_count > 0`.
    HasBadge,
    /// In at least one osu! user group (BN / GMT / NAT / DEV / ALM / etc.).
    HasGroupBadge,
    /// Days since the osu! account was created.
    AccountAgeDays,
    /// Days since the last recorded visit to osu!. Lower = more active.
    DaysSinceLastVisit,
    /// Total badges on the profile.
    BadgeCount,
    /// People following this user.
    FollowerCount,
    /// People subscribed to this user's beatmaps (mapper following).
    MappingSubscribers,
    /// Total kudosu earned (mapping reputation).
    Kudosu,
    /// Count of ranked/approved beatmaps the user has authored.
    RankedBeatmaps,
    /// Count of loved beatmaps.
    LovedBeatmaps,
    /// Total playcount across all of the user's maps (mapper popularity).
    MappingPlaycount,
    /// Replays of this user's plays watched by other players.
    ReplaysWatchedByOthers,
    /// Beatmapsets this user has favourited.
    FavouriteCount,
    /// ISO-3166 country code, uppercase ("US", "JP", …).
    CountryCode,
    /// osu! username.
    Username,
    /// Exact osu! user group short name. Use `in` / `not_in` for "any of".
    GroupName,
    /// One of "mouse" | "keyboard" | "tablet" | "touch". Use `in` to allow
    /// multiple.
    Playstyle,

    // ---- Per-mode facts (use rule's default_mode) ----
    /// Global PP rank in this mode. `lte 1000` ⇒ "top 1k".
    GlobalRank,
    /// Country PP rank in this mode.
    CountryRank,
    /// Performance points, rounded to nearest integer.
    PerformancePoints,
    /// Total play count in this mode.
    PlayCount,
    /// Total time played in this mode, rounded down to hours.
    PlayTimeHours,
    /// Total score in this mode (BIGINT-backed).
    TotalScore,
    /// Ranked score in this mode (BIGINT-backed).
    RankedScore,
    /// Whole-percent hit accuracy in this mode (rounded down).
    HitAccuracy,
    /// Highest combo in this mode.
    MaxCombo,
    /// Integer level (drops the level progress fraction).
    LevelInt,
    /// Count of SS grades (regular *and* silver SS).
    SsCount,
    /// Count of S grades (regular *and* silver S).
    SCount,
    /// Count of A grades.
    ACount,
}

impl ConditionTarget {
    pub fn kind(self) -> TargetKind {
        use ConditionTarget::*;
        match self {
            IsSupporter | IsActive | IsRestricted | HasBadge | HasGroupBadge => TargetKind::Bool,
            AccountAgeDays
            | DaysSinceLastVisit
            | BadgeCount
            | FollowerCount
            | MappingSubscribers
            | Kudosu
            | RankedBeatmaps
            | LovedBeatmaps
            | MappingPlaycount
            | ReplaysWatchedByOthers
            | FavouriteCount
            | GlobalRank
            | CountryRank
            | PerformancePoints
            | PlayCount
            | PlayTimeHours
            | TotalScore
            | RankedScore
            | HitAccuracy
            | MaxCombo
            | LevelInt
            | SsCount
            | SCount
            | ACount => TargetKind::Int,
            CountryCode | Username | GroupName | Playstyle => TargetKind::String,
        }
    }

    /// True iff this target reads a per-game-mode stat (from `osu_stats`)
    /// and therefore depends on the rule tree's `default_mode`.
    pub fn is_per_mode(self) -> bool {
        use ConditionTarget::*;
        matches!(
            self,
            GlobalRank
                | CountryRank
                | PerformancePoints
                | PlayCount
                | PlayTimeHours
                | TotalScore
                | RankedScore
                | HitAccuracy
                | MaxCombo
                | LevelInt
                | SsCount
                | SCount
                | ACount
        )
    }

    pub fn as_str(self) -> &'static str {
        use ConditionTarget::*;
        match self {
            IsSupporter => "is_supporter",
            IsActive => "is_active",
            IsRestricted => "is_restricted",
            HasBadge => "has_badge",
            HasGroupBadge => "has_group_badge",
            AccountAgeDays => "account_age_days",
            DaysSinceLastVisit => "days_since_last_visit",
            BadgeCount => "badge_count",
            FollowerCount => "follower_count",
            MappingSubscribers => "mapping_subscribers",
            Kudosu => "kudosu",
            RankedBeatmaps => "ranked_beatmaps",
            LovedBeatmaps => "loved_beatmaps",
            MappingPlaycount => "mapping_playcount",
            ReplaysWatchedByOthers => "replays_watched_by_others",
            FavouriteCount => "favourite_count",
            CountryCode => "country_code",
            Username => "username",
            GroupName => "group_name",
            Playstyle => "playstyle",
            GlobalRank => "global_rank",
            CountryRank => "country_rank",
            PerformancePoints => "performance_points",
            PlayCount => "play_count",
            PlayTimeHours => "play_time_hours",
            TotalScore => "total_score",
            RankedScore => "ranked_score",
            HitAccuracy => "hit_accuracy",
            MaxCombo => "max_combo",
            LevelInt => "level_int",
            SsCount => "ss_count",
            SCount => "s_count",
            ACount => "a_count",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        use ConditionTarget::*;
        Some(match s {
            "is_supporter" => IsSupporter,
            "is_active" => IsActive,
            "is_restricted" => IsRestricted,
            "has_badge" => HasBadge,
            "has_group_badge" => HasGroupBadge,
            "account_age_days" => AccountAgeDays,
            "days_since_last_visit" => DaysSinceLastVisit,
            "badge_count" => BadgeCount,
            "follower_count" => FollowerCount,
            "mapping_subscribers" => MappingSubscribers,
            "kudosu" => Kudosu,
            "ranked_beatmaps" => RankedBeatmaps,
            "loved_beatmaps" => LovedBeatmaps,
            "mapping_playcount" => MappingPlaycount,
            "replays_watched_by_others" => ReplaysWatchedByOthers,
            "favourite_count" => FavouriteCount,
            "country_code" => CountryCode,
            "username" => Username,
            "group_name" => GroupName,
            "playstyle" => Playstyle,
            "global_rank" => GlobalRank,
            "country_rank" => CountryRank,
            "performance_points" | "pp" => PerformancePoints,
            "play_count" | "playcount" => PlayCount,
            "play_time_hours" => PlayTimeHours,
            "total_score" => TotalScore,
            "ranked_score" => RankedScore,
            "hit_accuracy" | "accuracy" => HitAccuracy,
            "max_combo" => MaxCombo,
            "level_int" | "level" => LevelInt,
            "ss_count" => SsCount,
            "s_count" => SCount,
            "a_count" => ACount,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
    Contains,
    Regex,
    In,
    NotIn,
}

impl ConditionOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Neq => "neq",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Between => "between",
            Self::Contains => "contains",
            Self::Regex => "regex",
            Self::In => "in",
            Self::NotIn => "not_in",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        Some(match s {
            "eq" => Self::Eq,
            "neq" => Self::Neq,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            "between" => Self::Between,
            "contains" => Self::Contains,
            "regex" => Self::Regex,
            "in" => Self::In,
            "not_in" => Self::NotIn,
            _ => return None,
        })
    }

    /// Operators that produce a meaningful predicate on each target kind.
    /// Save-time validation rejects mismatches.
    pub fn valid_for(self, kind: TargetKind) -> bool {
        use ConditionOperator::*;
        match kind {
            // bool: `eq` (true/false). `neq` collapses to `eq false/true`
            // and would surprise admins, so we don't expose it.
            TargetKind::Bool => matches!(self, Eq),
            // int: full numeric arsenal.
            TargetKind::Int => matches!(self, Eq | Neq | Gt | Gte | Lt | Lte | Between),
            // string: exact / inclusion / regex / list membership.
            TargetKind::String => matches!(self, Eq | Neq | Contains | Regex | In | NotIn),
        }
    }
}

/// A single condition row inside an AND-group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub target: ConditionTarget,
    pub operator: ConditionOperator,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_end: Option<Value>,
}
