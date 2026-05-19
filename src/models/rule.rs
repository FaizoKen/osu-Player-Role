//! The rule tree: OR of AND-groups (DNF), plus the role link's chosen
//! game mode for per-mode condition targets.
//!
//! Stored verbatim as the JSONB `rule_tree` column on `role_links`. Two-
//! level structure keeps validation, SQL translation, and the iframe
//! rule-builder UI simple while still expressing every boolean rule (any
//! boolean expression has a DNF form).
//!
//! Convention 42 invariant: an unconfigured role link grants the role to
//! nobody. `grant_on_any_player = false` AND `groups.is_empty()` means
//! "match nobody" — both [`crate::services::condition_eval::evaluate`] and
//! the SQL builder enforce this BEFORE inspecting groups.

use serde::{Deserialize, Serialize};

use crate::models::condition::Condition;
use crate::models::mode::Mode;

/// Maximum top-level groups. 8 fits a tiered hierarchy ("Top 100" OR
/// "Top 1k AND ≥10k plays" OR …) without nesting.
pub const MAX_GROUPS: usize = 8;
/// Maximum conditions per group. 12 is generous — real-world rules rarely
/// exceed 3-4.
pub const MAX_CONDITIONS_PER_GROUP: usize = 12;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleTree {
    #[serde(default)]
    pub grant_on_any_player: bool,
    /// Game mode every per-mode condition target evaluates against.
    /// Mode-independent targets (supporter, country, badges, …) ignore it.
    /// Defaults to `osu` (via `Mode`'s `#[default]` variant) so a brand-new
    /// role link is opinionated but sane.
    #[serde(default)]
    pub default_mode: Mode,
    #[serde(default)]
    pub groups: Vec<ConditionGroup>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConditionGroup {
    #[serde(default)]
    pub conditions: Vec<Condition>,
}
