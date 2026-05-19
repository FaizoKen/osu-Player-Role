//! Plain-data view of an osu! player's facts needed for condition
//! evaluation. Constructed by sync workers from `osu_users` and `osu_stats`
//! joined on `(osu_user_id, mode = default_mode)`.
//!
//! Kept POD (no methods, no I/O) so [`crate::services::condition_eval::evaluate`]
//! stays sync and fast.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub struct Facts {
    // ---- profile (mode-independent) ----
    pub is_supporter: bool,
    pub is_active: bool,
    pub is_restricted: bool,
    pub has_badge: bool,
    pub has_group_badge: bool,
    pub osu_joined_at: Option<DateTime<Utc>>,
    pub last_visit_at: Option<DateTime<Utc>>,
    pub badge_count: i64,
    pub follower_count: i64,
    pub mapping_subscribers: i64,
    pub kudosu: i64,
    pub ranked_beatmaps: i64,
    pub loved_beatmaps: i64,
    pub mapping_playcount: i64,
    pub replays_watched_by_others: i64,
    pub favourite_count: i64,
    pub country_code: Option<String>,
    pub username: String,
    pub groups: Vec<String>,
    pub playstyles: Vec<String>,

    // ---- per-mode (for the role link's default_mode) ----
    /// `None` if the player has no ranked plays in this mode.
    pub global_rank: Option<i64>,
    pub country_rank: Option<i64>,
    pub performance_points: i64,
    pub play_count: i64,
    pub play_time_hours: i64,
    pub total_score: i64,
    pub ranked_score: i64,
    pub hit_accuracy: i64,
    pub max_combo: i64,
    pub level_int: i64,
    pub ss_count: i64,
    pub s_count: i64,
    pub a_count: i64,
}
