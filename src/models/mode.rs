//! osu! game modes. The rule tree carries a `default_mode`; every per-mode
//! condition target evaluates against the user's stats in that mode.
//!
//! Stored in `osu_stats.mode` as TEXT — the CHECK constraint mirrors this
//! enum. Adding a new mode means: enum variant + CHECK constraint + an
//! entry in the API client's mode list.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Standard osu! (circles + sliders + spinners).
    #[default]
    Osu,
    /// osu!taiko (drumming).
    Taiko,
    /// osu!catch / "fruits" (catching falling fruit).
    Fruits,
    /// osu!mania (vertical-scroll key game).
    Mania,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Osu => "osu",
            Mode::Taiko => "taiko",
            Mode::Fruits => "fruits",
            Mode::Mania => "mania",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        match s {
            "osu" | "standard" => Some(Mode::Osu),
            "taiko" => Some(Mode::Taiko),
            // Tolerate the legacy "ctb" alias osu! itself used to ship.
            "fruits" | "catch" | "ctb" => Some(Mode::Fruits),
            "mania" => Some(Mode::Mania),
            _ => None,
        }
    }

    /// All four modes in their canonical order. Used by the refresh worker
    /// to fan out per-mode stat fetches.
    pub const ALL: [Mode; 4] = [Mode::Osu, Mode::Taiko, Mode::Fruits, Mode::Mania];

    /// Human-readable label for the iframe UI.
    pub fn label(self) -> &'static str {
        match self {
            Mode::Osu => "osu! (standard)",
            Mode::Taiko => "osu!taiko",
            Mode::Fruits => "osu!catch",
            Mode::Mania => "osu!mania",
        }
    }
}
