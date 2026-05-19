-- osu_users: linked Discord ↔ osu! identity. One row per verified member.
--
-- `osu_user_id` is UNIQUE because an osu! account can be linked to at most
-- one Discord account at a time. Re-linking from a different Discord ID
-- raises a unique-violation; the handler explicitly DELETEs the prior row
-- and seeds a new one (no "sub-sharing" by linking one supporter account to
-- many Discords).
--
-- Profile columns are denormalized off the osu! user object so the
-- mode-independent condition targets (IsSupporter, CountryCode, Username,
-- BadgeCount, Kudosu, …) evaluate without parsing JSONB at sync time. The
-- raw payload is preserved in `profile` for forensics / new targets without
-- a migration round-trip.
--
-- `discord_name` is captured from the rl_session cookie at link time so the
-- public users page can show "DiscordName (osu_username)" without an Auth
-- Gateway per-user lookup.

CREATE TABLE IF NOT EXISTS osu_users (
    discord_id              TEXT PRIMARY KEY,
    osu_user_id             BIGINT UNIQUE NOT NULL,
    osu_username            TEXT NOT NULL,
    discord_name            TEXT,

    -- Denormalized profile (refreshed on every link + every refresh-worker
    -- pass). Nullable where the API may omit the field.
    country_code            TEXT,
    country_name            TEXT,
    profile_colour          TEXT,
    avatar_url              TEXT,
    osu_joined_at           TIMESTAMPTZ NOT NULL,
    last_visit_at           TIMESTAMPTZ,
    is_supporter            BOOLEAN NOT NULL DEFAULT FALSE,
    support_level           INTEGER NOT NULL DEFAULT 0,
    is_restricted           BOOLEAN NOT NULL DEFAULT FALSE,
    is_active               BOOLEAN NOT NULL DEFAULT FALSE,
    badge_count             INTEGER NOT NULL DEFAULT 0,
    follower_count          INTEGER NOT NULL DEFAULT 0,
    mapping_followers       INTEGER NOT NULL DEFAULT 0,
    kudosu_total            INTEGER NOT NULL DEFAULT 0,
    ranked_beatmaps         INTEGER NOT NULL DEFAULT 0,
    loved_beatmaps          INTEGER NOT NULL DEFAULT 0,
    pending_beatmaps        INTEGER NOT NULL DEFAULT 0,
    graveyard_beatmaps      INTEGER NOT NULL DEFAULT 0,
    mapping_playcount       INTEGER NOT NULL DEFAULT 0,
    replays_watched_others  INTEGER NOT NULL DEFAULT 0,
    favourite_beatmapsets   INTEGER NOT NULL DEFAULT 0,
    -- Playstyles is an array of strings: "mouse" | "keyboard" | "tablet" | "touch"
    playstyles              TEXT[] NOT NULL DEFAULT '{}',
    -- Group identifiers (short names from /groups, e.g. "GMT", "BN", "NAT",
    -- "DEV", "ALM", "BSC", "LVD"). Empty array = no group memberships.
    groups                  TEXT[] NOT NULL DEFAULT '{}',

    -- Raw API payload preserved verbatim. New condition targets that need
    -- something exotic can read from here without a schema migration.
    profile                 JSONB NOT NULL DEFAULT '{}',

    linked_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    refreshed_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_refresh_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    refresh_failures        INTEGER NOT NULL DEFAULT 0
);

-- Refresh worker picks the user whose `next_refresh_at` is oldest first.
CREATE INDEX IF NOT EXISTS idx_osu_users_next_refresh
    ON osu_users (next_refresh_at);

-- Reverse lookup: an admin search-by-osu-id from the users page, or future
-- inbound notifications keyed by osu_user_id.
CREATE INDEX IF NOT EXISTS idx_osu_users_osu_id
    ON osu_users (osu_user_id);

-- Partial indexes for hot booleans (Convention 6 from the blueprint).
-- These accelerate "IsSupporter = true" / "HasBadge" filters in bulk sync.
CREATE INDEX IF NOT EXISTS idx_osu_users_supporters
    ON osu_users (discord_id) WHERE is_supporter;
CREATE INDEX IF NOT EXISTS idx_osu_users_has_badge
    ON osu_users (discord_id) WHERE badge_count > 0;
