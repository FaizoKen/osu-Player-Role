-- Role links: one per guild+role pair registered via POST /register.
--
-- The rule tree is stored as JSONB and validated by `parse_rule_tree`. Until
-- an admin actually configures the role, rule_tree =
-- '{"grant_on_any_player":false,"default_mode":"osu","groups":[]}' AND
-- grant_on_any_player = FALSE means "grant to nobody" (Convention 42).
--
-- `default_mode` is the osu! game mode (osu / taiko / fruits / mania) that
-- per-mode conditions like GlobalRank / PerformancePoints / PlayCount
-- evaluate against. Profile-level targets (IsSupporter, CountryCode, etc.)
-- ignore it. Storing the mode on the role link, not per-condition, keeps the
-- UI dead simple — most osu! roles are mode-specific anyway ("Top 1k Mania",
-- "5k+ plays in Taiko").
--
-- `rule_tree_version` powers optimistic locking on save: two tabs editing
-- the same role link cannot silently clobber each other. The save handler
-- bumps it inside the transaction; mismatched versions raise StaleVersion.

CREATE TABLE IF NOT EXISTS role_links (
    id                     BIGSERIAL PRIMARY KEY,
    guild_id               TEXT NOT NULL,
    role_id                TEXT NOT NULL,
    api_token              TEXT NOT NULL,
    rule_tree              JSONB NOT NULL
        DEFAULT '{"grant_on_any_player":false,"default_mode":"osu","groups":[]}',
    rule_tree_version      INTEGER NOT NULL DEFAULT 1,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (guild_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_links_guild_role
    ON role_links (guild_id, role_id);

-- Role assignments: local mirror of who currently has which Discord role.
-- Source of truth is RoleLogic; this table is the diff target during sync.
-- CASCADE keeps it consistent with role_links on DELETE /config.
CREATE TABLE IF NOT EXISTS role_assignments (
    guild_id        TEXT NOT NULL,
    role_id         TEXT NOT NULL,
    discord_id      TEXT NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, role_id, discord_id),
    FOREIGN KEY (guild_id, role_id) REFERENCES role_links (guild_id, role_id) ON DELETE CASCADE
);

-- Per-guild settings (Convention 33). Server-wide knobs live here, NOT on
-- role_links rows, so two role links in the same guild can't drift apart on
-- "settings for this server".
--
-- `view_permission` controls who can view the public users list:
--   'managers' (default), 'members', or 'disabled' to hide entirely.
CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id         TEXT PRIMARY KEY,
    view_permission  TEXT NOT NULL DEFAULT 'managers',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
