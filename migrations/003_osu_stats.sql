-- osu_stats: per-(user, mode) cached stats. Four rows per linked user,
-- one per game mode (osu / taiko / fruits / mania). Populated by the same
-- refresh-worker pass that updates `osu_users` (osu! API v2 returns all
-- four mode-stats on a single profile fetch via /users/{id}/{mode}, but
-- the basic /users/{id} response includes the user's *default* mode only,
-- so we fan out across modes after each link / refresh).
--
-- Every per-mode condition target reads from this table joined on
-- `default_mode` (the mode chosen at the role-link level). This means a
-- "Top 1k Mania" rule fetches no JSONB at sync time — straight column reads.
--
-- Stats are nullable where the API may omit them (e.g. a brand-new account
-- might lack a rank); the Rust evaluator + SQL builder fail-closed on NULLs.
--
-- Convention 6: every filterable target gets its own column for cheap
-- per-condition partial indexes.

CREATE TABLE IF NOT EXISTS osu_stats (
    osu_user_id            BIGINT NOT NULL,
    mode                   TEXT   NOT NULL,

    global_rank            INTEGER,
    country_rank           INTEGER,
    -- PP is a float in the API; we round to the nearest integer to keep
    -- the operator catalog uniform (all per-mode operators stay numeric +
    -- integer). 1pp differences below the rounding floor don't matter
    -- for role gates.
    performance_points     INTEGER NOT NULL DEFAULT 0,
    play_count             INTEGER NOT NULL DEFAULT 0,
    -- Total time played in *hours*, rounded down. The API returns seconds.
    play_time_hours        INTEGER NOT NULL DEFAULT 0,
    total_score            BIGINT  NOT NULL DEFAULT 0,
    ranked_score           BIGINT  NOT NULL DEFAULT 0,
    -- Accuracy as a whole-number percent, rounded down. 98.7% becomes 98.
    -- (The fractional digits matter at the very top of the ladder but the
    --  "≥98%" admin UX is wildly more newbie-friendly than "≥9870 bp".)
    hit_accuracy           INTEGER NOT NULL DEFAULT 0,
    max_combo              INTEGER NOT NULL DEFAULT 0,
    level_int              INTEGER NOT NULL DEFAULT 0,
    -- Grade counts.
    count_ss_silver        INTEGER NOT NULL DEFAULT 0,
    count_ss               INTEGER NOT NULL DEFAULT 0,
    count_s_silver         INTEGER NOT NULL DEFAULT 0,
    count_s               INTEGER NOT NULL DEFAULT 0,
    count_a                INTEGER NOT NULL DEFAULT 0,

    refreshed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (osu_user_id, mode),
    -- Whitelist modes to keep the bulk-SQL query template type-safe.
    CONSTRAINT osu_stats_mode_check CHECK (mode IN ('osu','taiko','fruits','mania')),
    FOREIGN KEY (osu_user_id) REFERENCES osu_users (osu_user_id) ON DELETE CASCADE
);

-- Hot path: bulk sync joins stats by (osu_user_id, mode). Composite PK
-- already covers it, but a partial on "ranked" rows accelerates "Top N"
-- queries by skipping unranked users.
CREATE INDEX IF NOT EXISTS idx_osu_stats_ranked_by_mode
    ON osu_stats (mode, global_rank)
    WHERE global_rank IS NOT NULL;
