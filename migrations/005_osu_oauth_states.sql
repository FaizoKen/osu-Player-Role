-- Server-side PKCE state for osu! OAuth flows. Convention 37 explicitly
-- permits oauth_states for a plugin's *secondary* OAuth (this one is osu!,
-- which has nothing to do with the gateway's Discord OAuth).
--
-- Rows live for ~10 minutes, then expire. The cleanup task GCs expired
-- rows periodically; the partial index keeps the working set tiny.
--
-- Only one flow ('viewer') exists for osu! — there is no broadcaster /
-- channel concept, so unlike Kick we don't need to discriminate flows.

CREATE TABLE IF NOT EXISTS osu_oauth_states (
    state           TEXT PRIMARY KEY,
    code_verifier   TEXT NOT NULL,
    discord_id      TEXT NOT NULL,
    return_to       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_osu_oauth_states_expires
    ON osu_oauth_states (expires_at);
