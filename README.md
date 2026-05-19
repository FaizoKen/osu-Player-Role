# osu!-Player-Role

A RoleLogic plugin that grants Discord roles based on a member's **osu! profile and stats** — global rank, PP, play count, accuracy, badges, supporter tag, user-group membership (BN / GMT / NAT / ...), and 25+ other facts.

Roles re-evaluate automatically as players' stats drift. Conditions compose as a **DNF rule tree** (OR of AND-groups), so admins can express rules like *"top 1k Global OR (supporter AND ≥10k plays) OR is in {BN, GMT, NAT}"* without nesting.

Per-rule **game mode picker** (osu! / taiko / catch / mania) — every "PP/rank/play-count" condition checks the player in that mode. Profile facts (supporter, country, badges, …) are mode-independent.

Written in Rust (axum, sqlx, tokio). Stateless HTTP tier + N durable job-polling workers + a polling refresh worker that keeps cached stats fresh against the [osu! API v2](https://osu.ppy.sh/docs).

---

## What makes it newbie-friendly

- **Starter templates** baked into the rule builder — one click loads "Top 1k Global", "Supporter OR 10k+ plays", "Staff / BN / GMT", "Mapper (≥1 ranked map)", country presets, "Any linked player".
- **Inline tooltips** on every condition target explain what the field means in plain English, with units ("days", "whole percent", "rounded pp").
- **Game-mode picker is step 1** — the choice that confuses new admins ("which osu! mode?") is presented up front, not buried.
- **Live preview button** shows the matching-player count *before* you save.
- **Optimistic locking** — two browser tabs editing the same role link can't silently clobber each other.
- **Friendly errors** — every save-time validation error names the group + condition number and tells you exactly what to fix.

---

## Quick start (local)

You need Docker. Postgres + the plugin start together in `compose.yml`.

```bash
cp .env.example .env
# Fill in: POSTGRES_PASSWORD, SESSION_SECRET, INTERNAL_API_KEY, BASE_URL.
# Suggested generators:
#   openssl rand -base64 24    # POSTGRES_PASSWORD
#   openssl rand -base64 48    # SESSION_SECRET
#   openssl rand -hex 32       # INTERNAL_API_KEY
docker compose up --build
```

Then visit `http://localhost:8095/osu-player-role/health` — should return `{"status":"healthy"}`.

Role config opens inside the RoleLogic dashboard once you register this plugin URL there: `https://your-domain.com/osu-player-role`.

Member verification lives at `/osu-player-role/verify`. Linked players list at `/osu-player-role/users/{guild_id}`.

---

## Set up the osu! OAuth application

The verify flow uses osu! OAuth (PKCE, scope `identify public`).

1. Visit <https://osu.ppy.sh/home/account/edit>, scroll to **OAuth**, click **New OAuth Application**.
2. Application name: anything (e.g. *RoleLogic-osu*).
3. Application Callback URL — **must exactly equal** `{BASE_URL}/oauth/osu/callback`. Example:
   `https://plugin-rolelogic.faizo.net/osu-player-role/oauth/osu/callback`.
4. Save the Client ID and Client Secret into `OSU_CLIENT_ID` / `OSU_CLIENT_SECRET` in `.env`.

The verify page surfaces a clear error if either is missing — no silent failures.

---

## Configuration

All config lives in env vars. See [.env.example](.env.example) for the full list. Required:

| Var | What |
| --- | --- |
| `DATABASE_URL`      | `postgres://…` |
| `SESSION_SECRET`    | HMAC key for `rl_session` cookie + iframe-session token. Must match the Auth Gateway's value. |
| `BASE_URL`          | Public plugin URL (HTTPS in prod, no trailing slash, includes the `/osu-player-role` prefix). |
| `INTERNAL_API_KEY`  | Shared secret for plugin → Auth Gateway `/auth/internal/*` calls. |
| `POSTGRES_PASSWORD` | Used by both the DB container and the templated `DATABASE_URL`. |

Optional but commonly set: `AUTH_GATEWAY_URL`, `ROLELOGIC_API_URL`, `RL_DASHBOARD_ORIGIN`, `OSU_CLIENT_ID`, `OSU_CLIENT_SECRET`, `WORKER_CONCURRENCY`, `REFRESH_CONCURRENCY`.

---

## Repo layout

```
src/
  main.rs              # Router, middleware stack, worker spawn, signal handler
  config.rs            # AppConfig from env (incl. OsuConfig)
  db.rs                # Pool + migrations
  error.rs             # AppError + sqlx-error → HTTP-status classifier
  schema.rs            # RoleLogic iframe /config builder
  models/
    condition.rs       # ConditionTarget / Operator / TargetKind  — 33 targets
    rule.rs            # RuleTree (DNF: OR of AND-groups + default_mode)
    facts.rs           # POD facts for evaluation
    mode.rs            # osu! game mode enum (osu/taiko/fruits/mania)
  routes/
    plugin.rs          # POST /register, GET/POST/DELETE /config
    admin.rs           # iframe role-config + data/save/preview + view-permission
    oauth.rs           # osu! OAuth callback — upserts user + per-mode stats
    verify.rs          # member verification flow (linking)
    users.rs           # public linked-players list
    health.rs          # /health, /ready, /favicon.ico
  services/
    rolelogic.rs       # RoleLogic API client (PUT/POST/DELETE users)
    auth_gateway.rs    # Auth Gateway /auth/internal/* (sync workers)
    auth.rs            # cookie + manager / guild-admin helpers
    osu.rs             # osu! API v2 client (OAuth/PKCE + client-credentials)
    condition_eval.rs  # sync Rust rule evaluator
    rule_sql.rs        # SQL WHERE pushdown for bulk per-role-link sync
    rule_validator.rs  # save-time rule-tree validation
    jobs.rs            # durable queue (enqueue/claim/retry/DLQ/reap)
    sync.rs            # per-player + per-role-link sync engine
    session.rs         # rl_session cookie verify
    rl_token.rs        # rl_token JWT + iframe-session token
    csrf.rs            # Origin allowlist check
    security_headers.rs# CSP/HSTS/nosniff/Referrer-Policy middleware
  tasks/
    job_listener.rs    # LISTEN jobs_pending → wake workers
    job_worker.rs      # FOR UPDATE SKIP LOCKED dispatch loop
    refresh.rs         # 60s tick: refetch users with stale next_refresh_at
    reconcile.rs       # 30m tick: re-enqueue config_sync per role + GC
    shutdown.rs        # tokio broadcast-based shutdown
migrations/            # 001–005, applied in numeric order on startup
templates/             # iframe rule builder, verify, users list, oauth done
```

---

## Condition targets

**33 targets** across two groups. **Per-mode** targets evaluate against the chosen `default_mode`. **Profile** targets are mode-independent.

### Per-mode (osu! / taiko / catch / mania)
`global_rank`, `country_rank`, `performance_points` (pp), `play_count`, `play_time_hours`, `total_score`, `ranked_score`, `hit_accuracy` (whole %), `max_combo`, `level_int`, `ss_count`, `s_count`, `a_count`.

### Profile (mode-independent)
`is_supporter`, `is_active`, `is_restricted`, `has_badge`, `has_group_badge`, `account_age_days`, `days_since_last_visit`, `badge_count`, `follower_count`, `mapping_subscribers`, `kudosu`, `ranked_beatmaps`, `loved_beatmaps`, `mapping_playcount`, `replays_watched_by_others`, `favourite_count`, `country_code`, `username`, `group_name`, `playstyle`.

### Operators
`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `between`, `contains`, `regex`, `in`, `not_in`. Each operator is only valid for the right kind (e.g. `gt` isn't offered for `is_supporter`).

---

## Development

```bash
cargo build               # debug build
cargo check               # type-check only
cargo test                # all unit tests
cargo clippy --no-deps --all-targets -- -D warnings
cargo fmt --all --check
docker compose up --build # full local stack
```

The unit tests cover the condition evaluator (Convention 42 unconfigured-rule guard, top-1k rule, between-PP, OR-of-AND realistic tier rule, group/playstyle list match), the SQL pushdown builder (single-group AND, multi-group OR, array overlap for groups, LIKE escaping), the rule validator (rejects unknown mode, accepts aliases, between requires value_end, CSV → array normalization, regex compile-fails-at-save), the JWT verifier (round-trip, wrong signature, expired, wrong audience, pivoted iframe session), and the session cookie verifier (round-trip, expired, tampered).

---

## Production deployment

See [OPERATIONS.md](OPERATIONS.md). The summary: one Postgres + one Rust binary fits comfortably in a 512MB / 1 vCPU VPS for tens of thousands of linked players.
