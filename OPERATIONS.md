# osu!-Player-Role — Operations

Practical notes for running this plugin in production. Sister doc to the main [README](README.md).

## Deployment shape

A single `docker compose up -d` is enough for a $4-6/month VPS:

- **osu-player-role**: the Rust binary, ~30–60 MB resident at idle, ~80–120 MB under bulk-sync load.
- **postgres:16-alpine**: ~80–160 MB with the tuned settings in `compose.yml`.

Both containers are constrained via `deploy.resources.limits` (512 MB app, 256 MB DB). The app's release profile is LTO + stripped + `panic = "abort"` — the binary is ~10–14 MB.

Healthcheck: `GET /osu-player-role/health` returns 200 when the DB is reachable; flips to `"degraded"` (still 200) when the osu! API itself is unreachable.

## Behind a reverse proxy / Cloudflare Tunnel

The plugin sits at `https://plugin-rolelogic.faizo.net/osu-player-role/*`. The Cloudflare Tunnel ingress rule:

```yaml
- hostname: plugin-rolelogic.faizo.net
  path: '^/osu-player-role'
  service: http://localhost:8095
- hostname: plugin-rolelogic.faizo.net
  path: '^/auth'
  service: http://localhost:8090   # Auth Gateway
- hostname: plugin-rolelogic.faizo.net
  service: http_status:404
```

**Important**: the reverse proxy MUST overwrite `Forwarded` / `X-Forwarded-For` / `X-Real-IP` with the real client IP. The plugin trusts those headers for its per-IP rate limit; otherwise an attacker can spoof per-IP buckets. Cloudflare Tunnel does this by default.

## Required env vars at boot

Without these the binary panics immediately on startup:

- `DATABASE_URL`
- `SESSION_SECRET` (must match the Auth Gateway's)
- `BASE_URL` (HTTPS, no trailing slash, includes `/osu-player-role`)
- `INTERNAL_API_KEY` (must match the Auth Gateway's)

Without `OSU_CLIENT_ID` / `OSU_CLIENT_SECRET` the binary still boots; the verify page just shows "osu! OAuth is not configured" and members can't link. This lets you stage a deploy before the OAuth app exists.

## osu! API rate limits

The osu! API soft-limits at ~60 req/min per app, with bursts permitted. The refresh worker is configured with `REFRESH_CONCURRENCY=2` by default and the `OsuClient` rate-limiter caps at 50 req/min as a hard ceiling. With 1000 linked users and a 6h refresh interval that's ~5 reads/min — well within budget.

If you raise concurrency, drop the user-stat-refresh interval, or expect a huge link burst (announcement on a popular server), watch for HTTP 429 in the logs and tune `REFRESH_CONCURRENCY` and `osu::OsuClient`'s quota down.

## Database operations

### Apply migrations only (no server)

Run the binary with the `migrate` argument:

```bash
docker compose run --rm app osu-player-role migrate
```

This is the safe step in a blue-green deploy: apply migrations once, then roll new replicas.

### Inspect the DLQ

Permanently-failed jobs land in `jobs` with `status = 'dead'`. The reconcile worker GCs dead jobs older than 30 days.

```sql
SELECT id, kind, payload, last_error, attempts, completed_at
FROM jobs
WHERE status = 'dead'
ORDER BY completed_at DESC
LIMIT 20;
```

To replay a dead job:

```sql
UPDATE jobs SET status = 'pending', attempts = 0, next_run_at = now(), last_error = NULL
WHERE id = $1;
```

### Force a full re-sync of one role link

```sql
INSERT INTO jobs (kind, payload) VALUES ('config_sync', '{"guild_id":"...", "role_id":"..."}');
NOTIFY jobs_pending;
```

### Force a re-fetch of one player's osu! profile

```sql
UPDATE osu_users SET next_refresh_at = now() WHERE discord_id = $1;
```

The refresh worker will pick them up within its 60s tick. After upserting fresh stats it auto-enqueues a `player_sync`.

## Scaling notes

- **Vertical first**: A single small VPS with the default `WORKER_CONCURRENCY=4` handles ~100 sync jobs/sec, which translates to roughly 100k linked players turning over their cached stats every 6h.
- **Horizontal**: Multiple replicas of the binary are safe — jobs claim via `FOR UPDATE SKIP LOCKED`, the LISTEN/NOTIFY wakes every replica's workers within milliseconds, and the per-role-link sync is set-replace-PUT so two replicas racing on the same role just both compute the same answer and only one wins the PUT.
- **DB pool**: each replica opens up to `DB_MAX_CONNECTIONS` (default 16). Budget `(replicas * DB_MAX_CONNECTIONS) ≤ pgBouncer pool` if you front Postgres with pgBouncer.

## What "role re-evaluation" actually means

Two paths fan into the same RoleLogic API:

1. **player_sync** (after link, unlink, or stats refresh) — looks at all the role links across the user's guilds, evaluates each, and adds/removes only the user in question via `POST/DELETE /api/role-link/.../users/{id}`.
2. **config_sync** (after admin saves a rule, debounced 5s; also fired by reconcile every 30 minutes) — builds a SQL WHERE clause from the rule tree, runs one query across all linked guild members, and atomically `PUT`s the resulting set.

Both paths skip the RoleLogic API call when the computed set already equals what we last persisted.

## Recovering from a missed DELETE /config

If RoleLogic deletes a role link while this plugin is offline, the dashboard's later token-authed calls to RoleLogic come back as `HTTP 403 "Invalid or revoked token"`. The sync engine recognizes that body, deletes the orphan local `role_links` row (cascading to `role_assignments`), and continues. No manual cleanup required.

## Backups

`pgdata` holds everything: role links, rule trees, linked accounts, cached stats, OAuth state. Snapshot with `pg_dump` from the host:

```bash
docker compose exec -T db pg_dump -U opr osu_player_role | gzip > backup-$(date +%F).sql.gz
```

Restore:

```bash
gunzip < backup-2026-01-01.sql.gz | docker compose exec -T db psql -U opr osu_player_role
```

Backups can be lossy of `jobs` rows — workers will re-pick whatever's still due. Linked accounts / rule trees are the precious bits.

## Observability

Default `RUST_LOG=osu_player_role=info,tower_http=warn` keeps the application logs readable. To debug a specific request, add `tower_http=info` and the per-request `[GET /osu-player-role/...]` lines reappear with response codes.

Every request carries an `x-request-id` header (UUID) that's both inbound (preserved) and outbound. Correlate logs by that ID.

`SetSensitiveRequestHeadersLayer` masks `Authorization`, `Cookie`, and `X-Internal-Key` in tracing output so credentials don't leak into log aggregators.
