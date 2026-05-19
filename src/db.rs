use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

use crate::config::DbPoolConfig;

/// How long a single pooled connection may live before recycling.
const POOL_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

pub async fn create_pool(database_url: &str, cfg: &DbPoolConfig) -> PgPool {
    // pgBouncer transaction-mode safety: a prepared statement registered on
    // one backend isn't visible on the next, so caching breaks. Disabling
    // the cache is the canonical fix.
    let connect_options = PgConnectOptions::from_str(database_url)
        .expect("invalid DATABASE_URL")
        .statement_cache_capacity(0);

    PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(cfg.idle_timeout_secs))
        .max_lifetime(POOL_MAX_LIFETIME)
        .test_before_acquire(false)
        .connect_with(connect_options)
        .await
        .expect("Failed to connect to PostgreSQL")
}

/// Migrations are applied in order on startup. They are idempotent
/// (`CREATE … IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, etc.) so a replica
/// that finds them already applied is a no-op. New migrations MUST follow
/// the expand→contract pattern so blue/green deploys never run two app
/// versions against an incompatible schema.
///
/// When you add a migration file, add the matching entry here. The app does
/// NOT discover new files automatically.
pub async fn run_migrations(pool: &PgPool) {
    let migrations: &[(&str, &str)] = &[
        ("001", include_str!("../migrations/001_initial_schema.sql")),
        ("002", include_str!("../migrations/002_osu_users.sql")),
        ("003", include_str!("../migrations/003_osu_stats.sql")),
        ("004", include_str!("../migrations/004_jobs.sql")),
        (
            "005",
            include_str!("../migrations/005_osu_oauth_states.sql"),
        ),
    ];
    for (id, sql) in migrations {
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration {id} failed: {e}"));
    }
    tracing::info!("Applied {} migrations", migrations.len());
}
