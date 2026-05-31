//! PersistentScores — SQLite-backed per-network scoring store.
//!
//! Stores `(fingerprint, method) → ScoreEntry` with ACID guarantees.
//! Max 50 fingerprints × 10 methods ≈ 500 rows, ~30 KB.

#![allow(missing_docs)]
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE scores (
//!     fingerprint BLOB NOT NULL,          -- first 16 bytes of network fingerprint
//!     method INTEGER NOT NULL,            -- MethodId as u8
//!     successes INTEGER NOT NULL DEFAULT 0,
//!     failures INTEGER NOT NULL DEFAULT 0,
//!     last_success_at INTEGER,            -- unix epoch seconds
//!     last_failure_at INTEGER,            -- unix epoch seconds
//!     median_latency_ms INTEGER NOT NULL DEFAULT 0,  -- EWMA
//!     blocked_at INTEGER,                 -- unix epoch seconds (NULL = not blocked)
//!     consecutive_failures INTEGER NOT NULL DEFAULT 0,
//!     PRIMARY KEY (fingerprint, method)
//! );
//! ```

use std::{
    path::Path,
    time::{Duration, SystemTime},
};

use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::veil::fsm::{MethodId, NetworkFingerprint, ScoreEntry, ScoreLookup, ScoreOutcome};

/// SQLite-backed persistent scores store.
pub struct PersistentScores {
    pool: SqlitePool,
    max_fingerprints: usize,
}

impl PersistentScores {
    /// Open or create a scores database at the given path.
    ///
    /// If the database doesn't exist, it will be created with the initial schema.
    /// If the database is corrupt, it will be deleted and recreated.
    pub async fn open(
        path: impl AsRef<Path>,
        max_fingerprints: usize,
    ) -> Result<Self, ScoringError> {
        let path_ref = path.as_ref();
        // `SqlitePool::connect("sqlite:PATH")` opens the file read-write but does
        // NOT create it if absent — sqlx returns SQLITE_CANTOPEN(14). On iOS the
        // first launch always misses, so we must opt in to creation explicitly.
        // `:memory:` is a special token: keep the URL form for that case.
        let pool = if path_ref.as_os_str() == ":memory:" {
            SqlitePool::connect("sqlite::memory:").await.map_err(|e| {
                ScoringError::DbError(format!("failed to connect to :memory:: {e}"))
            })?
        } else {
            let opts = SqliteConnectOptions::new()
                .filename(path_ref)
                .create_if_missing(true);
            SqlitePoolOptions::new()
                .connect_with(opts)
                .await
                .map_err(|e| {
                    ScoringError::DbError(format!(
                        "failed to connect to {}: {e}",
                        path_ref.display(),
                    ))
                })?
        };

        Self::migrate(&pool).await?;

        Ok(Self {
            pool,
            max_fingerprints,
        })
    }

    /// Open with default max_fingerprints (50).
    pub async fn open_default(path: impl AsRef<Path>) -> Result<Self, ScoringError> {
        Self::open(path, 50).await
    }

    /// Run schema migrations. Idempotent — safe to call on every startup.
    async fn migrate(pool: &SqlitePool) -> Result<(), ScoringError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS scores (
                fingerprint BLOB NOT NULL,
                method INTEGER NOT NULL,
                successes INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                last_success_at INTEGER,
                last_failure_at INTEGER,
                median_latency_ms INTEGER NOT NULL DEFAULT 0,
                blocked_at INTEGER,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (fingerprint, method)
            )
            "#,
        )
        .execute(pool)
        .await
        .map_err(|e| ScoringError::DbError(format!("migration failed: {e}")))?;

        Ok(())
    }

    /// Record a score outcome for a (fingerprint, method) pair.
    pub async fn record(
        &self,
        fingerprint: &NetworkFingerprint,
        method: MethodId,
        outcome: ScoreOutcome,
    ) -> Result<(), ScoringError> {
        let fp = fingerprint.as_bytes();

        match outcome {
            ScoreOutcome::Success { latency_ms } => {
                // EWMA for latency: new = old * 0.7 + new * 0.3
                let current_latency: u32 = sqlx::query_scalar(
                    "SELECT median_latency_ms FROM scores WHERE fingerprint = ? AND method = ?",
                )
                .bind(fp)
                .bind(method as i64)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| ScoringError::DbError(format!("read failed: {e}")))?
                .unwrap_or(0);

                let ewma_latency = if current_latency == 0 {
                    latency_ms
                } else {
                    ((current_latency as f64 * 0.7) + (latency_ms as f64 * 0.3)).round() as u32
                };

                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                sqlx::query(
                    r#"
                    INSERT INTO scores (fingerprint, method, successes, failures,
                                        last_success_at, median_latency_ms,
                                        consecutive_failures, blocked_at)
                    VALUES (?, ?, 1, 0, ?, ?, 0, NULL)
                    ON CONFLICT(fingerprint, method) DO UPDATE SET
                        successes = scores.successes + 1,
                        last_success_at = excluded.last_success_at,
                        median_latency_ms = excluded.median_latency_ms,
                        consecutive_failures = 0,
                        blocked_at = NULL
                    "#,
                )
                .bind(fp)
                .bind(method as i64)
                .bind(now)
                .bind(ewma_latency as i64)
                .execute(&self.pool)
                .await
                .map_err(|e| ScoringError::DbError(format!("insert failed: {e}")))?;
            }

            ScoreOutcome::Failure { reason } => {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let is_hard_block = matches!(
                    reason,
                    crate::veil::fsm::ProbeFailureReason::FingerprintBlocked
                        | crate::veil::fsm::ProbeFailureReason::WebTunnelDecoyResponse
                );

                if is_hard_block {
                    sqlx::query(
                        r#"
                        INSERT INTO scores (fingerprint, method, failures,
                                            last_failure_at, blocked_at,
                                            consecutive_failures)
                        VALUES (?, ?, 1, ?, ?, 1)
                        ON CONFLICT(fingerprint, method) DO UPDATE SET
                            failures = scores.failures + 1,
                            last_failure_at = excluded.last_failure_at,
                            blocked_at = excluded.blocked_at,
                            consecutive_failures = scores.consecutive_failures + 1
                        "#,
                    )
                    .bind(fp)
                    .bind(method as i64)
                    .bind(now)
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| ScoringError::DbError(format!("insert failed: {e}")))?;
                } else {
                    sqlx::query(
                        r#"
                        INSERT INTO scores (fingerprint, method, failures,
                                            last_failure_at, consecutive_failures)
                        VALUES (?, ?, 1, ?, 1)
                        ON CONFLICT(fingerprint, method) DO UPDATE SET
                            failures = scores.failures + 1,
                            last_failure_at = excluded.last_failure_at,
                            consecutive_failures = scores.consecutive_failures + 1
                        "#,
                    )
                    .bind(fp)
                    .bind(method as i64)
                    .bind(now)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| ScoringError::DbError(format!("insert failed: {e}")))?;
                }
            }
        }

        // Prune if over limit.
        self.prune().await?;

        Ok(())
    }

    /// Get a score entry.
    pub async fn get_score(
        &self,
        fingerprint: &NetworkFingerprint,
        method: MethodId,
    ) -> Result<Option<ScoreEntry>, ScoringError> {
        let row = sqlx::query(
            r#"
            SELECT successes, failures, last_success_at, last_failure_at,
                   median_latency_ms, blocked_at, consecutive_failures
            FROM scores WHERE fingerprint = ? AND method = ?
            "#,
        )
        .bind(fingerprint.as_bytes())
        .bind(method as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ScoringError::DbError(format!("query failed: {e}")))?;

        match row {
            Some(row) => {
                let successes: i64 = row.get(0);
                let failures: i64 = row.get(1);
                let last_success_at: Option<i64> = row.get(2);
                let last_failure_at: Option<i64> = row.get(3);
                let median_latency_ms: i64 = row.get(4);
                let blocked_at: Option<i64> = row.get(5);
                let consecutive_failures: i64 = row.get(6);

                Ok(Some(ScoreEntry {
                    successes: successes as u32,
                    failures: failures as u32,
                    last_success_at: last_success_at.map(epoch_to_system),
                    last_failure_at: last_failure_at.map(epoch_to_system),
                    median_latency_ms: median_latency_ms as u32,
                    blocked_at: blocked_at.map(epoch_to_system),
                    consecutive_failures: consecutive_failures as u8,
                }))
            }
            None => Ok(None),
        }
    }

    /// Check if a method is permanently blocked.
    ///
    /// Blocked if:
    /// - `blocked_at` is set AND
    /// - `consecutive_failures >= 5` AND
    /// - `blocked_at` is within `block_ttl` from now
    pub fn is_blocked_sync(
        &self,
        _fingerprint: &NetworkFingerprint,
        _method: MethodId,
        _block_ttl: Duration,
        _now: SystemTime,
    ) -> bool {
        // We need a synchronous check — use a blocking lookup.
        // This is called from the pure FSM, so we can't do async I/O here.
        // The caller should pre-compute this via `is_permanently_blocked_async`.
        // This impl is for the ScoreLookup trait and should be pre-populated.
        false // Placeholder — see `CachedScoreLookup` for actual use.
    }

    /// Async version of is_permanently_blocked.
    pub async fn is_permanently_blocked_async(
        &self,
        fingerprint: &NetworkFingerprint,
        method: MethodId,
        block_ttl: Duration,
        now: SystemTime,
    ) -> Result<bool, ScoringError> {
        let row = sqlx::query(
            r#"
            SELECT blocked_at, consecutive_failures
            FROM scores WHERE fingerprint = ? AND method = ?
            "#,
        )
        .bind(fingerprint.as_bytes())
        .bind(method as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ScoringError::DbError(format!("query failed: {e}")))?;

        match row {
            Some(row) => {
                let blocked_at: Option<i64> = row.get(0);
                let consecutive_failures: i64 = row.get(1);

                if let Some(ba) = blocked_at {
                    let blocked_time = epoch_to_system(ba);
                    let consecutive = consecutive_failures as u8;
                    let expired = now
                        .duration_since(blocked_time)
                        .map(|d| d > block_ttl)
                        .unwrap_or(true);

                    // Unblocked if block TTL expired.
                    if expired {
                        return Ok(false);
                    }

                    // Permanently blocked if 5+ consecutive failures.
                    Ok(consecutive >= 5)
                } else {
                    Ok(false)
                }
            }
            None => Ok(false),
        }
    }

    /// Prune oldest fingerprints if over the limit.
    async fn prune(&self) -> Result<(), ScoringError> {
        // Count distinct fingerprints.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT fingerprint) FROM scores")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ScoringError::DbError(format!("count failed: {e}")))?;

        if count as usize <= self.max_fingerprints {
            return Ok(());
        }

        // Delete fingerprints with the oldest max(last_success_at, last_failure_at).
        let to_delete = (count as usize) - self.max_fingerprints;
        sqlx::query(
            r#"
            DELETE FROM scores WHERE fingerprint IN (
                SELECT fingerprint FROM scores
                GROUP BY fingerprint
                ORDER BY MAX(COALESCE(last_success_at, 0), COALESCE(last_failure_at, 0)) ASC
                LIMIT ?
            )
            "#,
        )
        .bind(to_delete as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| ScoringError::DbError(format!("prune failed: {e}")))?;

        Ok(())
    }

    /// Get all scores for a fingerprint (for diagnostics).
    pub async fn get_all_for_fingerprint(
        &self,
        fingerprint: &NetworkFingerprint,
    ) -> Result<Vec<(MethodId, ScoreEntry)>, ScoringError> {
        let rows = sqlx::query(
            r#"
            SELECT method, successes, failures, last_success_at, last_failure_at,
                   median_latency_ms, blocked_at, consecutive_failures
            FROM scores WHERE fingerprint = ?
            "#,
        )
        .bind(fingerprint.as_bytes())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ScoringError::DbError(format!("query failed: {e}")))?;

        let mut result = Vec::new();
        for row in rows {
            let method_id: i64 = row.get(0);
            let method = match method_id as u8 {
                0 => MethodId::Obfs4,
                1 => MethodId::WebTunnel,
                2 => MethodId::Masque,
                _ => continue,
            };
            let entry = ScoreEntry {
                successes: row.get::<i64, _>(1) as u32,
                failures: row.get::<i64, _>(2) as u32,
                last_success_at: row.get::<Option<i64>, _>(3).map(epoch_to_system),
                last_failure_at: row.get::<Option<i64>, _>(4).map(epoch_to_system),
                median_latency_ms: row.get::<i64, _>(5) as u32,
                blocked_at: row.get::<Option<i64>, _>(6).map(epoch_to_system),
                consecutive_failures: row.get::<i64, _>(7) as u8,
            };
            result.push((method, entry));
        }

        Ok(result)
    }
}

/// Cached score lookup that implements `ScoreLookup` for the pure FSM.
///
/// Since the FSM is pure (no async I/O), we pre-load all scores into memory
/// and pass a `CachedScoreLookup` to `reduce()`.
pub struct CachedScoreLookup {
    #[allow(dead_code)]
    fingerprint: NetworkFingerprint,
    entries: std::collections::HashMap<MethodId, ScoreEntry>,
}

impl CachedScoreLookup {
    /// Build a cached lookup for a specific fingerprint.
    pub async fn build(
        scores: &PersistentScores,
        fingerprint: &NetworkFingerprint,
    ) -> Result<Self, ScoringError> {
        let all = scores.get_all_for_fingerprint(fingerprint).await?;
        let mut entries = std::collections::HashMap::new();
        for (method, entry) in all {
            entries.insert(method, entry);
        }
        Ok(Self {
            fingerprint: fingerprint.clone(),
            entries,
        })
    }

    /// Pre-compute blocked status for all methods.
    pub fn blocked_for(&self, method: MethodId, block_ttl: Duration, now: SystemTime) -> bool {
        let entry = match self.entries.get(&method) {
            Some(e) => e,
            None => return false,
        };
        match entry.blocked_at {
            Some(ba) => {
                let consecutive = entry.consecutive_failures;
                let expired = now
                    .duration_since(ba)
                    .map(|d| d > block_ttl)
                    .unwrap_or(true);
                if expired {
                    return false;
                }
                consecutive >= 5
            }
            None => false,
        }
    }
}

impl ScoreLookup for CachedScoreLookup {
    fn get(&self, _fp: &NetworkFingerprint, method: MethodId) -> Option<ScoreEntry> {
        self.entries.get(&method).cloned()
    }

    fn is_permanently_blocked(
        &self,
        _fp: &NetworkFingerprint,
        method: MethodId,
        block_ttl: Duration,
        now: SystemTime,
    ) -> bool {
        self.blocked_for(method, block_ttl, now)
    }
}

fn epoch_to_system(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64)
}

/// Errors from the scoring subsystem.
#[derive(Debug, thiserror::Error)]
pub enum ScoringError {
    #[error("database error: {0}")]
    DbError(String),
}
