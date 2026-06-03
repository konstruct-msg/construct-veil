//! Scoring — score lookup trait, entry struct, and candidate selection.

use std::time::{Duration, SystemTime};

use super::types::{MethodId, NetworkFingerprint, ScoreEntry, VeilConfig};

/// Trait for accessing scores from the FSM (decoupled from SQLite).
pub trait ScoreLookup {
    /// Get score for a (fingerprint, method) pair. Returns None if no data.
    fn get(&self, fingerprint: &NetworkFingerprint, method: MethodId) -> Option<ScoreEntry>;

    /// Check if a method is permanently blocked on this network.
    fn is_permanently_blocked(
        &self,
        fingerprint: &NetworkFingerprint,
        method: MethodId,
        block_ttl: Duration,
        now: SystemTime,
    ) -> bool;
}

/// Select top-K probe candidates based on scores.
pub fn select_probe_candidates(
    fingerprint: &NetworkFingerprint,
    allowed: super::types::MethodSet,
    scores: &dyn ScoreLookup,
    cfg: &VeilConfig,
    now: SystemTime,
) -> Vec<MethodId> {
    let mut scored: Vec<(MethodId, f64)> = Vec::new();

    for method in allowed.iter_allowed() {
        // Skip permanently blocked methods (unless everything is blocked).
        if scores.is_permanently_blocked(fingerprint, method, cfg.block_ttl, now) {
            continue;
        }

        let score = compute_score(scores, fingerprint, method, now);
        scored.push((method, score));
    }

    // Sort by score descending.
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Take top-K.
    let top_k = cfg.top_k_probes.min(scored.len());
    let mut candidates: Vec<MethodId> = scored.iter().take(top_k).map(|(m, _)| *m).collect();

    // If zero candidates (everything blocked), try the least-recently-blocked method.
    if candidates.is_empty() {
        let mut blocked_methods: Vec<(MethodId, Option<SystemTime>)> = allowed
            .iter_allowed()
            .filter_map(|m| {
                let entry = scores.get(fingerprint, m);
                entry.and_then(|e| e.blocked_at.map(|t| (m, Some(t))))
            })
            .collect();
        blocked_methods.sort_by_key(|&(_, t)| t);
        if let Some((m, _)) = blocked_methods.first() {
            candidates.push(*m);
        } else {
            // Fallback: allow any method from the allowed set.
            if let Some(first) = allowed.iter_allowed().next() {
                candidates.push(first);
            }
        }
    }

    candidates
}

/// Compute score for a (fingerprint, method) pair.
///
/// score = base_quality − recent_failure_penalty − latency_penalty + recency_bonus
fn compute_score(
    scores: &dyn ScoreLookup,
    fingerprint: &NetworkFingerprint,
    method: MethodId,
    now: SystemTime,
) -> f64 {
    let entry = match scores.get(fingerprint, method) {
        Some(e) => e,
        None => return 50.0, // base_quality for new method (no data)
    };

    let total = entry.successes as f64 + entry.failures as f64;
    if total == 0.0 {
        return 50.0; // No data yet
    }

    // base_quality: EWMA-style success rate mapped to [0, 100]
    let base_quality = (entry.successes as f64 / total) * 100.0;

    // recent_failure_penalty: -20 per failure in last 5 minutes, linear decay over 1 hour
    let recent_failure_penalty = compute_recent_failure_penalty(&entry, now);

    // latency_penalty: min(20, (median_latency_ms - 1000) / 100)
    let latency_penalty = if entry.median_latency_ms > 1000 {
        ((entry.median_latency_ms as f64 - 1000.0) / 100.0).min(20.0)
    } else {
        0.0
    };

    // recency_bonus: +5 if last success < 1 hour ago
    let recency_bonus = entry
        .last_success_at
        .and_then(|t| now.duration_since(t).ok())
        .map(|d| {
            if d < Duration::from_secs(3600) {
                5.0
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);

    base_quality - recent_failure_penalty - latency_penalty + recency_bonus
}

/// Compute recent failure penalty.
/// Each failure in last 5 minutes = -20, decays linearly over 1 hour.
fn compute_recent_failure_penalty(entry: &ScoreEntry, now: SystemTime) -> f64 {
    let last_failure = match entry.last_failure_at {
        Some(t) => t,
        None => return 0.0,
    };

    let elapsed = match now.duration_since(last_failure) {
        Ok(d) => d,
        Err(_) => return 0.0, // future timestamp — ignore
    };

    let five_minutes = Duration::from_secs(300);
    let one_hour = Duration::from_secs(3600);

    if elapsed > one_hour {
        return 0.0;
    }

    if elapsed <= five_minutes {
        // Each recent failure = -20
        // We don't track individual failures, so use consecutive_failures as proxy
        (entry.consecutive_failures as f64) * 20.0
    } else {
        // Linear decay from 5 min to 1 hour
        let decay = 1.0 - (elapsed.as_secs_f64() - 300.0) / (3600.0 - 300.0);
        (entry.consecutive_failures as f64) * 20.0 * decay.max(0.0)
    }
}
