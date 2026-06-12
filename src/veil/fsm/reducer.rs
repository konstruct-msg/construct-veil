//! The FSM reducer — pure transition function and tests.

use std::{
    collections::HashMap,
    time::{Instant, SystemTime},
};

use super::scoring::{ScoreLookup, select_probe_candidates};
use super::types::*;

/// The FSM reducer: `(state, event, scores, config, now) → (state, effects)`.
///
/// Pure function — no I/O, no side effects.
#[allow(clippy::too_many_lines)]
pub fn reduce(
    state: VeilState,
    event: VeilEvent,
    scores: &dyn ScoreLookup,
    cfg: &VeilConfig,
    now: Instant,
    now_sys: SystemTime,
) -> (VeilState, Vec<VeilEffect>) {
    match (&state, event) {
        // ── Idle ─────────────────────────────────────────────────────────
        (
            VeilState::Idle,
            VeilEvent::Start {
                relay,
                bundle,
                ref fingerprint,
                allowed_methods,
            },
        ) => {
            let candidates =
                select_probe_candidates(fingerprint, allowed_methods, scores, cfg, now_sys);

            let attempts: HashMap<MethodId, ProbeAttempt> = candidates
                .iter()
                .map(|m| (*m, ProbeAttempt { started_at: now }))
                .collect();

            let new_state = VeilState::Probing {
                candidates: candidates.clone(),
                attempts,
                started_at: now,
            };

            let effects = vec![VeilEffect::StartProbes {
                methods: candidates,
                relay,
                bundle,
            }];

            (new_state, effects)
        }

        (VeilState::Idle, VeilEvent::Stop) => (VeilState::Idle, vec![]),

        (VeilState::Idle, _) => {
            // Ignore all other events in Idle.
            (state, vec![])
        }

        // ── Probing ──────────────────────────────────────────────────────
        (
            VeilState::Probing {
                candidates,
                attempts: _,
                started_at: _,
            },
            VeilEvent::ProbeSucceeded {
                method,
                port,
                latency_ms,
            },
        ) => {
            if !candidates.contains(&method) {
                // Probe from a different session — ignore.
                return (state, vec![]);
            }

            let new_state = VeilState::Active {
                method,
                port,
                started_at: now,
                consecutive_failures: 0,
            };

            let mut effects = vec![VeilEffect::CancelOtherProbes { winner: method }];

            effects.push(VeilEffect::RecordScore {
                method,
                fingerprint: NetworkFingerprint::default(), // placeholder — caller fills
                outcome: ScoreOutcome::Success { latency_ms },
            });

            (new_state, effects)
        }

        (
            VeilState::Probing {
                candidates,
                attempts,
                started_at,
            },
            VeilEvent::ProbeFailed { method, reason },
        ) => {
            if !candidates.contains(&method) {
                return (state, vec![]);
            }

            // Remove this method from candidates.
            let new_candidates: Vec<MethodId> = candidates
                .iter()
                .filter(|&&m| m != method)
                .copied()
                .collect();

            if new_candidates.is_empty() {
                // All probes failed.
                let until = now + cfg.cooldown_duration;
                let new_state = VeilState::Cooldown { until };
                let effects = vec![VeilEffect::ScheduleCooldown {
                    duration: cfg.cooldown_duration,
                }];
                return (new_state, effects);
            }

            // Still have live candidates.
            let mut new_attempts = attempts.clone();
            new_attempts.remove(&method);

            let new_state = VeilState::Probing {
                candidates: new_candidates,
                attempts: new_attempts,
                started_at: *started_at,
            };

            let effects = vec![VeilEffect::RecordScore {
                method,
                fingerprint: NetworkFingerprint::default(),
                outcome: ScoreOutcome::Failure { reason },
            }];

            (new_state, effects)
        }

        (
            VeilState::Probing {
                candidates: _,
                attempts: _,
                started_at: _,
            },
            VeilEvent::AllProbesFailed,
        ) => {
            let until = now + cfg.cooldown_duration;
            let new_state = VeilState::Cooldown { until };
            let effects = vec![VeilEffect::ScheduleCooldown {
                duration: cfg.cooldown_duration,
            }];

            (new_state, effects)
        }

        (VeilState::Probing { .. }, VeilEvent::Stop) => {
            let effects = vec![VeilEffect::StopActive];
            (VeilState::Idle, effects)
        }

        (VeilState::Probing { .. }, _) => {
            // Ignore other events.
            (state, vec![])
        }

        // ── Active ───────────────────────────────────────────────────────
        (
            VeilState::Active {
                method,
                port,
                started_at,
                consecutive_failures,
            },
            VeilEvent::TransportFailure { kind },
        ) => {
            match kind {
                TransportFailureKind::FingerprintBlocked
                | TransportFailureKind::WebTunnelDecoyResponse => {
                    // Immediate rotation.
                    let new_state = VeilState::Degraded {
                        method: *method,
                        port: *port,
                        consecutive_failures: u8::MAX, // Force re-probe
                    };
                    (new_state, vec![])
                }
                TransportFailureKind::TlsCertProblem => {
                    // Don't record as method failure — it's a bundle issue.
                    (state, vec![])
                }
                TransportFailureKind::StreamTimeout | TransportFailureKind::Unknown => {
                    let new_fails = consecutive_failures.saturating_add(1);
                    if new_fails >= cfg.degraded_threshold {
                        (
                            VeilState::Degraded {
                                method: *method,
                                port: *port,
                                consecutive_failures: new_fails,
                            },
                            vec![],
                        )
                    } else {
                        (
                            VeilState::Active {
                                method: *method,
                                port: *port,
                                started_at: *started_at,
                                consecutive_failures: new_fails,
                            },
                            vec![],
                        )
                    }
                }
            }
        }

        (VeilState::Active { .. }, VeilEvent::Stop) => {
            (VeilState::Idle, vec![VeilEffect::StopActive])
        }

        (VeilState::Active { .. }, _) => {
            // Ignore other events in Active.
            (state, vec![])
        }

        // ── Degraded ─────────────────────────────────────────────────────
        (
            VeilState::Degraded {
                method,
                port,
                consecutive_failures,
            },
            VeilEvent::TransportFailure { kind },
        ) => {
            match kind {
                TransportFailureKind::TlsCertProblem => (state, vec![]),
                _ => {
                    let new_fails = consecutive_failures.saturating_add(1);
                    if *consecutive_failures >= cfg.degraded_threshold {
                        // Threshold already reached — move to probing without current method.
                        let effects = vec![VeilEffect::StopActive];
                        (VeilState::Idle, effects)
                    } else {
                        (
                            VeilState::Degraded {
                                method: *method,
                                port: *port,
                                consecutive_failures: new_fails,
                            },
                            vec![],
                        )
                    }
                }
            }
        }

        (VeilState::Degraded { .. }, VeilEvent::Stop) => {
            (VeilState::Idle, vec![VeilEffect::StopActive])
        }

        (VeilState::Degraded { .. }, _) => (state, vec![]),

        // ── Cooldown ─────────────────────────────────────────────────────
        (VeilState::Cooldown { until }, VeilEvent::CooldownElapsed) => {
            if now >= *until {
                (VeilState::Idle, vec![])
            } else {
                // Too early — stay in cooldown.
                (state, vec![])
            }
        }

        (VeilState::Cooldown { .. }, VeilEvent::Stop) => (VeilState::Idle, vec![]),

        (VeilState::Cooldown { .. }, _) => {
            // Ignore other events during cooldown.
            (state, vec![])
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    fn now_sys() -> SystemTime {
        SystemTime::now()
    }

    /// No-op score lookup for basic tests.
    struct NoScores;
    impl ScoreLookup for NoScores {
        fn get(&self, _fp: &NetworkFingerprint, _method: MethodId) -> Option<ScoreEntry> {
            None
        }
        fn is_permanently_blocked(
            &self,
            _fp: &NetworkFingerprint,
            _method: MethodId,
            _ttl: Duration,
            _now: SystemTime,
        ) -> bool {
            false
        }
    }

    // ── Idle transitions ──────────────────────────────────────────────────

    #[test]
    fn idle_start_goes_to_probing() {
        let state = VeilState::Idle;
        let (new_state, effects) = reduce(
            state,
            VeilEvent::Start {
                relay: "relay:443".into(),
                bundle: "cert=abc".into(),
                fingerprint: NetworkFingerprint::default(),
                allowed_methods: MethodSet::all(),
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        match new_state {
            VeilState::Probing { ref candidates, .. } => {
                assert_eq!(candidates.len(), 2); // top_k=2 by default
            }
            _ => panic!("expected Probing, got {:?}", new_state),
        }

        assert_eq!(effects.len(), 1);
        match &effects[0] {
            VeilEffect::StartProbes {
                methods,
                relay,
                bundle,
            } => {
                assert_eq!(relay, "relay:443");
                assert_eq!(bundle, "cert=abc");
                assert_eq!(methods.len(), 2);
            }
            _ => panic!("expected StartProbes effect"),
        }
    }

    #[test]
    fn idle_stop_stays_idle() {
        let (new_state, effects) = reduce(
            VeilState::Idle,
            VeilEvent::Stop,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );
        assert!(matches!(new_state, VeilState::Idle));
        assert!(effects.is_empty());
    }

    // ── Probing transitions ───────────────────────────────────────────────

    #[test]
    fn probing_probe_succeeded_goes_to_active() {
        let candidates = vec![MethodId::Obfs4, MethodId::WebTunnel];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates,
            attempts,
            started_at: now(),
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::ProbeSucceeded {
                method: MethodId::Obfs4,
                port: 12345,
                latency_ms: 500,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        match new_state {
            VeilState::Active { method, port, .. } => {
                assert_eq!(method, MethodId::Obfs4);
                assert_eq!(port, 12345);
            }
            _ => panic!("expected Active, got {:?}", new_state),
        }

        // Should emit CancelOtherProbes + RecordScore
        assert_eq!(effects.len(), 2);
        assert!(
            matches!(&effects[0], VeilEffect::CancelOtherProbes { winner } if *winner == MethodId::Obfs4)
        );
    }

    #[test]
    fn probing_probe_failed_removes_candidate() {
        let candidates = vec![MethodId::Obfs4, MethodId::WebTunnel];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates: candidates.clone(),
            attempts,
            started_at: now(),
        };

        let (new_state, _) = reduce(
            state,
            VeilEvent::ProbeFailed {
                method: MethodId::WebTunnel,
                reason: ProbeFailureReason::FingerprintBlocked,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        match new_state {
            VeilState::Probing { ref candidates, .. } => {
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0], MethodId::Obfs4);
            }
            _ => panic!("expected Probing, got {:?}", new_state),
        }
    }

    #[test]
    fn probing_last_candidate_failed_goes_to_cooldown() {
        let candidates = vec![MethodId::Obfs4];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates,
            attempts,
            started_at: now(),
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::ProbeFailed {
                method: MethodId::Obfs4,
                reason: ProbeFailureReason::ConnectionFailed,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Cooldown { .. }));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, VeilEffect::ScheduleCooldown { .. }))
        );
    }

    #[test]
    fn probing_all_probes_failed_goes_to_cooldown() {
        let candidates = vec![MethodId::Obfs4, MethodId::WebTunnel];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates,
            attempts,
            started_at: now(),
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::AllProbesFailed,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Cooldown { .. }));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, VeilEffect::ScheduleCooldown { .. }))
        );
    }

    #[test]
    fn probing_stop_goes_to_idle() {
        let candidates = vec![MethodId::Obfs4, MethodId::WebTunnel];
        let attempts: HashMap<MethodId, ProbeAttempt> = candidates
            .iter()
            .map(|m| (*m, ProbeAttempt { started_at: now() }))
            .collect();
        let state = VeilState::Probing {
            candidates,
            attempts,
            started_at: now(),
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::Stop,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );
        assert!(matches!(new_state, VeilState::Idle));
        assert!(effects.iter().any(|e| matches!(e, VeilEffect::StopActive)));
    }

    // ── Active transitions ────────────────────────────────────────────────

    #[test]
    fn active_stream_timeout_increments_failures() {
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 0,
        };

        let (new_state, _) = reduce(
            state.clone(),
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::StreamTimeout,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        match new_state {
            VeilState::Active {
                consecutive_failures,
                ..
            } => {
                assert_eq!(consecutive_failures, 1);
            }
            _ => panic!("expected Active, got {:?}", new_state),
        }
    }

    #[test]
    fn active_fingerprint_blocked_immediate_rotation() {
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 0,
        };

        let (new_state, _) = reduce(
            state,
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::FingerprintBlocked,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(
            new_state,
            VeilState::Degraded {
                consecutive_failures: u8::MAX,
                ..
            }
        ));
    }

    #[test]
    fn active_tls_cert_problem_no_state_change() {
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 0,
        };

        let (new_state, effects) = reduce(
            state.clone(),
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::TlsCertProblem,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Active { .. }));
        assert!(effects.is_empty());
    }

    #[test]
    fn active_degraded_threshold_reached() {
        let cfg = VeilConfig {
            degraded_threshold: 2,
            ..VeilConfig::default()
        };
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 1,
        };

        let (new_state, _) = reduce(
            state,
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::StreamTimeout,
            },
            &NoScores,
            &cfg,
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Degraded { .. }));
    }

    #[test]
    fn active_stop_goes_to_idle() {
        let state = VeilState::Active {
            method: MethodId::Obfs4,
            port: 12345,
            started_at: now(),
            consecutive_failures: 0,
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::Stop,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );
        assert!(matches!(new_state, VeilState::Idle));
        assert!(effects.iter().any(|e| matches!(e, VeilEffect::StopActive)));
    }

    // ── Degraded transitions ──────────────────────────────────────────────

    #[test]
    fn degraded_more_failures_idle() {
        let state = VeilState::Degraded {
            method: MethodId::Obfs4,
            port: 12345,
            consecutive_failures: 2,
        };

        let (new_state, effects) = reduce(
            state,
            VeilEvent::TransportFailure {
                kind: TransportFailureKind::StreamTimeout,
            },
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        // Threshold reached (2 >= 2) → goes to Idle with StopActive.
        assert!(matches!(new_state, VeilState::Idle));
        assert!(effects.iter().any(|e| matches!(e, VeilEffect::StopActive)));
    }

    // ── Cooldown transitions ──────────────────────────────────────────────

    #[test]
    fn cooldown_elapsed_goes_to_idle() {
        let until = now() - Duration::from_secs(1); // already elapsed
        let state = VeilState::Cooldown { until };

        let (new_state, _) = reduce(
            state,
            VeilEvent::CooldownElapsed,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Idle));
    }

    #[test]
    fn cooldown_not_yet_elapsed_stays_cooldown() {
        let until = now() + Duration::from_secs(30);
        let state = VeilState::Cooldown { until };

        let (new_state, _) = reduce(
            state.clone(),
            VeilEvent::CooldownElapsed,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );

        assert!(matches!(new_state, VeilState::Cooldown { .. }));
    }

    #[test]
    fn cooldown_stop_goes_to_idle() {
        let until = now() + Duration::from_secs(30);
        let state = VeilState::Cooldown { until };

        let (new_state, _) = reduce(
            state,
            VeilEvent::Stop,
            &NoScores,
            &VeilConfig::default(),
            now(),
            now_sys(),
        );
        assert!(matches!(new_state, VeilState::Idle));
    }

    // ── Candidate selection ───────────────────────────────────────────────

    #[test]
    fn select_candidates_returns_top_k() {
        struct MockScores;
        impl ScoreLookup for MockScores {
            fn get(&self, _fp: &NetworkFingerprint, method: MethodId) -> Option<ScoreEntry> {
                match method {
                    MethodId::Obfs4 => Some(ScoreEntry {
                        successes: 10,
                        failures: 1,
                        last_success_at: Some(SystemTime::now() - Duration::from_secs(60)),
                        last_failure_at: None,
                        median_latency_ms: 800,
                        blocked_at: None,
                        consecutive_failures: 0,
                    }),
                    MethodId::WebTunnel => Some(ScoreEntry {
                        successes: 2,
                        failures: 5,
                        last_success_at: None,
                        last_failure_at: Some(SystemTime::now() - Duration::from_secs(3600)),
                        median_latency_ms: 2000,
                        blocked_at: None,
                        consecutive_failures: 3,
                    }),
                    _ => None,
                }
            }
            fn is_permanently_blocked(
                &self,
                _fp: &NetworkFingerprint,
                _method: MethodId,
                _ttl: Duration,
                _now: SystemTime,
            ) -> bool {
                false
            }
        }

        let cfg = VeilConfig {
            top_k_probes: 2,
            ..VeilConfig::default()
        };
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &MockScores,
            &cfg,
            now_sys(),
        );

        assert_eq!(candidates.len(), 2);
        // Obfs4 should be first (higher score).
        assert_eq!(candidates[0], MethodId::Obfs4);
    }

    #[test]
    fn select_candidates_skips_permanently_blocked() {
        struct BlockedScores;
        impl ScoreLookup for BlockedScores {
            fn get(&self, _fp: &NetworkFingerprint, method: MethodId) -> Option<ScoreEntry> {
                match method {
                    MethodId::WebTunnel => Some(ScoreEntry {
                        successes: 0,
                        failures: 10,
                        last_success_at: None,
                        last_failure_at: Some(SystemTime::now()),
                        median_latency_ms: 0,
                        blocked_at: Some(SystemTime::now() - Duration::from_secs(3600)),
                        consecutive_failures: 10,
                    }),
                    _ => None,
                }
            }
            fn is_permanently_blocked(
                &self,
                _fp: &NetworkFingerprint,
                method: MethodId,
                _ttl: Duration,
                _now: SystemTime,
            ) -> bool {
                method == MethodId::WebTunnel
            }
        }

        let cfg = VeilConfig {
            top_k_probes: 2,
            ..VeilConfig::default()
        };
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &BlockedScores,
            &cfg,
            now_sys(),
        );

        // WebTunnel should be skipped; Obfs4 and Masque (both no data = 50.0) remain.
        assert_eq!(candidates.len(), 2);
        assert!(!candidates.contains(&MethodId::WebTunnel));
        // Obfs4 should be first (tied score, but appears earlier in MethodId::all()).
        assert_eq!(candidates[0], MethodId::Obfs4);
    }

    #[test]
    fn select_candidates_empty_fallback() {
        struct AllBlockedScores;
        impl ScoreLookup for AllBlockedScores {
            fn get(&self, _fp: &NetworkFingerprint, _method: MethodId) -> Option<ScoreEntry> {
                Some(ScoreEntry {
                    successes: 0,
                    failures: 5,
                    last_success_at: None,
                    last_failure_at: Some(SystemTime::now()),
                    median_latency_ms: 0,
                    blocked_at: Some(SystemTime::now() - Duration::from_secs(86400)),
                    consecutive_failures: 5,
                })
            }
            fn is_permanently_blocked(
                &self,
                _fp: &NetworkFingerprint,
                _method: MethodId,
                _ttl: Duration,
                _now: SystemTime,
            ) -> bool {
                true
            }
        }

        let cfg = VeilConfig {
            top_k_probes: 2,
            ..VeilConfig::default()
        };
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &AllBlockedScores,
            &cfg,
            now_sys(),
        );

        // Should pick the least-recently-blocked method as a fallback.
        assert!(!candidates.is_empty());
    }

    // ── Legacy (top_k=1) behaviour ────────────────────────────────────────

    #[test]
    fn legacy_config_selects_one_candidate() {
        let cfg = VeilConfig::legacy();
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &NoScores,
            &cfg,
            now_sys(),
        );

        assert_eq!(candidates.len(), 1);
    }

    // ── Method set ────────────────────────────────────────────────────────

    #[test]
    fn method_set_all_allows_everything() {
        let ms = MethodSet::all();
        assert!(ms.contains(MethodId::Obfs4));
        assert!(ms.contains(MethodId::WebTunnel));
        assert!(ms.contains(MethodId::Masque));
        assert!(ms.contains(MethodId::VeilFront));
    }

    #[test]
    fn method_set_disables_specific_method() {
        let ms = MethodSet::from_bitmask(MethodId::WebTunnel.bit());
        assert!(ms.contains(MethodId::Obfs4));
        assert!(!ms.contains(MethodId::WebTunnel));
    }

    #[test]
    fn method_bits_are_distinct_single_flags() {
        // `MethodSet` ANDs these (`self.0 & method.bit()`), so each must be a
        // distinct single bit. A bare discriminant (Obfs4=0, VeilFront=3=0b11)
        // collides and corrupts any non-zero allowed-set bitmask.
        let bits: Vec<u32> = MethodId::all().iter().map(|m| m.bit()).collect();
        for (m, b) in MethodId::all().iter().zip(&bits) {
            assert_eq!(b.count_ones(), 1, "{m:?}.bit()={b:#b} is not a single flag");
        }
        let combined = bits.iter().fold(0u32, |a, b| a | b);
        assert_eq!(
            combined.count_ones() as usize,
            bits.len(),
            "method bits collide: {bits:?}"
        );
    }

    #[test]
    fn disabling_all_but_veil_front_leaves_only_veil_front() {
        // Mirrors the coordinator's "restrict allowed to registered" logic for a
        // veil-front-only build: disable every method except VeilFront.
        let mut bits = 0u32;
        for m in MethodId::all() {
            if *m != MethodId::VeilFront {
                bits |= m.bit();
            }
        }
        let ms = MethodSet::from_bitmask(bits);
        assert!(ms.contains(MethodId::VeilFront));
        assert!(!ms.contains(MethodId::Obfs4));
        assert!(!ms.contains(MethodId::WebTunnel));
        assert_eq!(
            ms.iter_allowed().collect::<Vec<_>>(),
            vec![MethodId::VeilFront]
        );
    }

    #[test]
    fn veil_front_is_a_candidate() {
        struct VeilFrontOnlyScores;
        impl ScoreLookup for VeilFrontOnlyScores {
            fn get(&self, _fp: &NetworkFingerprint, method: MethodId) -> Option<ScoreEntry> {
                match method {
                    MethodId::VeilFront => Some(ScoreEntry {
                        successes: 5,
                        failures: 0,
                        last_success_at: Some(SystemTime::now() - Duration::from_secs(60)),
                        last_failure_at: None,
                        median_latency_ms: 300,
                        blocked_at: None,
                        consecutive_failures: 0,
                    }),
                    // All other methods are blocked.
                    MethodId::Obfs4 | MethodId::WebTunnel | MethodId::Masque => Some(ScoreEntry {
                        successes: 0,
                        failures: 10,
                        last_success_at: None,
                        last_failure_at: Some(SystemTime::now()),
                        median_latency_ms: 0,
                        blocked_at: Some(SystemTime::now() - Duration::from_secs(3600)),
                        consecutive_failures: 10,
                    }),
                }
            }
            fn is_permanently_blocked(
                &self,
                _fp: &NetworkFingerprint,
                method: MethodId,
                _ttl: Duration,
                _now: SystemTime,
            ) -> bool {
                method != MethodId::VeilFront
            }
        }

        let cfg = VeilConfig {
            top_k_probes: 2,
            ..VeilConfig::default()
        };
        let candidates = select_probe_candidates(
            &NetworkFingerprint::default(),
            MethodSet::all(),
            &VeilFrontOnlyScores,
            &cfg,
            now_sys(),
        );

        // VeilFront should be the only candidate (others are blocked).
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], MethodId::VeilFront);
    }
}
