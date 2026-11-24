//! The FSM reducer — pure transition function and tests.

use std::{collections::HashMap, time::Instant};

use super::types::*;

/// The methods one session probes: the allowed ones, in [`MethodId::all`] order, at
/// most `top_k_probes` of them.
///
/// Nothing ranks them by history. Until 2026-11-24 a per-network SQLite score did, and
/// with the one method that ships it returned that method whatever the score said,
/// "blocked" included (todo 341).
pub fn probe_candidates(allowed: MethodSet, cfg: &VeilConfig) -> Vec<MethodId> {
    allowed.iter_allowed().take(cfg.top_k_probes).collect()
}

/// The FSM reducer: `(state, event, config, now) → (state, effects)`.
///
/// Pure function — no I/O, no side effects.
#[allow(clippy::too_many_lines)]
pub fn reduce(
    state: VeilState,
    event: VeilEvent,
    cfg: &VeilConfig,
    now: Instant,
) -> (VeilState, Vec<VeilEffect>) {
    match (&state, event) {
        // ── Idle ─────────────────────────────────────────────────────────
        (
            VeilState::Idle,
            VeilEvent::Start {
                relay,
                allowed_methods,
            },
        ) => {
            let candidates = probe_candidates(allowed_methods, cfg);

            // Nothing to probe (the host allowed no method, or none is registered):
            // there is no probe race to run, so this is "all probes failed" right
            // away. Until 2026-10-22 this produced `StartProbes { methods: [] }`,
            // which the coordinator's parallel path turned into `mpsc::channel(0)`
            // — a panic, and through the FFI an abort of the host app.
            if candidates.is_empty() {
                let until = now + cfg.cooldown_duration;
                return (
                    VeilState::Cooldown { until },
                    vec![VeilEffect::ScheduleCooldown {
                        duration: cfg.cooldown_duration,
                    }],
                );
            }

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
            VeilEvent::ProbeSucceeded { method, port },
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

            let effects = vec![VeilEffect::CancelOtherProbes { winner: method }];

            (new_state, effects)
        }

        (
            VeilState::Probing {
                candidates,
                attempts,
                started_at,
            },
            VeilEvent::ProbeFailed { method },
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

            (new_state, vec![])
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
                TransportFailureKind::FingerprintBlocked => {
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

    // ── Idle transitions ──────────────────────────────────────────────────

    /// No allowed method → straight to Cooldown, never `StartProbes { [] }`.
    /// Mutation: drop the `candidates.is_empty()` guard — this gets Probing with
    /// an empty StartProbes effect.
    #[test]
    fn start_with_no_allowed_method_goes_to_cooldown_without_probes() {
        let (new_state, effects) = reduce(
            VeilState::Idle,
            VeilEvent::Start {
                relay: "relay:443".into(),
                allowed_methods: MethodSet::none(),
            },
            &VeilConfig::default(),
            now(),
        );
        assert!(
            matches!(new_state, VeilState::Cooldown { .. }),
            "{new_state:?}"
        );
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, VeilEffect::StartProbes { .. })),
            "{effects:?}"
        );
    }

    #[test]
    fn idle_start_goes_to_probing() {
        let state = VeilState::Idle;
        let (new_state, effects) = reduce(
            state,
            VeilEvent::Start {
                relay: "relay:443".into(),
                allowed_methods: MethodSet::all(),
            },
            &VeilConfig::default(),
            now(),
        );

        match new_state {
            VeilState::Probing { ref candidates, .. } => {
                assert_eq!(candidates.len(), 2); // top_k=2 by default
            }
            _ => panic!("expected Probing, got {:?}", new_state),
        }

        assert_eq!(effects.len(), 1);
        match &effects[0] {
            VeilEffect::StartProbes { methods, relay } => {
                assert_eq!(relay, "relay:443");
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
            &VeilConfig::default(),
            now(),
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
            },
            &VeilConfig::default(),
            now(),
        );

        match new_state {
            VeilState::Active { method, port, .. } => {
                assert_eq!(method, MethodId::Obfs4);
                assert_eq!(port, 12345);
            }
            _ => panic!("expected Active, got {:?}", new_state),
        }

        assert_eq!(effects.len(), 1);
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
            },
            &VeilConfig::default(),
            now(),
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
            },
            &VeilConfig::default(),
            now(),
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
            &VeilConfig::default(),
            now(),
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

        let (new_state, effects) = reduce(state, VeilEvent::Stop, &VeilConfig::default(), now());
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
            &VeilConfig::default(),
            now(),
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
            &VeilConfig::default(),
            now(),
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
            &VeilConfig::default(),
            now(),
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
            &cfg,
            now(),
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

        let (new_state, effects) = reduce(state, VeilEvent::Stop, &VeilConfig::default(), now());
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
            &VeilConfig::default(),
            now(),
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
            &VeilConfig::default(),
            now(),
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
            &VeilConfig::default(),
            now(),
        );

        assert!(matches!(new_state, VeilState::Cooldown { .. }));
    }

    #[test]
    fn cooldown_stop_goes_to_idle() {
        let until = now() + Duration::from_secs(30);
        let state = VeilState::Cooldown { until };

        let (new_state, _) = reduce(state, VeilEvent::Stop, &VeilConfig::default(), now());
        assert!(matches!(new_state, VeilState::Idle));
    }

    // ── Candidate selection ───────────────────────────────────────────────

    /// The allowed methods in their fixed order, cut to `top_k_probes`. Mutation: drop
    /// the `take` (four candidates), or iterate `MethodId::all()` without the filter.
    #[test]
    fn candidates_are_the_allowed_methods_in_order_up_to_top_k() {
        let cfg = VeilConfig::default(); // top_k = 2
        assert_eq!(
            probe_candidates(MethodSet::all(), &cfg),
            vec![MethodId::Obfs4, MethodId::WebTunnel]
        );
        assert_eq!(
            probe_candidates(MethodSet::from_bitmask(MethodId::Obfs4.bit()), &cfg),
            vec![MethodId::WebTunnel, MethodId::Masque]
        );
        assert_eq!(
            probe_candidates(MethodSet::all(), &VeilConfig::legacy()),
            vec![MethodId::Obfs4]
        );
        assert!(probe_candidates(MethodSet::none(), &cfg).is_empty());
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
        assert_eq!(
            probe_candidates(ms, &VeilConfig::default()),
            vec![MethodId::VeilFront]
        );
    }
}
