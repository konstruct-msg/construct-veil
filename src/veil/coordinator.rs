//! VeilCoordinator — the async orchestrator that drives the FSM, executes probes,
//! and manages the active proxy.
//!
//! This is the bridge between the pure FSM (`reduce()`) and real I/O:
//! - Executes `VeilEffect`s (start probes, cancel, record scores, schedule cooldown)
//! - Feeds `VeilEvent`s back to the FSM based on probe results
//! - Manages the active proxy loop once a method wins the probe race

#![allow(missing_docs)]

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::veil::fsm::{
    MethodId, MethodSet, NetworkFingerprint, ProbeFailureReason, TransportFailureKind, VeilConfig,
    VeilEffect, VeilEvent, VeilState, reduce,
};
use crate::veil::obfuscator::{Obfuscator, ObfuscatorError, ProbeRequest, VeilFrontAuthV3};
use crate::veil::scoring::{CachedScoreLookup, PersistentScores};

/// Result of a single probe attempt.
struct ProbeResult {
    method: MethodId,
    /// None if the probe failed; Some(latency_ms) if it succeeded.
    outcome: ProbeOutcome,
}

enum ProbeOutcome {
    Success {
        #[allow(dead_code)]
        port: u16,
        latency_ms: u32,
    },
    Failure {
        reason: ProbeFailureReason,
        latency_ms: u32,
    },
}

/// Result returned when a coordinator session starts successfully.
pub struct CoordinatorStartResult {
    /// Local TCP port the proxy is listening on.
    pub port: u16,
    /// Which obfuscator method won the probe race.
    pub method: MethodId,
    /// Wall-clock ms from start to first byte through the tunnel.
    pub latency_ms: u32,
}

/// Handle to a running coordinator session.
/// Used by `veil_stop()` to shut down the active proxy.
struct ActiveSession {
    /// Distinguishes this session from the next one: the proxy task clears the
    /// slot on exit only if the slot still holds its own session.
    id: u64,
    port: u16,
    #[allow(dead_code)]
    method: MethodId,
    shutdown_tx: oneshot::Sender<()>,
    /// Cancels every tunnel this session's listener accepted.
    tunnels: CancellationToken,
}

impl ActiveSession {
    /// Stop accepting and tear down the session's live tunnels.
    fn shut_down(self) {
        let _ = self.shutdown_tx.send(());
        self.tunnels.cancel();
    }
}

/// The main VEIL coordinator.
///
/// Drives the FSM through probing, manages parallel probe tasks,
/// and runs the proxy loop for the winning method.
pub struct VeilCoordinator {
    config: VeilConfig,
    scores: Arc<PersistentScores>,
    obfuscators: HashMap<MethodId, Arc<dyn Obfuscator>>,
    active: Arc<Mutex<Option<ActiveSession>>>,
    next_session_id: std::sync::atomic::AtomicU64,
}

impl VeilCoordinator {
    /// Create a new coordinator with the given config and scores store.
    pub fn new(config: VeilConfig, scores: PersistentScores) -> Self {
        Self {
            config,
            scores: Arc::new(scores),
            obfuscators: HashMap::new(),
            active: Arc::new(Mutex::new(None)),
            next_session_id: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Register an obfuscator method.
    pub fn register(&mut self, obfuscator: Box<dyn Obfuscator>) {
        self.obfuscators
            .insert(obfuscator.method_id(), Arc::from(obfuscator));
    }

    /// Start an VEIL session with full TLS/WebTunnel parameters.
    ///
    /// This is the main entry point for the coordinator.
    /// For Phase 1 (top_k_probes=1), probes are executed sequentially.
    /// Once a probe succeeds, the proxy loop is started and the port is returned.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_session_with_params(
        &self,
        relay: String,
        bundle: String,
        fingerprint: NetworkFingerprint,
        allowed_methods: MethodSet,
        tls_sni: String,
        spki_hex: String,
        host_header: String,
        wt_base_path: String,
        veil_front_ticket_b64: String,
        veil_front_auth_v3: VeilFrontAuthV3,
    ) -> Result<CoordinatorStartResult, CoordinatorError> {
        let start_time = Instant::now();
        let mut state = VeilState::Idle;

        // Restrict the allowed set to methods we actually have an obfuscator for.
        // The host passes "all methods" (bitmask 0), but a build may register only
        // a subset (e.g. veil-front-only on `utls`). Without this, the scorer can
        // pick an unregistered method into the top-K — it "immediately fails", the
        // registered method gets starved, no real probe runs, and the FSM dead-ends
        // in Cooldown (previously slept 30s then returned the misleading
        // "session was stopped").
        let allowed_methods = {
            let mut bits = allowed_methods.0;
            for m in MethodId::all() {
                if !self.obfuscators.contains_key(m) {
                    bits |= m.bit();
                }
            }
            MethodSet::from_bitmask(bits)
        };
        // Nothing allowed and registered: a configuration error for the host, not
        // a probe race. (Until 2026-10-22 this reached the parallel path as an
        // empty method list and panicked in `mpsc::channel(0)`.)
        if allowed_methods.iter_allowed().next().is_none() {
            return Err(CoordinatorError::NoMethods);
        }

        info!(
            target: "ice::coordinator",
            "session started  fingerprint={} methods={:?}",
            fingerprint.short_hex(),
            allowed_methods.iter_allowed().collect::<Vec<_>>(),
        );

        // One-shot start for FFI hosts (`veil_start`): run a single probe cycle and
        // return. Do NOT sleep the internal Cooldown here.
        //
        // Why: iOS/Swift already owns backoff (`TransportConfig.veilCooldownDuration`).
        // Sleeping 30s inside `block_on(veil_start)` (1) doubles cooldown with the
        // host, (2) freezes the caller's thread for the whole sleep, and under iOS
        // suspension stretches wall-clock into minutes while the process looks stuck
        // in `veil-probing` — then surfaces as the misleading "session was stopped"
        // when CooldownElapsed → Idle. Device heat log 2026-07-21: first start
        // 15:32→16:15 "session was stopped" after a suspended internal cooldown.
        loop {
            // Build cached score lookup for this iteration.
            // Scores are telemetry for ordering the probes; they never gate
            // connectivity. An unreadable store (locked, full disk, corrupt file)
            // means "probe without history", not "fail the start".
            let scores_cache = match CachedScoreLookup::build(&self.scores, &fingerprint).await {
                Ok(cache) => cache,
                Err(e) => {
                    warn!(
                        target: "ice::coordinator",
                        "scores unreadable, probing without history: {e}"
                    );
                    CachedScoreLookup::empty(&fingerprint)
                }
            };

            let now = Instant::now();
            let now_sys = SystemTime::now();

            // Determine the next event based on current state.
            let event = match &state {
                VeilState::Idle => VeilEvent::Start {
                    relay: relay.clone(),
                    bundle: bundle.clone(),
                    fingerprint: fingerprint.clone(),
                    allowed_methods,
                },
                // Unreachable for the one-shot path: we return on Cooldown below.
                // Kept so a future long-lived coordinator loop can re-enable sleep.
                VeilState::Cooldown { until } => {
                    let remaining = until.saturating_duration_since(now);
                    if !remaining.is_zero() {
                        info!(
                            target: "ice::coordinator",
                            "cooldown  duration={:?}s",
                            remaining.as_secs(),
                        );
                        tokio::time::sleep(remaining).await;
                    }
                    VeilEvent::CooldownElapsed
                }
                VeilState::Active { .. }
                | VeilState::Probing { .. }
                | VeilState::Degraded { .. } => {
                    break;
                }
            };

            // Run the FSM reducer.
            let (new_state, effects) =
                reduce(state, event, &scores_cache, &self.config, now, now_sys);
            state = new_state;

            // Execute effects.
            for effect in &effects {
                self.execute_effect_with_params(
                    effect,
                    &fingerprint,
                    &relay,
                    &bundle,
                    &mut state,
                    &scores_cache,
                    &tls_sni,
                    &spki_hex,
                    &host_header,
                    &wt_base_path,
                    &veil_front_ticket_b64,
                    &veil_front_auth_v3,
                    start_time,
                )
                .await?;
            }

            // Check terminal states.
            match &state {
                VeilState::Active { method, port, .. } => {
                    let latency = start_time.elapsed().as_millis() as u32;
                    info!(
                        target: "ice::coordinator",
                        "active  method={} port={}",
                        method.name(),
                        port,
                    );

                    // Proxy is already running (started in execute_effect).
                    // Brief wait to ensure registration.
                    tokio::time::sleep(Duration::from_millis(50)).await;

                    return Ok(CoordinatorStartResult {
                        port: *port,
                        method: *method,
                        latency_ms: latency,
                    });
                }
                // All methods failed this cycle. Hand backoff to the host immediately.
                VeilState::Cooldown { .. } => {
                    info!(
                        target: "ice::coordinator",
                        "all probes failed — returning AllProbesFailed (host owns cooldown)"
                    );
                    return Err(CoordinatorError::AllProbesFailed);
                }
                // Explicit Stop (or Start that never left Idle). Not a probe failure.
                VeilState::Idle => {
                    return Err(CoordinatorError::Stopped);
                }
                _ => {}
            }
        }

        unreachable!("FSM should transition to Active, Idle, or Cooldown")
    }

    /// Start an VEIL session with default TLS/WebTunnel parameters.
    ///
    /// Delegates to [`start_session_with_params`] with empty TLS/WebTunnel params
    /// and no veil-front ticket (so veil-front is effectively excluded from the
    /// race — its probe will fail ticket parsing).
    pub async fn start_session(
        &self,
        relay: String,
        bundle: String,
        fingerprint: NetworkFingerprint,
        allowed_methods: MethodSet,
    ) -> Result<CoordinatorStartResult, CoordinatorError> {
        self.start_session_with_params(
            relay,
            bundle,
            fingerprint,
            allowed_methods,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            VeilFrontAuthV3::default(),
        )
        .await
    }

    /// Execute a single FSM effect (with full TLS/WebTunnel params).
    #[allow(clippy::too_many_arguments)]
    async fn execute_effect_with_params(
        &self,
        effect: &VeilEffect,
        fingerprint: &NetworkFingerprint,
        relay: &str,
        bundle: &str,
        state: &mut VeilState,
        scores_cache: &CachedScoreLookup,
        tls_sni: &str,
        spki_hex: &str,
        host_header: &str,
        wt_base_path: &str,
        veil_front_ticket_b64: &str,
        veil_front_auth_v3: &VeilFrontAuthV3,
        _start_time: Instant,
    ) -> Result<(), CoordinatorError> {
        match effect {
            VeilEffect::StartProbes { methods, .. } => {
                info!(
                    target: "ice::fsm",
                    "probing started  fingerprint={} methods={:?} reason=fresh",
                    fingerprint.short_hex(),
                    methods,
                );

                if methods.len() == 1 {
                    // Single probe — sequential path (Phase 1, legacy).
                    self.run_sequential_probes(
                        methods,
                        fingerprint,
                        relay,
                        bundle,
                        state,
                        scores_cache,
                        tls_sni,
                        spki_hex,
                        host_header,
                        wt_base_path,
                        veil_front_ticket_b64,
                        veil_front_auth_v3,
                    )
                    .await?;
                } else {
                    // Multiple probes — parallel happy-eyeballs path (Phase 2).
                    self.run_parallel_probes(
                        methods,
                        fingerprint,
                        relay,
                        bundle,
                        state,
                        scores_cache,
                        tls_sni,
                        spki_hex,
                        host_header,
                        wt_base_path,
                        veil_front_ticket_b64,
                        veil_front_auth_v3,
                    )
                    .await?;
                }
            }

            VeilEffect::CancelOtherProbes { winner } => {
                info!(
                    target: "ice::fsm",
                    "cancelled other probes  winner={}",
                    winner.name(),
                );
            }

            VeilEffect::StopActive => {
                info!(target: "ice::fsm", "stop_active");
                let mut guard = self.active.lock().await;
                if let Some(session) = guard.take() {
                    session.shut_down();
                }
            }

            VeilEffect::ScheduleCooldown { duration } => {
                info!(
                    target: "ice::fsm",
                    "cooldown  duration={:?}s reason=all_probes_failed",
                    duration.as_secs(),
                );
            }

            VeilEffect::RecordScore {
                method,
                fingerprint: fp,
                outcome,
            } => {
                let fp_to_use = if fp.as_bytes().iter().all(|&b| b == 0) {
                    fingerprint
                } else {
                    fp
                };
                self.scores
                    .record(fp_to_use, *method, *outcome)
                    .await
                    .map_err(|e| CoordinatorError::Scoring(e.to_string()))?;
            }
        }

        Ok(())
    }

    /// Run probes sequentially (top_k_probes=1).
    #[allow(clippy::too_many_arguments)]
    async fn run_sequential_probes(
        &self,
        methods: &[MethodId],
        fingerprint: &NetworkFingerprint,
        relay: &str,
        bundle: &str,
        state: &mut VeilState,
        scores_cache: &CachedScoreLookup,
        tls_sni: &str,
        spki_hex: &str,
        host_header: &str,
        wt_base_path: &str,
        veil_front_ticket_b64: &str,
        veil_front_auth_v3: &VeilFrontAuthV3,
    ) -> Result<(), CoordinatorError> {
        for &method in methods {
            let probe_start = Instant::now();

            let result = self
                .execute_probe_with_params(
                    method,
                    relay,
                    bundle,
                    tls_sni,
                    spki_hex,
                    host_header,
                    wt_base_path,
                    veil_front_ticket_b64,
                    veil_front_auth_v3,
                )
                .await;

            match result {
                Ok(()) => {
                    let latency_ms = probe_start.elapsed().as_millis() as u32;
                    self.handle_probe_success(
                        method,
                        latency_ms,
                        fingerprint,
                        relay,
                        bundle,
                        tls_sni,
                        spki_hex,
                        veil_front_ticket_b64,
                        veil_front_auth_v3,
                        state,
                        scores_cache,
                    )
                    .await?;
                    return Ok(());
                }
                Err(reason) => {
                    let latency_ms = probe_start.elapsed().as_millis() as u32;
                    self.handle_probe_failure(
                        method,
                        reason,
                        latency_ms,
                        fingerprint,
                        state,
                        scores_cache,
                    )
                    .await;

                    if matches!(*state, VeilState::Cooldown { .. } | VeilState::Idle) {
                        break;
                    }
                }
            }
        }

        self.handle_all_probes_failed(state, scores_cache);
        Ok(())
    }

    /// Run probes in parallel with staggered starts (happy-eyeballs).
    ///
    /// Probes are started with `inter_probe_delay` between them.
    /// The first probe to succeed wins; all others are cancelled.
    #[allow(clippy::too_many_arguments)]
    async fn run_parallel_probes(
        &self,
        methods: &[MethodId],
        fingerprint: &NetworkFingerprint,
        relay: &str,
        bundle: &str,
        state: &mut VeilState,
        scores_cache: &CachedScoreLookup,
        tls_sni: &str,
        spki_hex: &str,
        host_header: &str,
        wt_base_path: &str,
        veil_front_ticket_b64: &str,
        veil_front_auth_v3: &VeilFrontAuthV3,
    ) -> Result<(), CoordinatorError> {
        let num_probes = methods.len();
        if num_probes == 0 {
            // The reducer never emits an empty StartProbes; guard the channel
            // capacity anyway — `mpsc::channel(0)` panics.
            return Err(CoordinatorError::NoMethods);
        }
        let (tx, mut rx) = mpsc::channel::<ProbeResult>(num_probes);
        let mut cancel_tokens: HashMap<MethodId, CancellationToken> = HashMap::new();

        // Launch probes with staggered delay.
        for (i, &method) in methods.iter().enumerate() {
            let stagger =
                Duration::from_millis(i as u64 * self.config.inter_probe_delay.as_millis() as u64);

            let tx_clone = tx.clone();
            let relay_str = relay.to_owned();
            let bundle_str = bundle.to_owned();
            let tls_sni_str = tls_sni.to_owned();
            let spki_hex_str = spki_hex.to_owned();
            let host_header_str = host_header.to_owned();
            let wt_base_path_str = wt_base_path.to_owned();
            let veil_front_ticket_b64_str = veil_front_ticket_b64.to_owned();
            let veil_front_auth_v3_owned = veil_front_auth_v3.clone();
            let probe_timeout = self.config.probe_timeout;
            let obfuscator = self.obfuscators.get(&method);
            let has_obfuscator = obfuscator.is_some();

            if !has_obfuscator {
                // No obfuscator registered for this method — immediately fail.
                crate::veil::diag::record(format!(
                    "{}: no obfuscator registered in this build",
                    method.name()
                ));
                tokio::spawn(async move {
                    let _ = tx_clone
                        .send(ProbeResult {
                            method,
                            outcome: ProbeOutcome::Failure {
                                reason: ProbeFailureReason::Unknown,
                                latency_ms: 0,
                            },
                        })
                        .await;
                });
                continue;
            }

            let cancel = CancellationToken::new();
            cancel_tokens.insert(method, cancel.clone());

            let obf = self.obfuscators.get(&method).unwrap().clone();

            let _handle = tokio::spawn(async move {
                // Stagger probe start.
                if !stagger.is_zero() {
                    tokio::time::sleep(stagger).await;
                }

                // Check if we've already been cancelled (another probe won).
                if cancel.is_cancelled() {
                    return;
                }

                let probe_start = Instant::now();
                let req = ProbeRequest {
                    relay_addr: relay_str,
                    bundle: bundle_str,
                    tls_sni: tls_sni_str,
                    spki_hex: spki_hex_str,
                    host_header: host_header_str,
                    wt_base_path: wt_base_path_str,
                    veil_front_ticket_b64: veil_front_ticket_b64_str,
                    auth_v3: veil_front_auth_v3_owned,
                };

                let handle = match obf.start(&req, cancel.clone()).await {
                    Ok(h) => h,
                    Err(e) => {
                        let latency_ms = probe_start.elapsed().as_millis() as u32;
                        crate::veil::diag::record(format!(
                            "{}: start error: {e:?} ({latency_ms}ms)",
                            method.name()
                        ));
                        let _ = tx_clone
                            .send(ProbeResult {
                                method,
                                outcome: ProbeOutcome::Failure {
                                    reason: classify_obfuscator_error(&e),
                                    latency_ms,
                                },
                            })
                            .await;
                        return;
                    }
                };

                // Wait for first byte (with timeout).
                let result = tokio::time::timeout(probe_timeout, handle.first_byte).await;

                let latency_ms = probe_start.elapsed().as_millis() as u32;
                let outcome = match result {
                    Ok(Ok(())) => ProbeOutcome::Success {
                        port: 0,
                        latency_ms,
                    },
                    Ok(Err(e)) => {
                        crate::veil::diag::record(format!(
                            "{}: probe error: {e:?} ({latency_ms}ms)",
                            method.name()
                        ));
                        ProbeOutcome::Failure {
                            reason: classify_obfuscator_error(&e),
                            latency_ms,
                        }
                    }
                    Err(_) => {
                        cancel.cancel();
                        crate::veil::diag::record(format!(
                            "{}: timeout after {latency_ms}ms (no first byte)",
                            method.name()
                        ));
                        ProbeOutcome::Failure {
                            reason: ProbeFailureReason::Timeout,
                            latency_ms,
                        }
                    }
                };

                let _ = tx_clone.send(ProbeResult { method, outcome }).await;
            });
        }

        // Drop the original sender so rx closes when all tasks finish.
        drop(tx);

        // Collect results: first success wins, track failures.
        let mut failures: Vec<(MethodId, ProbeFailureReason, u32)> = Vec::new();
        let mut winner: Option<(MethodId, u32)> = None;

        while let Some(probe_result) = rx.recv().await {
            match probe_result.outcome {
                ProbeOutcome::Success { latency_ms, .. } => {
                    winner = Some((probe_result.method, latency_ms));
                    info!(
                        target: "ice::fsm",
                        "probe succeeded  method={} latency_ms={}",
                        probe_result.method.name(),
                        latency_ms,
                    );
                    break; // Winner found — stop waiting.
                }
                ProbeOutcome::Failure { reason, latency_ms } => {
                    info!(
                        target: "ice::fsm",
                        "probe failed  method={} reason={:?} latency_ms={}",
                        probe_result.method.name(),
                        reason,
                        latency_ms,
                    );
                    failures.push((probe_result.method, reason, latency_ms));
                }
            }
        }

        // Cancel all remaining probes.
        for cancel in cancel_tokens.values() {
            cancel.cancel();
        }

        if let Some((winning_method, latency_ms)) = winner {
            // Bind local listener for the proxy.
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(CoordinatorError::Io)?;
            let port = listener.local_addr().map_err(CoordinatorError::Io)?.port();

            // Feed ProbeSucceeded into FSM.
            let now = Instant::now();
            let now_sys = SystemTime::now();
            let (new_state, effects) = reduce(
                state.clone(),
                VeilEvent::ProbeSucceeded {
                    method: winning_method,
                    port,
                    latency_ms,
                },
                scores_cache,
                &self.config,
                now,
                now_sys,
            );
            *state = new_state;

            // Execute effects (RecordScore). A store that cannot be written is
            // logged, not returned: the probe has already won.
            for sub_effect in &effects {
                if let VeilEffect::RecordScore {
                    method: sm,
                    outcome,
                    ..
                } = sub_effect
                {
                    self.record_score(fingerprint, *sm, *outcome).await;
                }
            }

            // Record failures for other probes.
            for (failed_method, reason, _latency_ms) in &failures {
                let _ = self
                    .scores
                    .record(
                        fingerprint,
                        *failed_method,
                        crate::veil::fsm::ScoreOutcome::Failure { reason: *reason },
                    )
                    .await;
            }

            let proxy_params = ProxyParams {
                method: winning_method,
                relay_addr: relay.to_owned(),
                bundle: bundle.to_owned(),
                tls_sni: tls_sni.to_owned(),
                spki_hex: spki_hex.to_owned(),
                veil_front_ticket_b64: veil_front_ticket_b64.to_owned(),
                veil_front_auth_v3: veil_front_auth_v3.clone(),
            };
            self.install_session(listener, port, proxy_params).await;

            return Ok(());
        }

        // All probes failed: feed each failure through the FSM and score it from
        // the reducer's effects — the same path the sequential probes take.
        for (method, reason, latency_ms) in &failures {
            self.handle_probe_failure(
                *method,
                *reason,
                *latency_ms,
                fingerprint,
                state,
                scores_cache,
            )
            .await;
        }

        self.handle_all_probes_failed(state, scores_cache);
        Ok(())
    }

    /// Handle a successful probe: transition FSM, record score, start proxy.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn handle_probe_success(
        &self,
        method: MethodId,
        latency_ms: u32,
        fingerprint: &NetworkFingerprint,
        relay: &str,
        bundle: &str,
        tls_sni: &str,
        spki_hex: &str,
        veil_front_ticket_b64: &str,
        veil_front_auth_v3: &VeilFrontAuthV3,
        state: &mut VeilState,
        scores_cache: &CachedScoreLookup,
    ) -> Result<(), CoordinatorError> {
        // Bind a local listener for the proxy.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(CoordinatorError::Io)?;
        let port = listener.local_addr().map_err(CoordinatorError::Io)?.port();

        info!(
            target: "ice::fsm",
            "probe succeeded  method={} latency_ms={}",
            method.name(),
            latency_ms,
        );

        // Feed ProbeSucceeded back into FSM.
        let now = Instant::now();
        let now_sys = SystemTime::now();
        let (new_state, effects) = reduce(
            state.clone(),
            VeilEvent::ProbeSucceeded {
                method,
                port,
                latency_ms,
            },
            scores_cache,
            &self.config,
            now,
            now_sys,
        );
        *state = new_state;

        // Execute the new effects. A store that cannot be written is logged, not
        // returned: the probe has already won.
        for sub_effect in &effects {
            if let VeilEffect::RecordScore {
                method: sm,
                outcome,
                ..
            } = sub_effect
            {
                self.record_score(fingerprint, *sm, *outcome).await;
            }
        }

        let proxy_params = ProxyParams {
            method,
            relay_addr: relay.to_owned(),
            bundle: bundle.to_owned(),
            tls_sni: tls_sni.to_owned(),
            spki_hex: spki_hex.to_owned(),
            veil_front_ticket_b64: veil_front_ticket_b64.to_owned(),
            veil_front_auth_v3: veil_front_auth_v3.clone(),
        };
        self.install_session(listener, port, proxy_params).await;

        Ok(())
    }

    /// Make `listener` the active session's proxy and start serving it.
    ///
    /// A session still in the slot is shut down first, tunnels included. The
    /// proxy task clears the slot when it ends only if the slot still holds this
    /// session: until 2026-10-22 it cleared unconditionally, so an old session
    /// that exited after a new one was installed wiped the new one — `is_alive`
    /// said no, `port` said 0, and `stop` could not reach the live listener.
    async fn install_session(&self, listener: TcpListener, port: u16, params: ProxyParams) {
        use std::sync::atomic::Ordering;

        // shutdown_tx must live in ActiveSession — dropping it would resolve the
        // loop's shutdown_rx at once, drop the listener, and leave the gRPC client
        // with an unreachable 127.0.0.1:port (ECONNREFUSED).
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let tunnels = CancellationToken::new();
        let id = self.next_session_id.fetch_add(1, Ordering::Relaxed) + 1;
        {
            let mut guard = self.active.lock().await;
            if let Some(old) = guard.take() {
                old.shut_down();
            }
            *guard = Some(ActiveSession {
                id,
                port,
                method: params.method,
                shutdown_tx,
                tunnels: tunnels.clone(),
            });
        }

        let active = self.active.clone();
        tokio::spawn(async move {
            run_proxy_loop(listener, shutdown_rx, tunnels, move |local| {
                handle_proxy_connection(local, params.clone())
            })
            .await;
            let mut guard = active.lock().await;
            if guard.as_ref().is_some_and(|s| s.id == id) {
                *guard = None;
            }
        });
    }

    /// Handle a failed probe: transition FSM, record score.
    async fn handle_probe_failure(
        &self,
        method: MethodId,
        reason: ProbeFailureReason,
        latency_ms: u32,
        fingerprint: &NetworkFingerprint,
        state: &mut VeilState,
        scores_cache: &CachedScoreLookup,
    ) {
        info!(
            target: "ice::fsm",
            "probe failed  method={} reason={:?} latency_ms={}",
            method.name(),
            reason,
            latency_ms,
        );

        // Feed ProbeFailed back into FSM.
        let now = Instant::now();
        let now_sys = SystemTime::now();
        let (new_state, effects) = reduce(
            state.clone(),
            VeilEvent::ProbeFailed { method, reason },
            scores_cache,
            &self.config,
            now,
            now_sys,
        );
        *state = new_state;

        // Record score.
        for sub_effect in &effects {
            if let VeilEffect::RecordScore {
                method: sm,
                outcome,
                ..
            } = sub_effect
            {
                self.record_score(fingerprint, *sm, *outcome).await;
            }
        }
    }

    /// Write one outcome to the store; a failure is logged and otherwise
    /// ignored, because scores never gate connectivity.
    async fn record_score(
        &self,
        fingerprint: &NetworkFingerprint,
        method: MethodId,
        outcome: crate::veil::fsm::ScoreOutcome,
    ) {
        if let Err(e) = self.scores.record(fingerprint, method, outcome).await {
            warn!(
                target: "ice::coordinator",
                "score not recorded  method={} outcome={:?}: {e}",
                method.name(),
                outcome,
            );
        }
    }

    /// The scores store, for tests that read back what a session recorded.
    #[cfg(test)]
    pub(crate) fn scores(&self) -> &PersistentScores {
        &self.scores
    }

    /// Handle all probes failed: transition to Cooldown.
    fn handle_all_probes_failed(&self, state: &mut VeilState, scores_cache: &CachedScoreLookup) {
        if matches!(state, VeilState::Probing { .. }) {
            let now = Instant::now();
            let now_sys = SystemTime::now();
            let (new_state, effects) = reduce(
                state.clone(),
                VeilEvent::AllProbesFailed,
                scores_cache,
                &self.config,
                now,
                now_sys,
            );
            *state = new_state;
            for effect in &effects {
                if let VeilEffect::ScheduleCooldown { duration } = effect {
                    info!(
                        target: "ice::fsm",
                        "cooldown  duration={:?}s reason=all_probes_failed",
                        duration.as_secs(),
                    );
                }
            }
        }
    }

    /// Execute a single probe with full TLS/WebTunnel parameters.
    #[allow(clippy::too_many_arguments)]
    async fn execute_probe_with_params(
        &self,
        method: MethodId,
        relay: &str,
        bundle: &str,
        tls_sni: &str,
        spki_hex: &str,
        host_header: &str,
        wt_base_path: &str,
        veil_front_ticket_b64: &str,
        veil_front_auth_v3: &VeilFrontAuthV3,
    ) -> Result<(), ProbeFailureReason> {
        let obfuscator = match self.obfuscators.get(&method) {
            Some(o) => o.clone(),
            None => return Err(ProbeFailureReason::Unknown),
        };

        let req = ProbeRequest {
            relay_addr: relay.to_owned(),
            bundle: bundle.to_owned(),
            tls_sni: tls_sni.to_owned(),
            spki_hex: spki_hex.to_owned(),
            host_header: host_header.to_owned(),
            wt_base_path: wt_base_path.to_owned(),
            veil_front_ticket_b64: veil_front_ticket_b64.to_owned(),
            auth_v3: veil_front_auth_v3.clone(),
        };
        let cancel = CancellationToken::new();

        let handle = match obfuscator.start(&req, cancel.clone()).await {
            Ok(h) => h,
            Err(e) => return Err(classify_obfuscator_error(&e)),
        };

        let result = tokio::time::timeout(self.config.probe_timeout, handle.first_byte).await;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(classify_obfuscator_error(&e)),
            Err(_) => {
                cancel.cancel();
                Err(ProbeFailureReason::Timeout)
            }
        }
    }

    /// Stop the active session.
    /// Stop the active session: its listener and every tunnel it accepted.
    pub async fn stop(&self) -> bool {
        let mut guard = self.active.lock().await;
        if let Some(session) = guard.take() {
            session.shut_down();
            true
        } else {
            false
        }
    }

    /// Check if a session is currently active.
    pub async fn is_alive(&self) -> bool {
        let guard = self.active.lock().await;
        guard.is_some()
    }

    /// Get the active session port.
    pub async fn port(&self) -> u16 {
        let guard = self.active.lock().await;
        guard.as_ref().map(|s| s.port).unwrap_or(0)
    }

    /// Report a transport failure for the active session.
    pub async fn report_failure(&self, kind: TransportFailureKind) {
        // This is handled by the caller re-starting with appropriate parameters.
        // For now, just log.
        info!(
            target: "ice::coordinator",
            "transport_failure  kind={:?}",
            kind,
        );
    }
}

/// Parameters needed to run the data-plane proxy for the winning method.
#[derive(Clone)]
struct ProxyParams {
    /// Winning obfuscation method — selects the data-plane path.
    method: MethodId,
    /// Relay address (`host:port`).
    relay_addr: String,
    /// obfs4 bridge / cert bundle. Empty for non-obfs4 methods.
    bundle: String,
    /// TLS SNI (TLS-wrapped methods). Read only by the veil-front (utls) path.
    #[cfg_attr(not(feature = "utls"), allow(dead_code))]
    tls_sni: String,
    /// SPKI hex pin (TLS-wrapped methods). Read only by the veil-front (utls) path.
    #[cfg_attr(not(feature = "utls"), allow(dead_code))]
    spki_hex: String,
    /// Base64-encoded veil-front ticket (AUTH v2). Empty for non-veil-front methods.
    #[cfg_attr(not(feature = "utls"), allow(dead_code))]
    veil_front_ticket_b64: String,
    /// AUTH v3 (key-bound capability) params. Read only by the veil-front path.
    #[cfg_attr(not(feature = "utls"), allow(dead_code))]
    veil_front_auth_v3: VeilFrontAuthV3,
}

/// Run the proxy loop: accept local connections and hand each to `serve`.
///
/// Every connection runs under `tunnels`: cancelling it ends them all, and the
/// loop cancels it itself when it stops accepting. Until 2026-10-22 `stop()`
/// only ended this accept loop; tunnels already accepted kept flowing through
/// the old relay (with its capability and chaff) until a peer closed them — after
/// "switch front" or "turn VEIL off".
async fn run_proxy_loop<F, Fut>(
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
    tunnels: CancellationToken,
    serve: F,
) where
    F: Fn(TcpStream) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => match result {
                Ok((local, _)) => {
                    let tunnel = serve(local);
                    let cancelled = tunnels.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = cancelled.cancelled() => {}
                            _ = tunnel => {}
                        }
                    });
                }
                Err(e) => match crate::accept::accept_retry_delay(&e) {
                    Some(delay) => {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                    }
                    None => break,
                },
            },
        }
    }
    tunnels.cancel();
}

/// Handle a single proxy connection by dispatching to the winning method's
/// data plane: local → <method> → relay.
async fn handle_proxy_connection(local: TcpStream, params: ProxyParams) {
    match params.method {
        #[cfg(feature = "utls")]
        MethodId::VeilFront => {
            // veil-front: framed h2c ferry over the authenticated TLS tunnel.
            if let Err(e) = crate::veil::veil_front_adapter::run_veil_front_ferry(
                local,
                &params.relay_addr,
                &params.tls_sni,
                &params.spki_hex,
                &params.veil_front_ticket_b64,
                &params.veil_front_auth_v3,
            )
            .await
            {
                eprintln!("ice: coordinator: veil-front ferry failed: {e}");
            }
        }
        // obfs4 (and any non-veil-front method) — obfs4 data plane.
        _ => forward_obfs4(local, params).await,
    }
}

/// obfs4 data plane: local → obfs4 handshake → relay.
async fn forward_obfs4(mut local: TcpStream, params: ProxyParams) {
    let config = match crate::ClientConfig::from_bridge_line(&params.bundle) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ice: coordinator: invalid bundle: {e}");
            return;
        }
    };

    let connect = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(&params.relay_addr),
    )
    .await
    .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
    match connect {
        Ok(tcp) => {
            let _ = tcp.set_nodelay(true);
            match crate::Obfs4Stream::client_handshake_stream(tcp, config).await {
                Ok(mut remote) => {
                    let _ = copy_bidirectional(&mut local, &mut remote).await;
                }
                Err(e) => {
                    eprintln!("ice: coordinator: obfs4 handshake failed: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("ice: coordinator: relay connect failed: {e}");
        }
    }
}

/// Classify an ObfuscatorError into a ProbeFailureReason.
fn classify_obfuscator_error(e: &ObfuscatorError) -> ProbeFailureReason {
    match e {
        ObfuscatorError::FingerprintBlocked => ProbeFailureReason::FingerprintBlocked,
        ObfuscatorError::WebTunnelDecoyResponse => ProbeFailureReason::WebTunnelDecoyResponse,
        ObfuscatorError::CertProblem(_) => ProbeFailureReason::TlsCertProblem,
        ObfuscatorError::Timeout => ProbeFailureReason::Timeout,
        ObfuscatorError::Cancelled => ProbeFailureReason::ConnectionFailed,
        ObfuscatorError::ConnectionRefused => ProbeFailureReason::ConnectionFailed,
        ObfuscatorError::Handshake(_) => ProbeFailureReason::ConnectionFailed,
        // A TLS error that is neither alert 40 nor a certificate verdict (reset,
        // EOF, another alert): a failed connection, not a DPI verdict — which the
        // scorer would turn into a week-long block after five of them.
        ObfuscatorError::Tls(_) => ProbeFailureReason::ConnectionFailed,
        ObfuscatorError::Io(_) => ProbeFailureReason::ConnectionFailed,
        ObfuscatorError::Unknown(_) => ProbeFailureReason::Unknown,
    }
}

/// Errors from the coordinator.
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("scoring error: {0}")]
    Scoring(String),

    #[error("session was stopped")]
    Stopped,

    #[error("all probes failed")]
    AllProbesFailed,

    #[error("no obfuscation method is both allowed and registered")]
    NoMethods,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::veil::obfuscator::ObfuscatorHandle;

    /// An obfuscator whose probe resolves at once with a fixed outcome.
    struct Fake {
        method: MethodId,
        ok: bool,
    }

    #[async_trait::async_trait]
    impl Obfuscator for Fake {
        fn method_id(&self) -> MethodId {
            self.method
        }
        async fn start(
            &self,
            _req: &ProbeRequest,
            _cancel: CancellationToken,
        ) -> Result<ObfuscatorHandle, ObfuscatorError> {
            let ok = self.ok;
            Ok(ObfuscatorHandle::new(
                async move {
                    if ok {
                        Ok(())
                    } else {
                        Err(ObfuscatorError::ConnectionRefused)
                    }
                },
                async {},
            ))
        }
    }

    async fn coordinator(config: VeilConfig) -> VeilCoordinator {
        VeilCoordinator::new(
            config,
            PersistentScores::open(":memory:", 50).await.unwrap(),
        )
    }

    fn fingerprint() -> NetworkFingerprint {
        NetworkFingerprint::new(vec![3; 32])
    }

    async fn start(coord: &VeilCoordinator) -> Result<CoordinatorStartResult, CoordinatorError> {
        coord
            .start_session(
                "relay:443".into(),
                String::new(),
                fingerprint(),
                MethodSet::all(),
            )
            .await
    }

    /// No registered method: an error, not `mpsc::channel(0)`. Mutation: remove
    /// the `NoMethods` returns — the parallel path panics.
    #[tokio::test]
    async fn no_registered_method_is_an_error_not_a_panic() {
        let coord = coordinator(VeilConfig::default()).await;
        assert!(matches!(
            start(&coord).await,
            Err(CoordinatorError::NoMethods)
        ));
    }

    /// One candidate (the shipping veil-front-only build), one failure: it is
    /// recorded. Mutation: the reducer's all-failed branch without `RecordScore`.
    #[tokio::test]
    async fn a_single_failing_probe_is_scored() {
        let mut coord = coordinator(VeilConfig::legacy()).await;
        coord.register(Box::new(Fake {
            method: MethodId::VeilFront,
            ok: false,
        }));
        assert!(matches!(
            start(&coord).await,
            Err(CoordinatorError::AllProbesFailed)
        ));
        let entry = coord
            .scores()
            .get_score(&fingerprint(), MethodId::VeilFront)
            .await
            .unwrap()
            .expect("the failure was not recorded");
        assert_eq!((entry.failures, entry.consecutive_failures), (1, 1));
    }

    /// The parallel path scores the losers the same way. Mutation: skip the
    /// `handle_probe_failure` loop after the race.
    #[tokio::test]
    async fn parallel_failures_are_scored() {
        let mut coord = coordinator(VeilConfig {
            inter_probe_delay: Duration::from_millis(1),
            ..VeilConfig::default()
        })
        .await;
        for method in [MethodId::VeilFront, MethodId::Obfs4] {
            coord.register(Box::new(Fake { method, ok: false }));
        }
        assert!(matches!(
            start(&coord).await,
            Err(CoordinatorError::AllProbesFailed)
        ));
        for method in [MethodId::VeilFront, MethodId::Obfs4] {
            let entry = coord
                .scores()
                .get_score(&fingerprint(), method)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{} failure not recorded", method.name()));
            assert_eq!(entry.failures, 1, "{}", method.name());
        }
    }

    /// A store that cannot be read or written does not stop a reachable front
    /// from being used. Mutation: restore the `?` on `CachedScoreLookup::build`.
    #[tokio::test]
    async fn an_unusable_scores_store_does_not_block_the_session() {
        let mut coord = coordinator(VeilConfig::legacy()).await;
        coord.register(Box::new(Fake {
            method: MethodId::VeilFront,
            ok: true,
        }));
        coord.scores().close().await;

        let started = start(&coord)
            .await
            .expect("session must start without the scores store");
        assert_ne!(started.port, 0);
        assert_eq!(started.method, MethodId::VeilFront);
        assert!(coord.stop().await);
    }

    /// A second session replacing the first stays alive after the first one's
    /// proxy task exits. Mutation: clear the slot unconditionally on exit.
    #[tokio::test]
    async fn a_replaced_session_does_not_wipe_its_successor() {
        let mut coord = coordinator(VeilConfig::legacy()).await;
        coord.register(Box::new(Fake {
            method: MethodId::VeilFront,
            ok: true,
        }));
        let first = start(&coord).await.unwrap();
        let second = start(&coord).await.unwrap();
        assert_ne!(first.port, second.port);
        // Let the first session's proxy task observe its shutdown and exit.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(coord.is_alive().await, "the live session was wiped");
        assert_eq!(coord.port().await, second.port);
        assert!(coord.stop().await);
    }

    /// Stopping the session ends tunnels it already accepted, not only the
    /// listener. Mutation: `shut_down` without `tunnels.cancel()` (or a loop that
    /// spawns `serve` without the select) — the client never sees EOF.
    #[tokio::test]
    async fn stopping_ends_tunnels_already_accepted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let tunnels = CancellationToken::new();
        let session = ActiveSession {
            id: 1,
            port: addr.port(),
            method: MethodId::VeilFront,
            shutdown_tx,
            tunnels: tunnels.clone(),
        };
        // A tunnel that would live forever: it holds the socket and waits.
        let proxy = tokio::spawn(run_proxy_loop(
            listener,
            shutdown_rx,
            tunnels,
            |local| async move {
                let _keep = local;
                std::future::pending::<()>().await;
            },
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"x").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await; // accepted, tunnel running

        session.shut_down();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("tunnel outlived stop()")
            .unwrap_or(0);
        assert_eq!(n, 0, "expected EOF once the session stopped");
        tokio::time::timeout(Duration::from_secs(2), proxy)
            .await
            .expect("proxy loop did not end")
            .unwrap();
    }

    /// Mutation: map `Tls(_)` back to `FingerprintBlocked`.
    #[test]
    fn a_generic_tls_error_is_not_a_dpi_verdict() {
        assert_eq!(
            classify_obfuscator_error(&ObfuscatorError::Tls("reset".into())),
            ProbeFailureReason::ConnectionFailed
        );
        assert_eq!(
            classify_obfuscator_error(&ObfuscatorError::FingerprintBlocked),
            ProbeFailureReason::FingerprintBlocked
        );
        assert_eq!(
            classify_obfuscator_error(&ObfuscatorError::CertProblem("pin".into())),
            ProbeFailureReason::TlsCertProblem
        );
    }
}
