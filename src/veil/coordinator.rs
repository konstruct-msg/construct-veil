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
use tracing::info;

use crate::veil::fsm::{
    MethodId, MethodSet, NetworkFingerprint, ProbeFailureReason, TransportFailureKind, VeilConfig,
    VeilEffect, VeilEvent, VeilState, reduce,
};
use crate::veil::obfuscator::{Obfuscator, ObfuscatorError, ProbeRequest};
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
    port: u16,
    #[allow(dead_code)]
    method: MethodId,
    shutdown_tx: oneshot::Sender<()>,
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
}

impl VeilCoordinator {
    /// Create a new coordinator with the given config and scores store.
    pub fn new(config: VeilConfig, scores: PersistentScores) -> Self {
        Self {
            config,
            scores: Arc::new(scores),
            obfuscators: HashMap::new(),
            active: Arc::new(Mutex::new(None)),
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
    ) -> Result<CoordinatorStartResult, CoordinatorError> {
        let start_time = Instant::now();
        let mut state = VeilState::Idle;

        info!(
            target: "ice::coordinator",
            "session started  fingerprint={} methods={:?}",
            fingerprint.short_hex(),
            allowed_methods.iter_allowed().collect::<Vec<_>>(),
        );

        loop {
            // Build cached score lookup for this iteration.
            let scores_cache = CachedScoreLookup::build(&self.scores, &fingerprint)
                .await
                .map_err(|e| CoordinatorError::Scoring(e.to_string()))?;

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
    /// Delegates to [`start_session_with_params`] with empty TLS/WebTunnel params.
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
                    let _ = session.shutdown_tx.send(());
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
    ) -> Result<(), CoordinatorError> {
        let num_probes = methods.len();
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
            let probe_timeout = self.config.probe_timeout;
            let obfuscator = self.obfuscators.get(&method);
            let has_obfuscator = obfuscator.is_some();

            if !has_obfuscator {
                // No obfuscator registered for this method — immediately fail.
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
                };

                let handle = match obf.start(&req, cancel.clone()).await {
                    Ok(h) => h,
                    Err(e) => {
                        let latency_ms = probe_start.elapsed().as_millis() as u32;
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
                    Ok(Err(e)) => ProbeOutcome::Failure {
                        reason: classify_obfuscator_error(&e),
                        latency_ms,
                    },
                    Err(_) => {
                        cancel.cancel();
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

            // Execute effects (RecordScore).
            for sub_effect in &effects {
                if let VeilEffect::RecordScore {
                    method: sm,
                    outcome,
                    ..
                } = sub_effect
                {
                    self.scores
                        .record(fingerprint, *sm, *outcome)
                        .await
                        .map_err(|e| CoordinatorError::Scoring(e.to_string()))?;
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

            // Start proxy loop. shutdown_tx must be stored in ActiveSession —
            // dropping it here would cancel run_proxy_loop's shutdown_rx.await
            // immediately, exit the accept loop, drop the listener, and leave
            // the iOS gRPC client with an unreachable 127.0.0.1:port (ECONNREFUSED).
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let active = self.active.clone();
            let proxy_method = winning_method;
            let relay_addr = relay.to_owned();
            let bundle_str = bundle.to_owned();

            {
                let mut guard = self.active.lock().await;
                *guard = Some(ActiveSession {
                    port,
                    method: proxy_method,
                    shutdown_tx,
                });
            }

            tokio::spawn(async move {
                run_proxy_loop(listener, relay_addr, bundle_str, shutdown_rx, proxy_method).await;
                let mut guard = active.lock().await;
                *guard = None;
            });

            return Ok(());
        }

        // All probes failed.
        for (method, reason, _latency_ms) in &failures {
            let _ = self
                .scores
                .record(
                    fingerprint,
                    *method,
                    crate::veil::fsm::ScoreOutcome::Failure { reason: *reason },
                )
                .await;

            // Feed individual ProbeFailed events into FSM.
            let now = Instant::now();
            let now_sys = SystemTime::now();
            let (new_state, _effects) = reduce(
                state.clone(),
                VeilEvent::ProbeFailed {
                    method: *method,
                    reason: *reason,
                },
                scores_cache,
                &self.config,
                now,
                now_sys,
            );
            *state = new_state;
        }

        self.handle_all_probes_failed(state, scores_cache);
        Ok(())
    }

    /// Handle a successful probe: transition FSM, record score, start proxy.
    async fn handle_probe_success(
        &self,
        method: MethodId,
        latency_ms: u32,
        fingerprint: &NetworkFingerprint,
        relay: &str,
        bundle: &str,
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

        // Execute the new effects.
        for sub_effect in &effects {
            match sub_effect {
                VeilEffect::RecordScore {
                    method: sm,
                    outcome,
                    ..
                } => {
                    self.scores
                        .record(fingerprint, *sm, *outcome)
                        .await
                        .map_err(|e| CoordinatorError::Scoring(e.to_string()))?;
                }
                _ => {}
            }
        }

        // Start the proxy loop. shutdown_tx must outlive this scope — see the
        // parallel-probe path for the failure mode if it doesn't.
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let active = self.active.clone();
        let proxy_method = method;
        let relay_addr = relay.to_owned();
        let bundle_str = bundle.to_owned();

        {
            let mut guard = self.active.lock().await;
            *guard = Some(ActiveSession {
                port,
                method: proxy_method,
                shutdown_tx,
            });
        }

        tokio::spawn(async move {
            run_proxy_loop(listener, relay_addr, bundle_str, shutdown_rx, proxy_method).await;
            let mut guard = active.lock().await;
            *guard = None;
        });

        Ok(())
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
                let _ = self.scores.record(fingerprint, *sm, *outcome).await;
            }
        }
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
    async fn execute_probe_with_params(
        &self,
        method: MethodId,
        relay: &str,
        bundle: &str,
        tls_sni: &str,
        spki_hex: &str,
        host_header: &str,
        wt_base_path: &str,
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
    pub async fn stop(&self) -> bool {
        let mut guard = self.active.lock().await;
        if let Some(session) = guard.take() {
            let _ = session.shutdown_tx.send(());
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

/// Run the proxy loop: accept local connections and forward through obfs4.
async fn run_proxy_loop(
    listener: TcpListener,
    relay_addr: String,
    bundle: String,
    mut shutdown_rx: oneshot::Receiver<()>,
    _method: MethodId,
) {
    let config = match crate::ClientConfig::from_bridge_line(&bundle) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ice: coordinator: invalid bundle: {e}");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => {
                match result {
                    Ok((local, _)) => {
                        let addr = relay_addr.clone();
                        let cfg = config.clone();
                        tokio::spawn(handle_proxy_connection(local, addr, cfg));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

/// Handle a single proxy connection: local → obfs4 → relay.
async fn handle_proxy_connection(
    mut local: TcpStream,
    relay_addr: String,
    config: crate::ClientConfig,
) {
    match TcpStream::connect(&relay_addr).await {
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
        ObfuscatorError::Tls(_) => ProbeFailureReason::FingerprintBlocked,
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
}
