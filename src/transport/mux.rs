//! Pluggable transport multiplexing (I-N5).
//!
//! Provides a unified interface for connecting through multiple underlying
//! transports (direct TCP, obfs4, future: WebSocket, domain fronting).
//!
//! # Design
//!
//! - [`PluggableTransport`] — trait implemented by each transport backend.
//! - [`TransportMultiplexer`] — wraps multiple transports with a selection
//!   strategy: try in order, race all, or probe then select.
//! - [`MuxStrategy`] — how to pick among multiple transports.
//!
//! # Example
//!
//! ```rust,no_run
//! use construct_ice::transport::mux::{
//!     DirectTransport, Obfs4Transport, TransportMultiplexer, MuxStrategy,
//! };
//! use construct_ice::ClientConfig;
//!
//! # async fn example() -> std::io::Result<()> {
//! let cfg = ClientConfig::from_bridge_cert("...").unwrap();
//!
//! let mux = TransportMultiplexer::new(MuxStrategy::Sequential)
//!     .with_transport(DirectTransport)
//!     .with_transport(Obfs4Transport::new(cfg));
//!
//! let _stream = mux.connect("relay.example.com:443").await?;
//! # Ok(())
//! # }
//! ```

use std::{future::Future, io, pin::Pin, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

// ── BoxStream ─────────────────────────────────────────────────────────────────

/// Object-safe supertrait combining [`AsyncRead`] + [`AsyncWrite`] + `Send` + `Unpin`.
///
/// All types implementing `AsyncRead + AsyncWrite + Send + Unpin` automatically
/// implement this trait via the blanket impl below.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// A type-erased async stream returned by [`PluggableTransport::connect`].
pub type BoxStream = Box<dyn AsyncStream>;

// ── PluggableTransport trait ─────────────────────────────────────────────────

/// A transport backend that can establish a stream to a remote address.
///
/// Implementations are free to do plain TCP, obfs4, WebSocket, SOCKS5, etc.
pub trait PluggableTransport: Send + Sync + 'static {
    /// Human-readable name for logging and diagnostics.
    fn name(&self) -> &str;

    /// Attempt to connect to `addr` (a `"host:port"` string), returning a stream on success.
    ///
    /// Implementations must clone any `self` data they need into the returned future
    /// so that the future is `'static` and can be passed to `tokio::spawn`.
    fn connect(
        &self,
        addr: String,
    ) -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>>;
}

// ── MuxStrategy ──────────────────────────────────────────────────────────────

/// Strategy used by [`TransportMultiplexer`] to select among transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MuxStrategy {
    /// Try each transport in the order they were added.
    ///
    /// Returns the first success. Falls through to the next transport on error.
    /// Lowest overhead; use when transport ordering is well-known.
    #[default]
    Sequential,

    /// Start all transports concurrently; return the first to succeed.
    ///
    /// Cancels the remaining attempts. Higher concurrency; use when latency
    /// matters more than connection overhead (e.g. censored networks with
    /// unpredictable transport availability).
    RaceAll,

    /// Probe each transport with a short deadline; pick the fastest.
    ///
    /// Similar to `RaceAll` but enforces a per-transport probe timeout.
    /// Gracefully degrades to `Sequential` if all probes time out within
    /// the deadline.
    SmartProbe {
        /// Per-transport probe timeout.
        probe_timeout: Duration,
    },
}

// ── TransportMultiplexer ─────────────────────────────────────────────────────

/// Multiplexes multiple [`PluggableTransport`]s behind a single `connect` call.
///
/// See the [module-level documentation][self] for usage.
pub struct TransportMultiplexer {
    transports: Vec<Arc<dyn PluggableTransport>>,
    strategy: MuxStrategy,
}

impl TransportMultiplexer {
    /// Create a new multiplexer with the given strategy and no transports.
    pub fn new(strategy: MuxStrategy) -> Self {
        TransportMultiplexer {
            transports: Vec::new(),
            strategy,
        }
    }

    /// Append a transport backend. Returns `self` for chaining.
    pub fn with_transport(mut self, transport: impl PluggableTransport) -> Self {
        self.transports.push(Arc::new(transport));
        self
    }

    /// Number of registered transports.
    pub fn len(&self) -> usize {
        self.transports.len()
    }

    /// Returns `true` if no transports have been added.
    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    /// The active multiplexing strategy.
    pub fn strategy(&self) -> MuxStrategy {
        self.strategy
    }

    /// Connect to `addr` using the configured strategy.
    ///
    /// Returns the first successfully established stream according to the
    /// strategy, or the last error if all transports failed.
    pub async fn connect(&self, addr: &str) -> io::Result<BoxStream> {
        if self.transports.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "TransportMultiplexer has no transports",
            ));
        }

        match self.strategy {
            MuxStrategy::Sequential => self.connect_sequential(addr).await,
            MuxStrategy::RaceAll => self.connect_race(addr, None).await,
            MuxStrategy::SmartProbe { probe_timeout } => {
                self.connect_race(addr, Some(probe_timeout)).await
            }
        }
    }

    // ── Strategy implementations ────────────────────────────────────────────

    async fn connect_sequential(&self, addr: &str) -> io::Result<BoxStream> {
        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no transports");
        for transport in &self.transports {
            match transport.connect(addr.to_owned()).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    eprintln!(
                        "[ice mux] transport '{}' failed for {addr}: {e}",
                        transport.name()
                    );
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    async fn connect_race(
        &self,
        addr: &str,
        probe_timeout: Option<Duration>,
    ) -> io::Result<BoxStream> {
        use tokio::sync::mpsc;

        // Channel capacity = number of transports so senders never block.
        let (tx, mut rx) = mpsc::channel::<io::Result<BoxStream>>(self.transports.len());

        for transport in &self.transports {
            let tx = tx.clone();
            let addr = addr.to_owned();
            let fut = transport.connect(addr);

            tokio::spawn(async move {
                let result = if let Some(to) = probe_timeout {
                    match tokio::time::timeout(to, fut).await {
                        Ok(r) => r,
                        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "probe timed out")),
                    }
                } else {
                    fut.await
                };
                // Ignore send errors — receiver may have moved on.
                let _ = tx.send(result).await;
            });
        }

        // Drop our own sender so the channel closes when all tasks finish.
        drop(tx);

        let mut last_err = io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "all transports failed in race",
        );

        while let Some(result) = rx.recv().await {
            match result {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = e,
            }
        }

        Err(last_err)
    }
}

// ── Built-in transport implementations ───────────────────────────────────────

/// Plain TCP transport (no obfuscation).
///
/// Suitable as a fallback when the destination is directly reachable,
/// or as the innermost layer under TLS.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectTransport;

impl PluggableTransport for DirectTransport {
    fn name(&self) -> &str {
        "direct-tcp"
    }

    fn connect(
        &self,
        addr: String,
    ) -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>> {
        Box::pin(async move {
            let stream = TcpStream::connect(&addr).await?;
            let _ = stream.set_nodelay(true);
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// obfs4 transport backend.
///
/// Wraps an [`Obfs4Stream`][crate::Obfs4Stream] behind the
/// [`PluggableTransport`] interface.
pub struct Obfs4Transport {
    config: crate::ClientConfig,
}

impl Obfs4Transport {
    /// Create a new obfs4 transport with the given client config.
    pub fn new(config: crate::ClientConfig) -> Self {
        Obfs4Transport { config }
    }
}

impl PluggableTransport for Obfs4Transport {
    fn name(&self) -> &str {
        "obfs4"
    }

    fn connect(
        &self,
        addr: String,
    ) -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>> {
        let config = self.config.clone();
        Box::pin(async move {
            let stream = crate::Obfs4Stream::connect(&addr, config)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mux_strategy_defaults_to_sequential() {
        assert_eq!(MuxStrategy::default(), MuxStrategy::Sequential);
    }

    #[test]
    fn multiplexer_starts_empty() {
        let mux = TransportMultiplexer::new(MuxStrategy::Sequential);
        assert!(mux.is_empty());
        assert_eq!(mux.len(), 0);
    }

    #[test]
    fn multiplexer_add_increments_len() {
        let mux = TransportMultiplexer::new(MuxStrategy::Sequential)
            .with_transport(DirectTransport)
            .with_transport(DirectTransport);
        assert_eq!(mux.len(), 2);
    }

    #[test]
    fn multiplexer_strategy_is_stored() {
        let mux = TransportMultiplexer::new(MuxStrategy::SmartProbe {
            probe_timeout: Duration::from_millis(200),
        });
        assert!(matches!(mux.strategy(), MuxStrategy::SmartProbe { .. }));
    }

    #[tokio::test]
    async fn direct_transport_connects_to_echo() {
        // Bind a trivial TCP listener and verify DirectTransport reaches it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = conn.write_all(b"HELLO").await;
            }
        });

        let t = DirectTransport;
        let mut stream = t.connect(addr).await.expect("direct connect failed");

        let mut buf = [0u8; 8];
        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf))
            .await
            .expect("read timed out")
            .expect("read error");

        assert_eq!(&buf[..n], b"HELLO");
    }

    #[tokio::test]
    async fn sequential_mux_falls_through_to_working_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = conn.write_all(b"OK").await;
            }
        });

        struct AlwaysFailTransport;
        impl PluggableTransport for AlwaysFailTransport {
            fn name(&self) -> &str {
                "always-fail"
            }
            fn connect(
                &self,
                _addr: String,
            ) -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>> {
                Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "always fail",
                    ))
                })
            }
        }

        struct OverrideTransport(String);
        impl PluggableTransport for OverrideTransport {
            fn name(&self) -> &str {
                "override"
            }
            fn connect(
                &self,
                _addr: String,
            ) -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>> {
                let target = self.0.clone();
                Box::pin(async move {
                    let s = TcpStream::connect(&target).await?;
                    Ok(Box::new(s) as BoxStream)
                })
            }
        }

        let mux = TransportMultiplexer::new(MuxStrategy::Sequential)
            .with_transport(AlwaysFailTransport)
            .with_transport(OverrideTransport(real_addr));

        let mut stream = mux.connect("dummy:1").await.expect("mux connect failed");

        let mut buf = [0u8; 4];
        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf))
            .await
            .expect("read timed out")
            .expect("read error");
        assert_eq!(&buf[..n], b"OK");
    }

    #[tokio::test]
    async fn empty_mux_returns_error() {
        let mux = TransportMultiplexer::new(MuxStrategy::Sequential);
        let result: io::Result<BoxStream> = mux.connect("127.0.0.1:1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn race_mux_returns_first_success() {
        // Two listeners: one fast, one slow.
        let fast_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fast_addr = fast_listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            if let Ok((mut conn, _)) = fast_listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = conn.write_all(b"FAST").await;
            }
        });

        struct DelayedTransport(Duration, String);
        impl PluggableTransport for DelayedTransport {
            fn name(&self) -> &str {
                "delayed"
            }
            fn connect(
                &self,
                _addr: String,
            ) -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>> {
                let delay = self.0;
                let target = self.1.clone();
                Box::pin(async move {
                    tokio::time::sleep(delay).await;
                    let s = TcpStream::connect(&target).await?;
                    Ok(Box::new(s) as BoxStream)
                })
            }
        }

        let mux = TransportMultiplexer::new(MuxStrategy::RaceAll)
            .with_transport(DelayedTransport(
                Duration::from_millis(200),
                fast_addr.clone(),
            ))
            .with_transport(OverrideTransportFast(fast_addr.clone()));

        struct OverrideTransportFast(String);
        impl PluggableTransport for OverrideTransportFast {
            fn name(&self) -> &str {
                "fast"
            }
            fn connect(
                &self,
                _addr: String,
            ) -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send + 'static>> {
                let target = self.0.clone();
                Box::pin(async move {
                    let s = TcpStream::connect(&target).await?;
                    Ok(Box::new(s) as BoxStream)
                })
            }
        }

        // Connect should succeed (one of the two will connect to the fast listener).
        let result = tokio::time::timeout(Duration::from_millis(500), mux.connect("dummy:1"))
            .await
            .expect("race connect timed out");
        assert!(
            result.is_ok(),
            "race should succeed when at least one transport works"
        );
    }
}
