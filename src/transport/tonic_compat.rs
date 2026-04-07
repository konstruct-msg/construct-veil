//! tonic / hyper integration for `Obfs4Stream`.
//!
//! Enabled by the `tonic-transport` feature flag.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};
//! use tonic::transport::Endpoint;
//!
//! let config = ClientConfig::from_bridge_cert("base64_cert")?;
//! let channel = Endpoint::from_static("https://relay.example.com:9443")
//!     .connect_with_connector(Obfs4Channel::new(config))
//!     .await?;
//!
//! // let client = MyServiceClient::new(channel);
//! ```
//!
//! ## Architecture
//!
//! ```text
//! tonic / gRPC
//!   └─ Endpoint::connect_with_connector(Obfs4Channel)
//!        └─ tower::Service<Uri> (Obfs4Channel)
//!             └─ TCP connect + obfs4 handshake
//!                  └─ HyperObfs4Io  (implements hyper::rt::Read + Write)
//!                       └─ Obfs4Stream<TcpStream>
//! ```
//!
//! `HyperObfs4Io` is a thin adapter between tokio's `AsyncRead`/`AsyncWrite`
//! and hyper 1.x's `hyper::rt::Read`/`hyper::rt::Write` traits.  It does not
//! copy data; all I/O is forwarded through a `Pin<&mut Obfs4Stream<TcpStream>>`.
//! The single `unsafe` block is required by `hyper::rt::ReadBufCursor::advance`,
//! which is marked unsafe to prevent callers from claiming more filled bytes
//! than were actually written; here we advance exactly by the count returned
//! by tokio's `ReadBuf::filled().len()`.

// `hyper::rt::ReadBufCursor::advance` is inherently unsafe (it marks uninitialised
// memory as initialised).  We use it correctly here — advance is called with
// exactly the number of bytes written into the slice by tokio's `poll_read`.
#![allow(unsafe_code)]

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use tokio::net::TcpStream;
use tower::Service;

use crate::{ClientConfig, Obfs4Stream};

// ── HyperObfs4Io ─────────────────────────────────────────────────────────────

/// Adapts [`Obfs4Stream<TcpStream>`] to the `hyper::rt::Read` + `hyper::rt::Write`
/// traits required by hyper 1.x connections.
///
/// This is the type returned by [`Obfs4Channel`]'s `Service::call`.  You
/// normally do not construct it directly — tonic / hyper receive it through the
/// service response.
pub struct HyperObfs4Io(Obfs4Stream<TcpStream>);

impl HyperObfs4Io {
    /// Wrap an already-connected stream.
    pub fn new(stream: Obfs4Stream<TcpStream>) -> Self {
        Self(stream)
    }

    /// Unwrap the inner stream.
    pub fn into_inner(self) -> Obfs4Stream<TcpStream> {
        self.0
    }
}

impl Read for HyperObfs4Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        use tokio::io::{AsyncRead, ReadBuf};

        // SAFETY: We only advance the cursor by `n`, which is exactly the
        // number of bytes that tokio's `poll_read` placed into `slice`.
        // The slice starts uninitialised; after `poll_read` the filled portion
        // (first `n` bytes) is fully initialised.
        let n = {
            let slice = unsafe {
                let raw = buf.as_mut();
                std::slice::from_raw_parts_mut(raw.as_mut_ptr() as *mut u8, raw.len())
            };
            let mut read_buf = ReadBuf::new(slice);
            match Pin::new(&mut self.0).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => read_buf.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };
        unsafe { buf.advance(n) };
        Poll::Ready(Ok(()))
    }
}

impl Write for HyperObfs4Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        use tokio::io::AsyncWrite;
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use tokio::io::AsyncWrite;
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        use tokio::io::AsyncWrite;
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

// ── Obfs4Channel ─────────────────────────────────────────────────────────────

/// A `tower::Service<Uri>` that establishes obfs4-obfuscated connections.
///
/// Pass to `tonic::transport::Endpoint::connect_with_connector()` to use
/// gRPC over obfs4.
///
/// ```rust,ignore
/// use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};
/// use tonic::transport::Endpoint;
///
/// let config = ClientConfig::from_bridge_cert("base64_cert")?;
/// let channel = Endpoint::from_static("https://relay.example.com:9443")
///     .connect_with_connector(Obfs4Channel::new(config))
///     .await?;
/// ```
#[derive(Clone)]
pub struct Obfs4Channel {
    config: ClientConfig,
}

impl Obfs4Channel {
    /// Create a new channel using the given client configuration.
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }
}

impl Service<Uri> for Obfs4Channel {
    type Response = HyperObfs4Io;
    type Error = crate::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // TCP connections are established on demand — always ready.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move {
            let host = uri.host().unwrap_or("127.0.0.1");
            let port = uri.port_u16().unwrap_or(443);
            let addr = format!("{host}:{port}");
            let stream = Obfs4Stream::connect(&addr, config).await?;
            Ok(HyperObfs4Io::new(stream))
        })
    }
}
