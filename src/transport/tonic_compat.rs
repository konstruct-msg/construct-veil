//! tonic / hyper интеграция для `Obfs4Stream`.
//!
//! Включается feature-флагом `tonic-transport` (добавляет tonic, hyper, tower).
//!
//! ## Использование — из коробки
//!
//! [`Obfs4Channel::channel()`] возвращает готовый `tonic::transport::Channel`,
//! который можно сразу передать в любой tonic-клиент:
//!
//! ```rust,no_run
//! use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ClientConfig::from_bridge_cert("base64_cert_here")?;
//! let channel = Obfs4Channel::channel("https://relay.example.com:9443", config).await?;
//! // let client = MyServiceClient::new(channel);
//! # Ok(())
//! # }
//! ```
//!
//! ## Расширенная настройка Endpoint
//!
//! ```rust,no_run
//! use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};
//! use tonic::transport::Endpoint;
//! use std::time::Duration;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ClientConfig::from_bridge_cert("base64_cert_here")?;
//! let channel = Endpoint::from_static("https://relay.example.com:9443")
//!     .timeout(Duration::from_secs(10))
//!     .connect_with_connector(Obfs4Channel::new(config))
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Стек соединения
//!
//! ```text
//! tonic (gRPC / HTTP2)
//!   └─ tonic::transport::Channel
//!        └─ Obfs4Channel  (tower::Service<Uri>)
//!             └─ TCP connect + obfs4 Ntor handshake
//!                  └─ HyperObfs4Io  (hyper::rt::Read + Write)
//!                       └─ Obfs4Stream<TcpStream>
//! ```

// `hyper::rt::ReadBufCursor::advance` is inherently unsafe — it marks uninitialised
// memory as initialised. We use it correctly: advance is called with exactly the
// byte count written by tokio's poll_read into the same slice.
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
use tonic::transport::{Channel, Endpoint};
use tower::Service;

use crate::{ClientConfig, Obfs4Stream};

// ── HyperObfs4Io ─────────────────────────────────────────────────────────────

/// Адаптер `Obfs4Stream<TcpStream>` → `hyper::rt::Read + Write`.
///
/// Тип ответа [`Obfs4Channel`] в `Service::call`. Обычно вы не создаёте
/// его напрямую — его получает tonic/hyper через сервис.
pub struct HyperObfs4Io(Obfs4Stream<TcpStream>);

impl HyperObfs4Io {
    /// Обернуть уже подключённый стрим.
    pub fn new(stream: Obfs4Stream<TcpStream>) -> Self {
        Self(stream)
    }

    /// Извлечь внутренний стрим.
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

        // SAFETY: We advance the cursor by exactly `n` — the byte count
        // reported by tokio's poll_read as written into `slice`.
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

/// Коннектор obfs4 для tonic — реализует `tower::Service<Uri>`.
///
/// # Простой путь
///
/// ```rust,no_run
/// use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ClientConfig::from_bridge_cert("base64_cert_here")?;
/// let channel = Obfs4Channel::channel("https://relay.example.com:9443", config).await?;
/// // let client = MyServiceClient::new(channel);
/// # Ok(())
/// # }
/// ```
///
/// # С настройкой Endpoint
///
/// ```rust,no_run
/// use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};
/// use tonic::transport::Endpoint;
/// use std::time::Duration;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ClientConfig::from_bridge_cert("base64_cert_here")?;
/// let channel = Endpoint::from_static("https://relay.example.com:9443")
///     .timeout(Duration::from_secs(10))
///     .connect_with_connector(Obfs4Channel::new(config))
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Obfs4Channel {
    config: ClientConfig,
}

impl Obfs4Channel {
    /// Создать коннектор с заданной конфигурацией obfs4.
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Подключиться к `url` и вернуть готовый `tonic::transport::Channel`.
    ///
    /// Самый удобный способ — не требует ручной работы с `Endpoint`.
    ///
    /// ```rust,no_run
    /// use construct_ice::{ClientConfig, transport::tonic_compat::Obfs4Channel};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ClientConfig::from_bridge_cert("base64_cert_here")?;
    /// let channel = Obfs4Channel::channel("https://relay.example.com:9443", config).await?;
    /// // let client = MyServiceClient::new(channel);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn channel(
        url: &'static str,
        config: ClientConfig,
    ) -> Result<Channel, tonic::transport::Error> {
        Endpoint::from_static(url)
            .connect_with_connector(Self::new(config))
            .await
    }
}

impl Service<Uri> for Obfs4Channel {
    type Response = HyperObfs4Io;
    type Error = crate::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // TCP соединения создаются по требованию — всегда готов.
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
