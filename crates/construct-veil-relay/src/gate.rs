//! Constant-shape gate — the load-bearing module.
//!
//! After TLS handshake, the relay reads the first application data and routes:
//! - **Valid auth** → Tunnel (h2c forward to Construct backend)
//! - **Invalid/missing** → Site (forward to cover application)
//!
//! **Critical:** both branches must be constant-shape. Failed auth MUST NOT:
//! - Close the connection differently
//! - Add custom timeouts
//! - Change response timing or length distribution
//!
//! The cover app's own behaviour is the ONLY timing on the unauth branch.

use bytes::BytesMut;
use construct_veil_protocol::{AUTH_PAYLOAD_LEN, EXPORTER_LABEL, VeilFrontCodec};
use tokio::io::AsyncReadExt;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};

use crate::tickets::TicketStore;

/// Result of the gate decision.
pub enum GateResult<S> {
    /// Valid auth — this connection is a tunnel.
    Tunnel {
        /// The original TLS stream (un-split).
        stream: S,
        /// Remaining buffered data after the AUTH frame was consumed.
        /// May contain early tunnel data from the client.
        leftover: BytesMut,
    },
    /// Invalid auth — forward to cover site.
    Site {
        /// The original TLS stream (un-split).
        stream: S,
        /// The raw bytes that were read (first application data).
        /// Must be forwarded to the site backend as-is.
        first_bytes: BytesMut,
    },
}

/// Gate with TLS exporter access — the actual production gate.
///
/// This is the version used by the main accept loop. It extracts the TLS
/// exporter from the connection before routing.
pub async fn gate_with_exporter(
    tls_stream: TlsStream<tokio::net::TcpStream>,
    store: &TicketStore,
) -> Result<GateResult<TlsStream<tokio::net::TcpStream>>, std::io::Error> {
    // Extract TLS exporter BEFORE splitting the stream.
    let exporter = {
        let (_, conn) = tls_stream.get_ref();
        let mut exp = [0u8; 32];
        if let Err(e) = conn.export_keying_material(&mut exp, EXPORTER_LABEL.as_bytes(), Some(&[]))
        {
            warn!(error = %e, "TLS exporter failed, routing to site");
            // Can't validate without exporter → site.
            return Ok(GateResult::Site {
                stream: tls_stream,
                first_bytes: BytesMut::new(),
            });
        }
        exp
    };

    let mut reader = tls_stream;
    let mut buf = BytesMut::with_capacity(4096);

    // Read enough bytes to attempt frame decode.
    loop {
        let n = reader.read_buf(&mut buf).await.map_err(|e| {
            warn!(error = %e, "read error during gate");
            e
        })?;

        if n == 0 {
            debug!("no data after TLS handshake, routing to site");
            return Ok(GateResult::Site {
                stream: reader,
                first_bytes: buf,
            });
        }

        if buf.len() >= AUTH_PAYLOAD_LEN + 3 {
            break;
        }

        if buf.len() > 65536 {
            debug!(
                bytes = buf.len(),
                "too much data without frame header, routing to site"
            );
            return Ok(GateResult::Site {
                stream: reader,
                first_bytes: buf,
            });
        }
    }

    // Try to decode the first frame.
    let mut decode_buf = buf.clone();
    match VeilFrontCodec::default().decode(&mut decode_buf) {
        Ok(Some(frame)) if frame.is_auth() && frame.payload.len() == AUTH_PAYLOAD_LEN => {
            let ticket_id: [u8; 16] = {
                let mut id = [0u8; 16];
                id.copy_from_slice(&frame.payload[..16]);
                id
            };
            let authcode: [u8; 32] = {
                let mut code = [0u8; 32];
                code.copy_from_slice(&frame.payload[16..48]);
                code
            };

            // Validate against the ticket store.
            if let Some(_ticket) = store.validate(&ticket_id, &authcode, &exporter).await {
                debug!(ticket_id = ?hex::encode(ticket_id), "auth valid, routing to tunnel");
                // The decode_buf has the AUTH frame consumed; remaining bytes are leftover.
                Ok(GateResult::Tunnel {
                    stream: reader,
                    leftover: decode_buf,
                })
            } else {
                debug!(ticket_id = ?hex::encode(ticket_id), "auth invalid, routing to site");
                // Auth failed — route to site with original bytes.
                Ok(GateResult::Site {
                    stream: reader,
                    first_bytes: buf,
                })
            }
        }
        Ok(Some(frame)) => {
            debug!(
                frame_type = frame.frame_type,
                "non-auth frame, routing to site"
            );
            Ok(GateResult::Site {
                stream: reader,
                first_bytes: buf,
            })
        }
        Ok(None) => {
            debug!("incomplete frame, routing to site");
            Ok(GateResult::Site {
                stream: reader,
                first_bytes: buf,
            })
        }
        Err(e) => {
            debug!(error = %e, "frame decode error, routing to site");
            Ok(GateResult::Site {
                stream: reader,
                first_bytes: buf,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_result_is_send() {
        // GateResult<BytesMut> must be Send for tokio::spawn.
        fn assert_send<T: Send>() {}
        assert_send::<GateResult<BytesMut>>();
    }
}
