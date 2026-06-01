//! Frame codec — `tokio-util` codec for veil-front wire protocol.
//!
//! Provides `VeilFrontCodec` which can be used with `tokio_util::codec::Framed`
//! to read/write frames over any `AsyncRead + AsyncWrite` stream.
//!
//! # Frame format
//! ```text
//! [type:u8][len:varint][payload:len bytes]
//! ```
//!
//! # Usage
//! ```ignore
//! use tokio_util::codec::Framed;
//! use construct_veil_protocol::VeilFrontCodec;
//!
//! let mut framed = Framed::new(stream, VeilFrontCodec::default());
//! framed.send(Frame::data(bytes)).await?;
//! let frame = framed.next().await.unwrap()?;
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::varint::{decode_varint, encode_varint};
use crate::{FRAME_TYPE_AUTH, FRAME_TYPE_CHAFF, FRAME_TYPE_DATA};

/// Default maximum frame payload size (1 MiB).
const DEFAULT_MAX_PAYLOAD: usize = 1024 * 1024;

/// The veil-front frame codec for `tokio-util::codec::Framed`.
#[derive(Debug, Clone)]
pub struct VeilFrontCodec {
    /// Maximum frame payload size allowed.
    pub max_payload: usize,
}

impl Default for VeilFrontCodec {
    fn default() -> Self {
        Self {
            max_payload: DEFAULT_MAX_PAYLOAD,
        }
    }
}

impl VeilFrontCodec {
    /// Create a new codec with the default max payload (1 MiB).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new codec with a custom max payload.
    pub fn with_max_payload(max_payload: usize) -> Self {
        Self { max_payload }
    }
}

/// A veil-front frame, produced and consumed by `VeilFrontCodec`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Frame {
    /// Frame type: `FRAME_TYPE_AUTH` (0x00), `FRAME_TYPE_DATA` (0x01), or `FRAME_TYPE_CHAFF` (0x02).
    pub frame_type: u8,
    /// Frame payload.
    pub payload: Bytes,
}

impl Frame {
    /// Create a DATA frame.
    pub fn data(payload: Bytes) -> Self {
        Self {
            frame_type: FRAME_TYPE_DATA,
            payload,
        }
    }

    /// Create a CHAFF frame with the given payload (random bytes recommended).
    pub fn chaff(payload: Bytes) -> Self {
        Self {
            frame_type: FRAME_TYPE_CHAFF,
            payload,
        }
    }

    /// Create an AUTH frame from raw ticket_id + authcode bytes.
    ///
    /// The payload must be exactly `TICKET_ID_LEN + AUTHCODE_LEN` (48 bytes).
    pub fn auth(payload: Bytes) -> Self {
        Self {
            frame_type: FRAME_TYPE_AUTH,
            payload,
        }
    }

    /// Check if this is an AUTH frame.
    pub fn is_auth(&self) -> bool {
        self.frame_type == FRAME_TYPE_AUTH
    }

    /// Check if this is a DATA frame.
    pub fn is_data(&self) -> bool {
        self.frame_type == FRAME_TYPE_DATA
    }

    /// Check if this is a CHAFF frame.
    pub fn is_chaff(&self) -> bool {
        self.frame_type == FRAME_TYPE_CHAFF
    }

    /// Encode the frame to wire format bytes.
    pub fn encode_to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + 9 + self.payload.len());
        buf.put_u8(self.frame_type);
        encode_varint(self.payload.len() as u64, &mut buf);
        buf.put_slice(&self.payload);
        buf.freeze()
    }
}

// ── Encoder ────────────────────────────────────────────────────────────────

impl Encoder<Frame> for VeilFrontCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u8(item.frame_type);
        encode_varint(item.payload.len() as u64, dst);
        dst.put_slice(&item.payload);
        Ok(())
    }
}

// ── Decoder ────────────────────────────────────────────────────────────────

impl Decoder for VeilFrontCodec {
    type Item = Frame;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        // Save position in case we need to backtrack (incomplete frame).
        let _saved_len = src.len();

        // Peek at frame type.
        let frame_type = src[0];

        // Try to decode the varint length.
        let mut len_buf = &src[1..];
        let (payload_len, varint_bytes) = match decode_varint(&mut len_buf) {
            Some(v) => v,
            None => {
                // Incomplete varint — need more data.
                return Ok(None);
            }
        };

        if payload_len as usize > self.max_payload {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "frame payload too large: {} bytes (max {})",
                    payload_len, self.max_payload
                ),
            ));
        }

        let header_len = 1 + varint_bytes; // frame_type byte + varint bytes
        let total_len = header_len + payload_len as usize;

        if src.len() < total_len {
            // Not enough data yet.
            return Ok(None);
        }

        // Advance past header.
        src.advance(header_len);

        // Extract payload.
        let payload = src.split_to(payload_len as usize).freeze();

        Ok(Some(Frame {
            frame_type,
            payload,
        }))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // If there's leftover data at EOF, it's a truncated frame.
        if !src.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated frame at EOF",
            ));
        }
        Ok(None)
    }
}

// ── Convenience constructors ───────────────────────────────────────────────

impl Frame {
    /// Create a DATA frame from a `Vec<u8>`.
    pub fn data_vec(payload: Vec<u8>) -> Self {
        Self::data(Bytes::from(payload))
    }

    /// Create a CHAFF frame filled with random bytes.
    #[cfg(feature = "rand")]
    pub fn chaff_random(len: usize) -> Self {
        use rand::RngCore;
        let mut payload = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut payload);
        Self::chaff(Bytes::from(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_single_frame() {
        let mut codec = VeilFrontCodec::default();
        let payload = Bytes::from(&b"hello veil-front"[..]);
        let frame = Frame::data(payload.clone());

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        let decoded = codec
            .decode(&mut buf)
            .unwrap()
            .expect("decode returned None");
        assert_eq!(decoded.frame_type, FRAME_TYPE_DATA);
        assert_eq!(decoded.payload, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn encode_decode_chaff_frame() {
        let mut codec = VeilFrontCodec::default();
        let payload = Bytes::from(vec![0xAB; 256]);
        let frame = Frame::chaff(payload.clone());

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec
            .decode(&mut buf)
            .unwrap()
            .expect("decode returned None");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_auth_frame() {
        let mut codec = VeilFrontCodec::default();

        // 48 bytes: 16 ticket_id + 32 authcode.
        let mut payload_bytes = [0u8; 48];
        payload_bytes[0] = 0xDE;
        payload_bytes[16] = 0xCA;
        let payload = Bytes::from(payload_bytes.to_vec());

        let frame = Frame::auth(payload.clone());

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec
            .decode(&mut buf)
            .unwrap()
            .expect("decode returned None");
        assert!(decoded.is_auth());
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn decode_incomplete_frame() {
        let mut codec = VeilFrontCodec::default();

        // Encode a frame.
        let payload = Bytes::from(&b"hello"[..]);
        let frame = Frame::data(payload);
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Give it only the first 2 bytes (type + partial varint).
        let mut partial = buf.split_to(2);
        assert!(codec.decode(&mut partial).unwrap().is_none());

        // Put the remaining bytes back.
        partial.unsplit(buf);
        let decoded = codec.decode(&mut partial).unwrap().expect("decode failed");
        assert!(decoded.is_data());
    }

    #[test]
    fn decode_multiple_frames() {
        let mut codec = VeilFrontCodec::default();
        let mut buf = BytesMut::new();

        let frames = vec![
            Frame::data(Bytes::from(&b"first"[..])),
            Frame::data(Bytes::from(&b"second"[..])),
            Frame::chaff(Bytes::from(vec![0u8; 64])),
        ];

        for f in &frames {
            codec.encode(f.clone(), &mut buf).unwrap();
        }

        for expected in &frames {
            let decoded = codec
                .decode(&mut buf)
                .unwrap()
                .expect("decode returned None");
            assert_eq!(decoded, *expected);
        }

        assert!(buf.is_empty());
    }

    #[test]
    fn payload_too_large() {
        let mut codec = VeilFrontCodec::with_max_payload(100);

        let payload = Bytes::from(vec![0u8; 200]);
        let frame = Frame::data(payload);

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_eof_truncated() {
        let mut codec = VeilFrontCodec::default();

        // Encode a frame.
        let payload = Bytes::from(&b"hello"[..]);
        let frame = Frame::data(payload);
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Take only the type byte.
        buf.truncate(1);

        let result = codec.decode_eof(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn frame_type_checks() {
        assert!(Frame::data(Bytes::new()).is_data());
        assert!(!Frame::data(Bytes::new()).is_auth());
        assert!(!Frame::data(Bytes::new()).is_chaff());

        assert!(Frame::auth(Bytes::new()).is_auth());
        assert!(Frame::chaff(Bytes::new()).is_chaff());
    }

    #[test]
    fn encode_to_bytes() {
        let payload = Bytes::from(&b"test"[..]);
        let frame = Frame::data(payload.clone());
        let encoded = frame.encode_to_bytes();

        let mut codec = VeilFrontCodec::default();
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = codec.decode(&mut buf).unwrap().expect("decode failed");
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn fuzz_decode_no_panic() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let mut codec = VeilFrontCodec::default();

        for _ in 0..10_000 {
            let len = rng.gen_range(0..=512);
            let data: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
            let mut buf = BytesMut::from(&data[..]);

            // decode should never panic — it either returns Ok(Some), Ok(None), or Err.
            let _ = codec.decode(&mut buf);
        }
    }

    #[test]
    fn large_payload_roundtrip() {
        let mut codec = VeilFrontCodec::default();
        let payload = Bytes::from(vec![0x55; 100_000]);
        let frame = Frame::data(payload.clone());

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().expect("decode failed");
        assert_eq!(decoded, frame);
    }
}
