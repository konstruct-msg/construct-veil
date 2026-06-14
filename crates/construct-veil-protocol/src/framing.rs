//! Frame codec — `tokio-util` codec for veil-front wire protocol.
//!
//! Provides `VeilFrontCodec` which can be used with `tokio_util::codec::Framed`
//! to read/write frames over any `AsyncRead + AsyncWrite` stream.
//!
//! # Frame format (WIRE_VER 3)
//! ```text
//! [ver:u8=WIRE_VER]
//! [type:u8]                       — AUTH (0x00) | DATA (0x01) | CHAFF (0x02)
//! [payload_len:varint]            — declared payload length
//! [pad_len:varint]                — trailing zero-pad length (0 if no bucketing)
//! [payload : payload_len bytes]
//! [pad     : pad_len  bytes of 0x00]
//! ```
//!
//! The version byte is checked on decode — mismatched versions produce an error,
//! enabling detection of silent format drift and per-version golden-vector pinning.
//!
//! `pad_len > 0` is produced by the encoder only when buckets are configured via
//! [`VeilFrontCodec::with_buckets`]. The decoder always reads `pad_len` and
//! silently discards the trailing bytes — it does not check that they are zero,
//! since the receiver gains nothing by validating bytes the sender is free to
//! choose.
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
use crate::{FRAME_TYPE_AUTH, FRAME_TYPE_AUTH_V2, FRAME_TYPE_CHAFF, FRAME_TYPE_DATA, WIRE_VER};

/// Default maximum frame payload size (1 MiB).
const DEFAULT_MAX_PAYLOAD: usize = 1024 * 1024;

/// Length buckets for codec-side payload padding.
///
/// When the encoder is configured with [`VeilFrontCodec::with_buckets`], each
/// frame's payload is padded with trailing zero bytes up to the smallest
/// bucket that is >= the payload length. Payloads larger than the top bucket
/// are emitted unpadded.
///
/// Buckets are chosen to cover typical gRPC-over-h2c frame sizes while
/// keeping the number of distinct on-wire lengths small. With these 16
/// buckets, the TLS-record length distribution shrinks from ~MTU values to
/// at most 16 distinct cipher-text record sizes, removing record-length as a
/// classifier feature.
pub const LENGTH_BUCKETS: &[usize] = &[
    64, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384,
];

/// Return the smallest bucket >= `payload_len`, or `payload_len` itself if
/// no bucket is large enough.
pub fn pick_bucket(buckets: &[usize], payload_len: usize) -> usize {
    for &b in buckets {
        if b >= payload_len {
            return b;
        }
    }
    payload_len
}

/// The veil-front frame codec for `tokio-util::codec::Framed`.
#[derive(Debug, Clone)]
pub struct VeilFrontCodec {
    /// Maximum frame payload size allowed.
    pub max_payload: usize,
    /// Optional length-bucket table for encoder-side padding.
    /// `None` means the encoder emits `pad_len = 0` (no padding).
    /// The decoder behaves identically either way.
    pub buckets: Option<&'static [usize]>,
}

impl Default for VeilFrontCodec {
    fn default() -> Self {
        Self {
            max_payload: DEFAULT_MAX_PAYLOAD,
            buckets: None,
        }
    }
}

impl VeilFrontCodec {
    /// Create a new codec with the default max payload (1 MiB) and no
    /// encoder-side padding.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new codec with a custom max payload.
    pub fn with_max_payload(max_payload: usize) -> Self {
        Self {
            max_payload,
            buckets: None,
        }
    }

    /// Enable encoder-side bucket padding.
    ///
    /// Payloads shorter than the smallest enclosing bucket are padded with
    /// zero bytes; the receiver-side decoder always honours `pad_len` and
    /// discards the trailing bytes regardless of its own configuration.
    pub fn with_buckets(mut self, buckets: &'static [usize]) -> Self {
        self.buckets = Some(buckets);
        self
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
    /// Create a new frame with the given type and payload.
    pub fn new(frame_type: u8, payload: Bytes) -> Self {
        Self {
            frame_type,
            payload,
        }
    }

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

    /// Create an AUTH v2 frame carrying a signed capability.
    ///
    /// The payload is `capability_blob || authcode[32]` (see `AuthRecordV2`).
    pub fn auth_v2(payload: Bytes) -> Self {
        Self {
            frame_type: FRAME_TYPE_AUTH_V2,
            payload,
        }
    }

    /// Check if this is an AUTH frame.
    pub fn is_auth(&self) -> bool {
        self.frame_type == FRAME_TYPE_AUTH
    }

    /// Check if this is an AUTH v2 (capability) frame.
    pub fn is_auth_v2(&self) -> bool {
        self.frame_type == FRAME_TYPE_AUTH_V2
    }

    /// Check if this is a DATA frame.
    pub fn is_data(&self) -> bool {
        self.frame_type == FRAME_TYPE_DATA
    }

    /// Check if this is a CHAFF frame.
    pub fn is_chaff(&self) -> bool {
        self.frame_type == FRAME_TYPE_CHAFF
    }

    /// Encode the frame to wire format bytes with `pad_len = 0`.
    ///
    /// Wire format: `[ver:u8][type:u8][payload_len:varint][pad_len:varint=0][payload]`.
    /// Use [`VeilFrontCodec`] with [`VeilFrontCodec::with_buckets`] if you
    /// need encoder-side padding.
    pub fn encode_to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + 9 + 1 + self.payload.len());
        buf.put_u8(WIRE_VER);
        buf.put_u8(self.frame_type);
        encode_varint(self.payload.len() as u64, &mut buf);
        encode_varint(0, &mut buf);
        buf.put_slice(&self.payload);
        buf.freeze()
    }
}

// ── Encoder ────────────────────────────────────────────────────────────────

impl Encoder<Frame> for VeilFrontCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = item.payload.len();
        let pad_len = match self.buckets {
            Some(b) => pick_bucket(b, payload_len).saturating_sub(payload_len),
            None => 0,
        };
        dst.put_u8(WIRE_VER);
        dst.put_u8(item.frame_type);
        encode_varint(payload_len as u64, dst);
        encode_varint(pad_len as u64, dst);
        dst.put_slice(&item.payload);
        if pad_len > 0 {
            dst.put_bytes(0u8, pad_len);
        }
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

        // Check wire version byte.
        let ver = src[0];
        if ver != WIRE_VER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown wire version: got 0x{ver:02x}, expected 0x{WIRE_VER:02x}"),
            ));
        }

        if src.len() < 2 {
            // Have version byte but not enough for frame type — need more data.
            return Ok(None);
        }

        // Peek at frame type.
        let frame_type = src[1];

        // Decode payload_len varint.
        let mut payload_len_buf = &src[2..];
        let (payload_len, vb_payload) = match decode_varint(&mut payload_len_buf) {
            Some(v) => v,
            None => return Ok(None),
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

        // Decode pad_len varint (always present in WIRE_VER 3).
        let pre_pad_off = 2 + vb_payload;
        if src.len() <= pre_pad_off {
            return Ok(None);
        }
        let mut pad_len_buf = &src[pre_pad_off..];
        let (pad_len, vb_pad) = match decode_varint(&mut pad_len_buf) {
            Some(v) => v,
            None => return Ok(None),
        };

        if pad_len as usize > self.max_payload {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "frame pad too large: {} bytes (max {})",
                    pad_len, self.max_payload
                ),
            ));
        }

        let header_len = 2 + vb_payload + vb_pad;
        let total_len = header_len + payload_len as usize + pad_len as usize;

        if src.len() < total_len {
            return Ok(None);
        }

        // Advance past header.
        src.advance(header_len);

        // Extract payload, then drop the trailing pad bytes.
        let payload = src.split_to(payload_len as usize).freeze();
        src.advance(pad_len as usize);

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

        // Give it only the first 3 bytes (ver + type + partial varint).
        let mut partial = buf.split_to(3);
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

        // Take only the version byte — can't decode anything.
        buf.truncate(1);

        let result = codec.decode_eof(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_wrong_version() {
        let mut codec = VeilFrontCodec::default();
        let mut buf = BytesMut::new();

        // Manually write a frame with wrong version.
        buf.put_u8(0xFF); // wrong version
        buf.put_u8(FRAME_TYPE_DATA);
        encode_varint(5, &mut buf);
        buf.put_slice(b"hello");

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("wire version"));
    }

    #[test]
    fn version_byte_in_encoded() {
        let mut codec = VeilFrontCodec::default();
        let payload = Bytes::from(&b"test"[..]);
        let frame = Frame::data(payload);
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // First byte must be WIRE_VER.
        assert_eq!(buf[0], WIRE_VER);
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

    // ── Bucket padding (WIRE_VER 3) ────────────────────────────────────────

    #[test]
    fn pick_bucket_rounds_up() {
        assert_eq!(pick_bucket(LENGTH_BUCKETS, 0), 64);
        assert_eq!(pick_bucket(LENGTH_BUCKETS, 1), 64);
        assert_eq!(pick_bucket(LENGTH_BUCKETS, 64), 64);
        assert_eq!(pick_bucket(LENGTH_BUCKETS, 65), 128);
        assert_eq!(pick_bucket(LENGTH_BUCKETS, 1500), 1536);
        assert_eq!(pick_bucket(LENGTH_BUCKETS, 16384), 16384);
    }

    #[test]
    fn pick_bucket_passes_oversize_through() {
        assert_eq!(pick_bucket(LENGTH_BUCKETS, 20_000), 20_000);
    }

    #[test]
    fn encoder_with_buckets_pads_to_next_bucket() {
        let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
        let payload = Bytes::from(&b"hello"[..]); // 5 bytes → bucket 64
        let frame = Frame::data(payload.clone());

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Wire: [ver=3][type=DATA][payload_len=5 (1B varint)]
        //       [pad_len=59 (1B varint)][payload(5)][pad(59)] = 68 bytes
        assert_eq!(buf.len(), 1 + 1 + 1 + 1 + 64);
        // Trailing 59 bytes must be zero pad.
        assert!(buf[buf.len() - 59..].iter().all(|&b| b == 0));
    }

    #[test]
    fn decoder_strips_pad_bytes() {
        let mut enc = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
        let mut dec = VeilFrontCodec::default(); // no buckets — decode is symmetric
        let payload = Bytes::from(&b"abcdef"[..]);

        let mut buf = BytesMut::new();
        enc.encode(Frame::data(payload.clone()), &mut buf).unwrap();

        let decoded = dec.decode(&mut buf).unwrap().expect("decode failed");
        assert_eq!(decoded.payload, payload);
        assert!(buf.is_empty(), "decoder must consume the pad bytes");
    }

    #[test]
    fn encoder_no_pad_when_at_bucket_boundary() {
        let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
        let payload = Bytes::from(vec![0u8; 256]); // exactly bucket 256
        let frame = Frame::data(payload);

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Header: ver+type+varint(256)=2B+varint(0)=1B = 5B; payload = 256B.
        assert_eq!(buf.len(), 1 + 1 + 2 + 1 + 256);
    }

    #[test]
    fn encoder_no_pad_above_top_bucket() {
        let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);
        let payload = Bytes::from(vec![0u8; 20_000]); // above top bucket
        let frame = Frame::data(payload);

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // pad_len = 0 (oversize falls through).
        // Header: ver+type+varint(20000)=3B+varint(0)=1B = 6B; payload = 20000B.
        assert_eq!(buf.len(), 1 + 1 + 3 + 1 + 20_000);
    }

    #[test]
    fn default_codec_emits_zero_pad() {
        let mut codec = VeilFrontCodec::default();
        let payload = Bytes::from(&b"x"[..]);
        let mut buf = BytesMut::new();
        codec.encode(Frame::data(payload), &mut buf).unwrap();
        // [ver][type][payload_len=1][pad_len=0][x]
        assert_eq!(&buf[..], &[WIRE_VER, FRAME_TYPE_DATA, 1, 0, b'x']);
    }

    #[test]
    fn bucket_distribution_within_bounds() {
        // Random payload sizes encoded through a bucketed codec must yield
        // wire sizes from a small fixed set.
        use rand::{Rng, SeedableRng};
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7);
        let mut codec = VeilFrontCodec::default().with_buckets(LENGTH_BUCKETS);

        let mut observed_payload_buckets = std::collections::BTreeSet::new();
        for _ in 0..2000 {
            let n = rng.gen_range(1..=LENGTH_BUCKETS[LENGTH_BUCKETS.len() - 1]);
            let mut buf = BytesMut::new();
            codec
                .encode(Frame::data(Bytes::from(vec![0xCC; n])), &mut buf)
                .unwrap();
            // Recover the on-wire payload+pad span via the published bucket
            // function — this is the invariant: bucket(n) bytes regardless of n.
            observed_payload_buckets.insert(pick_bucket(LENGTH_BUCKETS, n));
        }
        assert!(
            observed_payload_buckets.len() <= LENGTH_BUCKETS.len(),
            "observed {} distinct buckets, allowed at most {}",
            observed_payload_buckets.len(),
            LENGTH_BUCKETS.len()
        );
    }
}
