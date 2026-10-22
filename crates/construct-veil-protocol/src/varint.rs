//! Variable-length integer encoding (LEB128-style, at most 10 bytes).
//!
//! Used for frame length fields in the veil-front wire protocol.
//! Supports values 0..=2^64-1, but practically frames are < 64KB.

use bytes::{Buf, BufMut};

/// Maximum number of bytes a varint can occupy.
/// LEB128 uses 7 bits per byte, so u64::MAX needs ceil(64/7) = 10 bytes.
pub const VARINT_MAX_BYTES: usize = 10;

/// Encode a u64 as a LEB128 varint into the given buffer.
///
/// Returns the number of bytes written (1–10). Always the shortest (canonical)
/// encoding — the decoder rejects anything longer.
pub fn encode_varint(mut value: u64, buf: &mut impl BufMut) -> usize {
    if value == 0 {
        buf.put_u8(0);
        return 1;
    }

    let mut len = 0;
    while value > 0 {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80; // continuation bit
        }
        buf.put_u8(byte);
        len += 1;
    }
    len
}

/// Outcome of decoding a varint from a buffer that may hold only part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Varint {
    /// A complete varint: its value and how many bytes it took.
    Value(u64, usize),
    /// The buffer ends inside the varint — more bytes may complete it.
    Incomplete,
    /// No amount of further bytes can make this valid: more than
    /// [`VARINT_MAX_BYTES`], a value past `u64::MAX`, or a non-canonical
    /// (overlong) encoding.
    Malformed,
}

/// Decode a LEB128 varint, telling "incomplete" apart from "malformed".
///
/// Until 2026-10-22 the decoder returned `None` for both, and the frame codec
/// read every `None` as "need more data": a peer sending `03 01` followed by
/// 0xFF bytes kept the decoder waiting — and the read buffer growing — for as
/// long as it kept sending. It also accepted overlong (`80 00` = 0) and
/// overflowing (`FF×9 7F`) encodings.
pub fn decode_varint_checked(buf: &mut impl Buf) -> Varint {
    let mut result: u64 = 0;
    let mut bytes_read = 0usize;

    loop {
        if bytes_read == VARINT_MAX_BYTES {
            return Varint::Malformed; // a 10th byte with the continuation bit set
        }
        if !buf.has_remaining() {
            return Varint::Incomplete;
        }
        let byte = buf.get_u8();
        let low7 = (byte & 0x7F) as u64;
        let shift = 7 * bytes_read as u32;
        bytes_read += 1;

        // The 10th byte holds only bit 63: anything above 1 overflows u64.
        if bytes_read == VARINT_MAX_BYTES && low7 > 1 {
            return Varint::Malformed;
        }
        result |= low7 << shift;

        if byte & 0x80 == 0 {
            // A last byte of 0 after other bytes is an overlong encoding of a
            // value that fits in fewer bytes.
            if bytes_read > 1 && low7 == 0 {
                return Varint::Malformed;
            }
            return Varint::Value(result, bytes_read);
        }
    }
}

/// Decode a LEB128 varint from the given buffer.
///
/// Returns `Some((value, bytes_read))`, or `None` if the buffer is too short
/// **or** the varint is malformed. Use [`decode_varint_checked`] where the two
/// must be told apart (a stream decoder deciding whether to wait for more).
pub fn decode_varint(buf: &mut impl Buf) -> Option<(u64, usize)> {
    match decode_varint_checked(buf) {
        Varint::Value(v, n) => Some((v, n)),
        Varint::Incomplete | Varint::Malformed => None,
    }
}

/// Decode a varint from a byte slice without consuming a Buf trait object.
/// Returns `Some((value, bytes_read))` or `None`.
pub fn decode_varint_slice(data: &[u8]) -> Option<(u64, usize)> {
    let mut slice = data;
    decode_varint(&mut slice)
}

/// Encode a varint and return the resulting bytes.
#[inline]
pub fn encode_varint_vec(value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(VARINT_MAX_BYTES);
    encode_varint(value, &mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_zero() {
        let mut buf = Vec::new();
        let n = encode_varint(0, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf, vec![0x00]);

        let mut slice = buf.as_slice();
        let (val, len) = decode_varint(&mut slice).unwrap();
        assert_eq!(val, 0);
        assert_eq!(len, 1);
    }

    #[test]
    fn encode_decode_small() {
        for v in [1u64, 42, 127] {
            let mut buf = Vec::new();
            let n = encode_varint(v, &mut buf);
            assert_eq!(n, 1);
            assert_eq!(buf[0], v as u8);

            let mut slice = buf.as_slice();
            let (val, len) = decode_varint(&mut slice).unwrap();
            assert_eq!(val, v);
            assert_eq!(len, 1);
        }
    }

    #[test]
    fn encode_decode_128() {
        // 128 = 0x80 0x01 in LEB128
        let mut buf = Vec::new();
        let n = encode_varint(128, &mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf, vec![0x80, 0x01]);

        let mut slice = buf.as_slice();
        let (val, len) = decode_varint(&mut slice).unwrap();
        assert_eq!(val, 128);
        assert_eq!(len, 2);
    }

    #[test]
    fn encode_decode_max_u64() {
        let v = u64::MAX;
        let mut buf = Vec::new();
        let n = encode_varint(v, &mut buf);
        assert_eq!(n, VARINT_MAX_BYTES); // 10 bytes for LEB128 u64::MAX

        let mut slice = buf.as_slice();
        let (val, len) = decode_varint(&mut slice).unwrap();
        assert_eq!(val, u64::MAX);
        assert_eq!(len, VARINT_MAX_BYTES);
    }

    #[test]
    fn decode_truncated() {
        // Starts with continuation bit but no more bytes.
        let data = [0x80];
        assert!(decode_varint_slice(&data).is_none());
    }

    #[test]
    fn decode_too_many_bytes() {
        // 9 bytes of 0xFF — should fail.
        let data = [0xFF; 9];
        assert!(decode_varint_slice(&data).is_none());
    }

    #[test]
    fn roundtrip_random() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

        for _ in 0..10_000 {
            let v = rng.r#gen::<u64>();
            let mut buf = Vec::new();
            encode_varint(v, &mut buf);

            let mut slice = buf.as_slice();
            let (decoded, _) = decode_varint(&mut slice).expect("roundtrip failed");
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn encode_varint_vec_roundtrip() {
        let v = 300u64;
        let encoded = super::encode_varint_vec(v);
        let mut slice = encoded.as_slice();
        let (decoded, _) = decode_varint(&mut slice).unwrap();
        assert_eq!(decoded, v);
    }
}
