//! Variable-length integer encoding (LEB128-style, max 8 bytes).
//!
//! Used for frame length fields in the veil-front wire protocol.
//! Supports values 0..=2^64-1, but practically frames are < 64KB.

use bytes::{Buf, BufMut};

/// Maximum number of bytes a varint can occupy.
/// LEB128 uses 7 bits per byte, so u64::MAX needs ceil(64/7) = 10 bytes.
pub const VARINT_MAX_BYTES: usize = 10;

/// Encode a u64 as a LEB128 varint into the given buffer.
///
/// Returns the number of bytes written (1–8).
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

/// Decode a LEB128 varint from the given buffer.
///
/// Returns `Some((value, bytes_read))` or `None` if the buffer is too short
/// or the varint is malformed (too many continuation bytes).
pub fn decode_varint(buf: &mut impl Buf) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut bytes_read = 0;

    loop {
        if !buf.has_remaining() {
            return None; // incomplete varint
        }

        let byte = buf.get_u8();
        bytes_read += 1;

        if bytes_read > VARINT_MAX_BYTES {
            return None; // malformed: too many bytes
        }

        let low7 = (byte & 0x7F) as u64;

        // Check for overflow: can we fit 7 more bits?
        if shift >= 64 {
            return None;
        }
        let shifted = low7.checked_shl(shift)?;
        result |= shifted;
        shift += 7;

        if byte & 0x80 == 0 {
            // Last byte — done.
            return Some((result, bytes_read));
        }
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
