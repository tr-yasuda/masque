//! QUIC variable-length integer encoding and decoding (RFC 9000 Section 16).

use crate::error::{Error, Result};

/// Maximum value representable by a QUIC variable-length integer.
pub const MAX_VARINT: u64 = 4_611_686_018_427_387_903; // 2^62 - 1

/// Encodes a value as a QUIC variable-length integer.
///
/// Returns the encoded bytes. The output length is 1, 2, 4, or 8 bytes
/// depending on the magnitude of `value`.
///
/// # Panics
///
/// Panics if `value` is greater than [`MAX_VARINT`].
///
/// # Examples
///
/// ```
/// use masque::quic_varint::encode;
///
/// assert_eq!(encode(0), vec![0x00]);
/// assert_eq!(encode(64), vec![0x40, 0x40]);
/// ```
pub fn encode(value: u64) -> Vec<u8> {
    assert!(value <= MAX_VARINT, "value exceeds 2^62 - 1");

    if value <= 0x3f {
        vec![value as u8]
    } else if value <= 0x3fff {
        // `u64::to_be_bytes()` returns 8 bytes; take the trailing 2 bytes.
        (value | 0x4000).to_be_bytes()[6..].to_vec()
    } else if value <= 0x3fffffff {
        // `u64::to_be_bytes()` returns 8 bytes; take the trailing 4 bytes.
        (value | 0x80000000).to_be_bytes()[4..].to_vec()
    } else {
        (value | 0xc000000000000000).to_be_bytes().to_vec()
    }
}

/// Decodes a QUIC variable-length integer from a byte buffer.
///
/// Returns the decoded value and the number of bytes consumed. Trailing bytes
/// after the encoded integer are ignored; callers must use the returned length
/// to advance the buffer when parsing multiple varints.
///
/// # Examples
///
/// ```
/// use masque::quic_varint::decode;
///
/// let (value, consumed) = decode(&[0x40, 0x40]).unwrap();
/// assert_eq!(value, 64);
/// assert_eq!(consumed, 2);
/// ```
pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
    if buf.is_empty() {
        return Err(Error::InvalidVarInt {
            message: "empty buffer".into(),
        });
    }

    let first = buf[0];
    let (len, mask) = match first >> 6 {
        0b00 => (1, 0x3f),
        0b01 => (2, 0x3fff),
        0b10 => (4, 0x3fffffff),
        0b11 => (8, 0x3fffffffffffffff),
        _ => unreachable!(),
    };

    if buf.len() < len {
        return Err(Error::InvalidVarInt {
            message: "buffer too short".into(),
        });
    }

    let mut bytes = [0u8; 8];
    bytes[8 - len..].copy_from_slice(&buf[..len]);
    let value = u64::from_be_bytes(bytes) & mask;

    let min_value_for_len = match len {
        // The 1-byte form covers 0..=0x3f, so any value it produces is valid.
        1 => 0,
        2 => 0x40,
        4 => 0x4000,
        8 => 0x40000000,
        _ => unreachable!(),
    };
    if value < min_value_for_len {
        return Err(Error::InvalidVarInt {
            message: "non-canonical encoding".into(),
        });
    }

    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_uses_one_byte_for_small_values() {
        assert_eq!(encode(0), vec![0x00]);
        assert_eq!(encode(63), vec![0x3f]);
    }

    #[test]
    fn encode_uses_two_bytes_for_medium_values() {
        assert_eq!(encode(64), vec![0x40, 0x40]);
        assert_eq!(encode(16_383), vec![0x7f, 0xff]);
    }

    #[test]
    fn encode_uses_four_bytes_for_large_values() {
        assert_eq!(encode(16_384), vec![0x80, 0x00, 0x40, 0x00]);
        assert_eq!(encode(1_073_741_823), vec![0xbf, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn encode_uses_eight_bytes_for_huge_values() {
        assert_eq!(
            encode(1_073_741_824),
            vec![0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode(MAX_VARINT),
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    #[should_panic(expected = "value exceeds 2^62 - 1")]
    fn encode_panics_on_oversized_values() {
        encode(MAX_VARINT + 1);
    }

    #[test]
    fn decode_round_trips_boundary_values() {
        let values = [
            0u64,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            MAX_VARINT,
        ];
        for value in values {
            let encoded = encode(value);
            let (decoded, consumed) = decode(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn decode_rejects_empty_buffer() {
        let err = decode(&[]).unwrap_err();
        assert_eq!(err.to_string(), "invalid varint: empty buffer");
    }

    #[test]
    fn decode_rejects_short_buffer_for_two_byte_form() {
        let err = decode(&[0x40]).unwrap_err();
        assert_eq!(err.to_string(), "invalid varint: buffer too short");
    }

    #[test]
    fn decode_rejects_short_buffer_for_four_byte_form() {
        let err = decode(&[0x80, 0x00, 0x00]).unwrap_err();
        assert_eq!(err.to_string(), "invalid varint: buffer too short");
    }

    #[test]
    fn decode_rejects_short_buffer_for_eight_byte_form() {
        let err = decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap_err();
        assert_eq!(err.to_string(), "invalid varint: buffer too short");
    }

    #[test]
    fn decode_rejects_non_canonical_two_byte_form() {
        let err = decode(&[0x40, 0x05]).unwrap_err();
        assert_eq!(err.to_string(), "invalid varint: non-canonical encoding");
    }

    #[test]
    fn decode_rejects_non_canonical_four_byte_form() {
        let err = decode(&[0x80, 0x00, 0x00, 0x05]).unwrap_err();
        assert_eq!(err.to_string(), "invalid varint: non-canonical encoding");
    }

    #[test]
    fn decode_rejects_non_canonical_eight_byte_form() {
        let err = decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]).unwrap_err();
        assert_eq!(err.to_string(), "invalid varint: non-canonical encoding");
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let (value, consumed) = decode(&[0x40, 0x40, 0xff, 0xff]).unwrap();
        assert_eq!(value, 64);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn decode_rfc9000_example_vectors() {
        let cases = [
            (0u64, &[0x00][..]),
            (1, &[0x01]),
            (64, &[0x40, 0x40]),
            (15_293, &[0x7b, 0xbd]),
            (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d]),
            (
                151_288_809_941_952_652u64,
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
        ];
        for (expected, buf) in cases {
            let (value, consumed) = decode(buf).unwrap();
            assert_eq!(value, expected);
            assert_eq!(consumed, buf.len());
        }
    }
}
