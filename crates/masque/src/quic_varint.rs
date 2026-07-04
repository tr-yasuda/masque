//! QUIC variable-length integer encoding and decoding (RFC 9000 Section 16).

use crate::error::{Error, Result, VarIntErrorKind};

/// Maximum value representable by a QUIC variable-length integer.
pub const MAX_VARINT: u64 = 4_611_686_018_427_387_903; // 2^62 - 1

/// Encodes a value as a QUIC variable-length integer.
///
/// Returns the encoded bytes. The output length is 1, 2, 4, or 8 bytes
/// depending on the magnitude of `value`.
///
/// # Panics
///
/// Panics if `value` is greater than [`MAX_VARINT`]. For a checked
/// alternative, see [`try_encode`].
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
    let (len, encoded) = encode_to_array(value);
    encoded[..len].to_vec()
}

/// Encodes a value as a QUIC variable-length integer, returning an error if the
/// value is out of range.
///
/// This is the fallible counterpart to [`encode`].
///
/// # Examples
///
/// ```
/// use masque::quic_varint::{try_encode, MAX_VARINT};
///
/// assert_eq!(try_encode(64).unwrap(), vec![0x40, 0x40]);
/// assert!(try_encode(MAX_VARINT + 1).is_err());
/// ```
pub fn try_encode(value: u64) -> Result<Vec<u8>> {
    if value > MAX_VARINT {
        return Err(Error::InvalidVarInt {
            kind: VarIntErrorKind::ValueTooLarge,
            message: format!("value {value} exceeds 2^62 - 1"),
        });
    }
    let (len, encoded) = encode_to_array(value);
    Ok(encoded[..len].to_vec())
}

/// Encodes `value` into the provided buffer and returns the number of bytes
/// written.
///
/// This function does not allocate. The buffer must be at least 1 byte long;
/// the maximum possible encoded length is 8 bytes, so a `[u8; 8]` is sufficient
/// for any valid value.
///
/// # Errors
///
/// Returns an error if `value` is greater than [`MAX_VARINT`] or if `buf` is
/// too short to hold the encoded form.
///
/// # Examples
///
/// ```
/// use masque::quic_varint::encode_into;
///
/// let mut buf = [0u8; 8];
/// let n = encode_into(64, &mut buf).unwrap();
/// assert_eq!(&buf[..n], &[0x40, 0x40]);
/// ```
pub fn encode_into(value: u64, buf: &mut [u8]) -> Result<usize> {
    if value > MAX_VARINT {
        return Err(Error::InvalidVarInt {
            kind: VarIntErrorKind::ValueTooLarge,
            message: format!("value {value} exceeds 2^62 - 1"),
        });
    }
    let (len, encoded) = encode_to_array(value);
    if buf.len() < len {
        return Err(Error::InvalidVarInt {
            kind: VarIntErrorKind::BufferTooShort,
            message: "output buffer too short".into(),
        });
    }
    buf[..len].copy_from_slice(&encoded[..len]);
    Ok(len)
}

fn encode_to_array(value: u64) -> (usize, [u8; 8]) {
    if value <= 0x3f {
        (1, [value as u8, 0, 0, 0, 0, 0, 0, 0])
    } else if value <= 0x3fff {
        // Shift the 2-byte value into the most-significant bytes so that
        // `to_be_bytes()` produces a left-aligned `[u8; 8]`.
        (2, ((value | 0x4000) << 48).to_be_bytes())
    } else if value <= 0x3fffffff {
        (4, ((value | 0x80000000) << 32).to_be_bytes())
    } else {
        (8, (value | 0xc000000000000000).to_be_bytes())
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
    decode_at(buf, 0)
}

/// Decodes a QUIC variable-length integer starting at `offset` within `buf`.
///
/// Returns the decoded value and the number of bytes consumed starting at
/// `offset`. Trailing bytes after the encoded integer are ignored.
///
/// # Errors
///
/// Returns an error if `offset` is out of bounds or if the buffer is too
/// short to contain the encoded integer.
///
/// # Examples
///
/// ```
/// use masque::quic_varint::decode_at;
///
/// let buf = &[0x00, 0x40, 0x40, 0xff];
/// let (value, consumed) = decode_at(buf, 1).unwrap();
/// assert_eq!(value, 64);
/// assert_eq!(consumed, 2);
/// ```
pub fn decode_at(buf: &[u8], offset: usize) -> Result<(u64, usize)> {
    if buf.is_empty() {
        return Err(Error::InvalidVarInt {
            kind: VarIntErrorKind::EmptyBuffer,
            message: "empty buffer".into(),
        });
    }
    if offset >= buf.len() {
        return Err(Error::InvalidVarInt {
            kind: VarIntErrorKind::BufferTooShort,
            message: "offset out of bounds".into(),
        });
    }
    decode_inner(&buf[offset..])
}

fn decode_inner(buf: &[u8]) -> Result<(u64, usize)> {
    if buf.is_empty() {
        return Err(Error::InvalidVarInt {
            kind: VarIntErrorKind::EmptyBuffer,
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
            kind: VarIntErrorKind::BufferTooShort,
            message: "buffer too short".into(),
        });
    }

    let mut bytes = [0u8; 8];
    bytes[8 - len..].copy_from_slice(&buf[..len]);
    let value = u64::from_be_bytes(bytes) & mask;

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
    fn try_encode_rejects_oversized_values() {
        let err = try_encode(MAX_VARINT + 1).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::ValueTooLarge,
                ..
            }
        ));
        assert!(err.to_string().contains("exceeds 2^62 - 1"));
    }

    #[test]
    fn try_encode_matches_encode_for_valid_values() {
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
            assert_eq!(try_encode(value).unwrap(), encode(value));
        }
    }

    #[test]
    fn encode_into_writes_expected_bytes() {
        let mut buf = [0u8; 8];
        assert_eq!(encode_into(0, &mut buf).unwrap(), 1);
        assert_eq!(&buf[..1], &[0x00]);

        assert_eq!(encode_into(64, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[0x40, 0x40]);

        assert_eq!(encode_into(MAX_VARINT, &mut buf).unwrap(), 8);
        assert_eq!(&buf[..8], &[0xff; 8]);
    }

    #[test]
    fn encode_into_rejects_short_buffer() {
        let mut buf = [0u8; 1];
        let err = encode_into(MAX_VARINT, &mut buf).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                ..
            }
        ));
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
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::EmptyBuffer,
                ..
            }
        ));
        assert_eq!(err.to_string(), "invalid varint: empty buffer");
    }

    #[test]
    fn decode_rejects_short_buffer_for_two_byte_form() {
        let err = decode(&[0x40]).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                ..
            }
        ));
        assert_eq!(err.to_string(), "invalid varint: buffer too short");
    }

    #[test]
    fn decode_rejects_short_buffer_for_four_byte_form() {
        let err = decode(&[0x80, 0x00, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                ..
            }
        ));
        assert_eq!(err.to_string(), "invalid varint: buffer too short");
    }

    #[test]
    fn decode_rejects_short_buffer_for_eight_byte_form() {
        let err = decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                ..
            }
        ));
        assert_eq!(err.to_string(), "invalid varint: buffer too short");
    }

    #[test]
    fn decode_accepts_overlong_encodings() {
        // RFC 9000 Section 16 allows values to be encoded with more bytes than
        // necessary, except for the Frame Type field.
        assert_eq!(decode(&[0x40, 0x05]).unwrap(), (5, 2));
        assert_eq!(decode(&[0x80, 0x00, 0x00, 0x05]).unwrap(), (5, 4));
        assert_eq!(
            decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]).unwrap(),
            (5, 8)
        );
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let (value, consumed) = decode(&[0x40, 0x40, 0xff, 0xff]).unwrap();
        assert_eq!(value, 64);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn decode_at_reads_from_offset() {
        let buf = &[0x00, 0x40, 0x40, 0xff];
        let (value, consumed) = decode_at(buf, 1).unwrap();
        assert_eq!(value, 64);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn decode_at_rejects_out_of_bounds_offset() {
        let err = decode_at(&[0x40, 0x40], 3).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                ..
            }
        ));
    }

    #[test]
    fn decode_at_rejects_offset_equal_to_buffer_length() {
        let err = decode_at(&[0x40, 0x40], 2).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                ..
            }
        ));
        assert_eq!(err.to_string(), "invalid varint: offset out of bounds");
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
