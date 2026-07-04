//! QUIC variable-length integer encoding and decoding (RFC 9000 Section 16).

use crate::error::{Error, Result};

/// Maximum value representable by a QUIC variable-length integer.
const MAX_VARINT: u64 = 4_611_686_018_427_387_903; // 2^62 - 1

/// Encodes a value as a QUIC variable-length integer.
///
/// # Panics
///
/// Panics if `value` is greater than `2^62 - 1`.
pub fn encode(value: u64) -> Vec<u8> {
    assert!(value <= MAX_VARINT, "value exceeds 2^62 - 1");

    if value <= 0x3f {
        vec![value as u8]
    } else if value <= 0x3fff {
        (value | 0x4000).to_be_bytes()[6..].to_vec()
    } else if value <= 0x3fffffff {
        (value | 0x80000000).to_be_bytes()[4..].to_vec()
    } else {
        (value | 0xc000000000000000).to_be_bytes().to_vec()
    }
}

/// Decodes a QUIC variable-length integer from a byte buffer.
///
/// Returns the decoded value and the number of bytes consumed.
pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
    todo!()
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
}
