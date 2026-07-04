//! Capsule Protocol types and serialization (RFC 9297 Section 3.2).

use crate::quic_varint::{self, MAX_VARINT};
use crate::{Error, H3DatagramErrorKind, Result};

/// A Capsule Protocol type identifier.
///
/// This is a validated newtype: values are guaranteed to be representable as a
/// QUIC variable-length integer (`0..=MAX_VARINT`). The known DATAGRAM type
/// (`0x00`) is exposed as [`CapsuleType::DATAGRAM`]; any other value is treated
/// as an unknown type and preserved so that receivers can skip it without
/// aborting the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CapsuleType(u64);

impl CapsuleType {
    /// The DATAGRAM capsule type (`0x00`).
    pub const DATAGRAM: Self = Self(0);

    /// Create a `CapsuleType` from its raw numeric value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::VarintOutOfRange`] if `value` is greater than
    /// [`MAX_VARINT`].
    pub fn new(value: u64) -> Result<Self> {
        if value > MAX_VARINT {
            return Err(Error::H3DatagramError {
                kind: H3DatagramErrorKind::VarintOutOfRange,
                message: format!("capsule type {value} exceeds maximum varint value"),
                source: None,
            });
        }
        Ok(Self(value))
    }

    /// Return the raw numeric capsule type.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Return whether this is the known DATAGRAM type.
    #[must_use]
    pub const fn is_datagram(self) -> bool {
        self.0 == 0
    }

    /// Return whether this is an unknown capsule type.
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        self.0 != 0
    }
}

/// A Capsule Protocol message.
///
/// Each capsule consists of a type, a length, and a value. The length is
/// derived from the value and is serialized as a QUIC variable-length integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    capsule_type: CapsuleType,
    value: Vec<u8>,
}

impl Capsule {
    /// Create a new capsule from a type and value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::VarintOutOfRange`] if the value length cannot be
    /// encoded as a QUIC variable-length integer.
    pub fn new(capsule_type: CapsuleType, value: Vec<u8>) -> Result<Self> {
        validate_length(value.len())?;
        Ok(Self {
            capsule_type,
            value,
        })
    }

    /// Return the capsule type.
    #[must_use]
    pub const fn capsule_type(&self) -> CapsuleType {
        self.capsule_type
    }

    /// Return the capsule length (the number of bytes in the value).
    #[must_use]
    pub fn length(&self) -> u64 {
        self.value.len() as u64
    }

    /// Return the capsule value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Consume the capsule and return its value.
    #[must_use]
    pub fn into_value(self) -> Vec<u8> {
        self.value
    }

    /// Encode the capsule into a byte vector.
    ///
    /// The encoded form is `Capsule Type (i) | Capsule Length (i) | Capsule Value (...)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidVarInt`] only if an internal invariant is
    /// violated; this cannot happen for values produced through [`Capsule::new`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut type_buf = [0u8; 8];
        let type_len = quic_varint::encode_into(self.capsule_type.value(), &mut type_buf)?;

        let mut length_buf = [0u8; 8];
        let length_len = quic_varint::encode_into(self.length(), &mut length_buf)?;

        let mut out = Vec::with_capacity(type_len + length_len + self.value.len());
        out.extend_from_slice(&type_buf[..type_len]);
        out.extend_from_slice(&length_buf[..length_len]);
        out.extend_from_slice(&self.value);
        Ok(out)
    }

    /// Decode a capsule from a byte buffer.
    ///
    /// Returns the decoded capsule and the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] if the buffer does not contain a
    /// well-formed capsule. This includes malformed capsule type/length varints,
    /// a length that overflows `usize`, an offset overflow, or a truncated value.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        let (capsule_type_value, mut offset) = quic_varint::decode(buf).map_err(map_varint_err)?;
        let capsule_type = CapsuleType::new(capsule_type_value)?;

        let (length, consumed) = quic_varint::decode_at(buf, offset).map_err(map_varint_err)?;
        offset += consumed;

        let length = usize::try_from(length).map_err(|_| Error::H3DatagramError {
            kind: H3DatagramErrorKind::LengthTooLarge,
            message: "capsule length exceeds platform usize".into(),
            source: None,
        })?;

        let end = offset
            .checked_add(length)
            .ok_or_else(|| Error::H3DatagramError {
                kind: H3DatagramErrorKind::LengthOverflow,
                message: "capsule length overflow".into(),
                source: None,
            })?;

        if buf.len() < end {
            return Err(Error::H3DatagramError {
                kind: H3DatagramErrorKind::Truncated,
                message: "capsule value truncated".into(),
                source: None,
            });
        }

        let value = buf[offset..end].to_vec();
        Ok((
            Self {
                capsule_type,
                value,
            },
            end,
        ))
    }
}

fn validate_length(len: usize) -> Result<()> {
    let len_u64 = u64::try_from(len).map_err(|_| Error::H3DatagramError {
        kind: H3DatagramErrorKind::LengthTooLarge,
        message: "capsule value length exceeds u64".into(),
        source: None,
    })?;
    if len_u64 > MAX_VARINT {
        return Err(Error::H3DatagramError {
            kind: H3DatagramErrorKind::VarintOutOfRange,
            message: "capsule value length exceeds maximum varint".into(),
            source: None,
        });
    }
    Ok(())
}

fn map_varint_err(err: Error) -> Error {
    Error::H3DatagramError {
        kind: H3DatagramErrorKind::InvalidVarint,
        message: "malformed capsule varint".into(),
        source: Some(Box::new(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_type_datagram_value_is_zero() {
        assert_eq!(CapsuleType::DATAGRAM.value(), 0);
        assert!(CapsuleType::DATAGRAM.is_datagram());
        assert!(!CapsuleType::DATAGRAM.is_unknown());
        assert_eq!(CapsuleType::new(0).unwrap(), CapsuleType::DATAGRAM);
    }

    #[test]
    fn capsule_type_unknown_preserves_value() {
        let t = CapsuleType::new(0xff).unwrap();
        assert!(t.is_unknown());
        assert!(!t.is_datagram());
        assert_eq!(t.value(), 0xff);
    }

    #[test]
    fn capsule_type_known_and_unknown_values_differ() {
        assert_eq!(CapsuleType::DATAGRAM, CapsuleType::new(0).unwrap());
        assert_ne!(CapsuleType::DATAGRAM, CapsuleType::new(1).unwrap());
        assert_ne!(CapsuleType::new(1).unwrap(), CapsuleType::new(2).unwrap());
    }

    #[test]
    fn capsule_type_rejects_out_of_range_value() {
        let err = CapsuleType::new(MAX_VARINT + 1).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::VarintOutOfRange,
                ..
            }
        ));
        assert!(err.to_string().contains("capsule type"));
    }

    #[test]
    fn capsule_stores_type_length_and_value() {
        let value = vec![0x01, 0x02, 0x03];
        let capsule = Capsule::new(CapsuleType::DATAGRAM, value.clone()).unwrap();
        assert_eq!(capsule.capsule_type(), CapsuleType::DATAGRAM);
        assert_eq!(capsule.length(), 3);
        assert_eq!(capsule.value(), &value[..]);
        assert_eq!(capsule.into_value(), value);
    }

    #[test]
    fn capsule_encode_decode_round_trips_datagram() {
        let value = vec![0xab, 0xcd];
        let original = Capsule::new(CapsuleType::DATAGRAM, value).unwrap();
        let encoded = original.encode().unwrap();
        let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn capsule_encode_decode_round_trips_unknown_type() {
        let value = vec![0x00, 0x11, 0x22];
        let original = Capsule::new(CapsuleType::new(0x2bad).unwrap(), value).unwrap();
        let encoded = original.encode().unwrap();
        let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn capsule_encode_decode_round_trips_empty_value() {
        let original = Capsule::new(CapsuleType::DATAGRAM, vec![]).unwrap();
        let encoded = original.encode().unwrap();
        assert_eq!(encoded, vec![0x00, 0x00]);
        let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
        assert_eq!(decoded.length(), 0);
    }

    #[test]
    fn capsule_encode_decode_round_trips_varint_length_boundaries() {
        for len in [63usize, 64, 16383, 16384] {
            let value = vec![0u8; len];
            let original = Capsule::new(CapsuleType::DATAGRAM, value).unwrap();
            let encoded = original.encode().unwrap();
            let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
            assert_eq!(
                consumed,
                encoded.len(),
                "consumed bytes mismatch for value length {len}"
            );
            assert_eq!(decoded.length(), len as u64);
            assert_eq!(decoded.value().len(), len);
        }
    }

    #[test]
    fn capsule_decode_rejects_truncated_value() {
        // Type = 0x00, Length = 0x05, but only 2 value bytes follow.
        let encoded = [0x00, 0x05, 0x01, 0x02];
        let err = Capsule::decode(&encoded).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::Truncated,
                ..
            }
        ));
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn capsule_decode_wraps_truncated_header_in_h3_datagram_error() {
        let err = Capsule::decode(&[0xc0]).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::InvalidVarint,
                ..
            }
        ));
        assert!(err.to_string().contains("malformed capsule varint"));
    }

    #[test]
    fn capsule_decode_stops_at_end_of_capsule_with_trailing_bytes() {
        // DATAGRAM capsule with 2-byte value, followed by trailing bytes.
        let encoded = [0x00, 0x02, 0x01, 0x02, 0xff, 0xff];
        let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(decoded.value(), &[0x01, 0x02]);
    }
}
