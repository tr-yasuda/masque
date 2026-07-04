//! DATAGRAM Capsule encoding and decoding (RFC 9297 Section 3.5).

use crate::quic_varint;
use crate::{Capsule, CapsuleType, Error, H3DatagramErrorKind, HttpDatagram, Result};

/// A DATAGRAM capsule (RFC 9297 Section 3.5).
///
/// DATAGRAM capsules carry an HTTP Datagram Payload on a stream when QUIC
/// DATAGRAM frames are unavailable or undesirable. The capsule type is always
/// `0x00`, and the capsule value is the HTTP Datagram Payload itself — the
/// opaque bytes that follow the Quarter Stream ID in an HTTP/3 Datagram frame.
///
/// This type reuses [`HttpDatagram`] for the payload and stream association, so
/// the same stream ID restrictions enforced by [`HttpDatagram::new`] apply.
/// Because DATAGRAM capsules are sent on the request stream, the stream
/// identifier is implicit in the transport context and is not included in the
/// encoded capsule value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DatagramCapsule(HttpDatagram);

impl DatagramCapsule {
    /// Create a DATAGRAM capsule from an HTTP datagram.
    pub fn new(datagram: HttpDatagram) -> Self {
        Self(datagram)
    }

    /// Return the HTTP datagram carried by this capsule.
    #[must_use]
    pub const fn datagram(&self) -> &HttpDatagram {
        &self.0
    }

    /// Consume the capsule and return the HTTP datagram.
    #[must_use]
    pub fn into_datagram(self) -> HttpDatagram {
        self.0
    }

    /// Encode this DATAGRAM capsule into a byte vector.
    ///
    /// The encoded form is a Capsule Protocol message with type `0x00` and a
    /// value equal to [`HttpDatagram::payload`]. The request stream identifier
    /// is not encoded because the capsule is sent on that stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] if the payload is too large to be
    /// represented as a Capsule Protocol value.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// Encode this DATAGRAM capsule, appending the result to `buf`.
    ///
    /// This is the allocation-friendly counterpart to [`DatagramCapsule::encode`].
    /// The payload bytes are copied directly into `buf` without an intermediate
    /// buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] if the payload is too large to be
    /// represented as a Capsule Protocol value.
    pub fn encode_into(&self, buf: &mut Vec<u8>) -> Result<()> {
        let payload = self.0.payload();

        let mut type_buf = [0u8; 8];
        let type_len = quic_varint::encode_into(CapsuleType::DATAGRAM.value(), &mut type_buf)?;
        let mut length_buf = [0u8; 8];
        let length_len = quic_varint::encode_into(payload.len() as u64, &mut length_buf)?;

        buf.reserve(type_len + length_len + payload.len());
        buf.extend_from_slice(&type_buf[..type_len]);
        buf.extend_from_slice(&length_buf[..length_len]);
        buf.extend_from_slice(payload);
        Ok(())
    }

    /// Decode a DATAGRAM capsule from a byte buffer.
    ///
    /// `stream_id` is the request stream on which the capsule was received. It
    /// is used to reconstruct the [`HttpDatagram`] because the DATAGRAM capsule
    /// wire format does not include the stream identifier.
    ///
    /// Returns the decoded capsule and the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] if the buffer does not contain a
    /// well-formed DATAGRAM capsule, if the capsule type is not `0x00`, or if
    /// `stream_id` is not a valid HTTP datagram stream ID.
    pub fn decode(buf: &[u8], stream_id: u64) -> Result<(Self, usize)> {
        let (capsule, consumed) = Capsule::decode(buf)?;
        if !capsule.capsule_type().is_datagram() {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::UnexpectedCapsuleType,
                format!(
                    "expected DATAGRAM capsule, got type {:#x}",
                    capsule.capsule_type().value()
                ),
            ));
        }

        let datagram = HttpDatagram::new(stream_id, capsule.into_value())?;
        Ok((Self(datagram), consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_capsule_stores_datagram() {
        let datagram = HttpDatagram::new(0, vec![1, 2, 3]).unwrap();
        let capsule = DatagramCapsule::new(datagram.clone());
        assert_eq!(capsule.datagram(), &datagram);
        assert_eq!(capsule.into_datagram(), datagram);
    }

    #[test]
    fn datagram_capsule_is_hashable() {
        use std::collections::HashSet;

        let datagram = HttpDatagram::new(0, vec![1, 2, 3]).unwrap();
        let capsule = DatagramCapsule::new(datagram);
        let mut set = HashSet::new();
        assert!(set.insert(capsule.clone()));
        assert!(!set.insert(capsule));
    }

    #[test]
    fn datagram_capsule_round_trips() {
        let datagram = HttpDatagram::new(12, vec![1, 2, 3]).unwrap();
        let capsule = DatagramCapsule::new(datagram);
        let encoded = capsule.encode().unwrap();
        let (decoded, consumed) = DatagramCapsule::decode(&encoded, 12).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.datagram().stream_id(), 12);
        assert_eq!(decoded.datagram().payload(), &[1, 2, 3]);
    }

    #[test]
    fn datagram_capsule_round_trips_empty_payload() {
        let datagram = HttpDatagram::new(4, Vec::new()).unwrap();
        let capsule = DatagramCapsule::new(datagram);
        let encoded = capsule.encode().unwrap();
        // DATAGRAM capsule type (0x00), length (0x00).
        assert_eq!(encoded, vec![0x00, 0x00]);
        let (decoded, consumed) = DatagramCapsule::decode(&encoded, 4).unwrap();
        assert_eq!(consumed, encoded.len());
        assert!(decoded.datagram().payload().is_empty());
    }

    #[test]
    fn datagram_capsule_round_trips_maximum_stream_id() {
        use crate::quic_varint::MAX_VARINT;

        let max_stream_id = MAX_VARINT - 3;
        let datagram = HttpDatagram::new(max_stream_id, vec![0xab]).unwrap();
        let capsule = DatagramCapsule::new(datagram);
        let encoded = capsule.encode().unwrap();
        let (decoded, consumed) = DatagramCapsule::decode(&encoded, max_stream_id).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.datagram().stream_id(), max_stream_id);
        assert_eq!(decoded.datagram().payload(), &[0xab]);
    }

    #[test]
    fn datagram_capsule_encodes_into_appends_to_buffer() {
        let datagram = HttpDatagram::new(8, vec![0xab]).unwrap();
        let capsule = DatagramCapsule::new(datagram);
        let mut buf = vec![0xff, 0xff];
        capsule.encode_into(&mut buf).unwrap();
        assert_eq!(buf[0..2], [0xff, 0xff]);
        let (_, consumed) = DatagramCapsule::decode(&buf[2..], 8).unwrap();
        assert_eq!(consumed, buf.len() - 2);
    }

    #[test]
    fn datagram_capsule_decodes_from_known_bytes() {
        // DATAGRAM capsule with payload [0xab] received on stream 8.
        let encoded = [0x00, 0x01, 0xab];
        let (decoded, consumed) = DatagramCapsule::decode(&encoded, 8).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(decoded.datagram().stream_id(), 8);
        assert_eq!(decoded.datagram().payload(), &[0xab]);
    }

    #[test]
    fn datagram_capsule_rejects_non_datagram_type() {
        // Capsule type 0x01, length 0x00.
        let encoded = [0x01, 0x00];
        let err = DatagramCapsule::decode(&encoded, 0).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::UnexpectedCapsuleType,
                ..
            }
        ));
        let text = err.to_string();
        assert!(text.contains("expected DATAGRAM capsule"));
        assert!(text.contains("0x1"));
    }

    #[test]
    fn datagram_capsule_rejects_truncated_value() {
        // DATAGRAM capsule type (0x00), length (0x05), but only 2 value bytes.
        let encoded = [0x00, 0x05, 0x01, 0x02];
        let err = DatagramCapsule::decode(&encoded, 0).unwrap_err();
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
    fn datagram_capsule_rejects_invalid_stream_id() {
        // Well-formed DATAGRAM capsule, but stream_id 1 is not a valid
        // client-initiated bidirectional stream ID.
        let encoded = [0x00, 0x01, 0xab];
        let err = DatagramCapsule::decode(&encoded, 1).unwrap_err();
        assert!(matches!(err, Error::H3DatagramError { .. }));
        assert!(
            err.to_string()
                .contains("not a client-initiated bidirectional stream ID")
        );
    }

    #[test]
    fn datagram_capsule_rejects_malformed_length_varint() {
        // DATAGRAM capsule type (0x00), truncated length varint.
        let encoded = [0x00, 0xc0];
        let err = DatagramCapsule::decode(&encoded, 0).unwrap_err();
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
    fn datagram_capsule_rejects_empty_buffer() {
        let err = DatagramCapsule::decode(&[], 0).unwrap_err();
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
    fn datagram_capsule_decoded_stops_at_end_of_capsule_with_trailing_bytes() {
        // DATAGRAM capsule followed by trailing bytes.
        let encoded = [0x00, 0x01, 0xab, 0xff, 0xff];
        let (decoded, consumed) = DatagramCapsule::decode(&encoded, 8).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(decoded.datagram().stream_id(), 8);
        assert_eq!(decoded.datagram().payload(), &[0xab]);
    }
}
