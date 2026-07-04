//! HTTP Datagram payload types per RFC 9297.

use crate::{Error, H3DatagramErrorKind, Result};

/// The largest stream ID allowed by QUIC (RFC 9000 Section 2.1).
const MAX_QUIC_STREAM_ID: u64 = (1 << 62) - 1;

/// A payload carried by an HTTP Datagram.
///
/// HTTP Datagrams are defined by RFC 9297 as a convention for conveying
/// multiplexed, potentially unreliable datagrams inside an HTTP connection.
/// Each datagram is associated with a client-initiated bidirectional HTTP
/// request stream and carries an opaque payload whose semantics are defined by
/// the extension using HTTP Datagrams (for example, CONNECT-UDP in RFC 9298).
///
/// This type is transport-agnostic: it represents the abstract payload and
/// its request association, independent of whether the datagram is encoded
/// as an HTTP/3 Datagram frame or a DATAGRAM capsule.
///
/// # Payload size
///
/// `HttpDatagram` does not impose a payload-size limit. The actual limit is
/// negotiated by the HTTP/3 connection (`max_datagram_frame_size`) and is
/// enforced by the transport layer when encoding frames or capsules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct HttpDatagram {
    /// The request stream identifier with which this datagram is associated.
    ///
    /// This must be a client-initiated bidirectional stream ID, i.e.
    /// `stream_id % 4 == 0` and `stream_id <= 2^62 - 1`.
    stream_id: u64,
    /// The opaque payload bytes.
    payload: Vec<u8>,
}

impl HttpDatagram {
    /// Create a new HTTP datagram associated with the given request stream.
    ///
    /// `stream_id` must be a valid client-initiated bidirectional QUIC stream
    /// ID (`stream_id % 4 == 0` and `stream_id <= 2^62 - 1`), because RFC 9297
    /// associates HTTP datagrams only with such request streams.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::H3DatagramError`] if `stream_id` violates the
    /// constraints above.
    pub fn new(stream_id: u64, payload: impl Into<Vec<u8>>) -> Result<Self> {
        Self::validate_stream_id(stream_id)?;
        let payload = payload.into();
        Ok(Self { stream_id, payload })
    }

    /// Return the request stream identifier associated with this datagram.
    #[must_use]
    pub const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Return the opaque payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume the datagram and return its payload bytes.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Consume the datagram and return its stream identifier and payload.
    #[must_use]
    pub fn into_parts(self) -> (u64, Vec<u8>) {
        (self.stream_id, self.payload)
    }

    fn validate_stream_id(stream_id: u64) -> Result<()> {
        if stream_id > MAX_QUIC_STREAM_ID {
            return Err(Error::H3DatagramError {
                kind: H3DatagramErrorKind::Generic,
                message: "stream ID exceeds the maximum QUIC stream ID".into(),
            });
        }
        if stream_id % 4 != 0 {
            return Err(Error::H3DatagramError {
                kind: H3DatagramErrorKind::Generic,
                message: "stream ID is not a client-initiated bidirectional stream ID".into(),
            });
        }
        Ok(())
    }
}

/// Encoding and decoding semantics for a payload carried by an HTTP datagram.
///
/// Extensions such as CONNECT-UDP (RFC 9298) define the payload format carried
/// inside an HTTP datagram. Implement this trait for a concrete payload type to
/// convert between domain payload values and the opaque byte representation
/// stored in an [`HttpDatagram`].
///
/// # Contract
///
/// Implementations must be deterministic and panic-free on all inputs:
///
/// - `decode` must not panic on any `payload`, including empty or malformed
///   bytes; it should return an error instead.
/// - For every valid domain value `x`, `decode(&encode(x)?)` should round-trip
///   back to `x`.
/// - Implementations should validate input length, avoid recursion, and refuse
///   to allocate unbounded memory on untrusted peer data.
pub trait DatagramPayload: Sized {
    /// The error type returned when encoding or decoding fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Encode this payload into opaque datagram payload bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload cannot be encoded, for example because
    /// it is too large for the transport context.
    fn encode(&self) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Decode an HTTP datagram payload from opaque bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `payload` is malformed or cannot be decoded.
    fn decode(payload: &[u8]) -> std::result::Result<Self, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_datagram_holds_empty_payload() {
        let datagram = HttpDatagram::new(0, Vec::new()).unwrap();
        assert_eq!(datagram.stream_id(), 0);
        assert_eq!(datagram.payload(), &[]);
        assert!(datagram.payload().is_empty());
    }

    #[test]
    fn http_datagram_holds_non_empty_payload() {
        let payload = b"hello";
        let datagram = HttpDatagram::new(4, payload.as_slice()).unwrap();
        assert_eq!(datagram.stream_id(), 4);
        assert_eq!(datagram.payload(), payload);
    }

    #[test]
    fn http_datagram_converts_into_payload() {
        let payload = vec![1, 2, 3];
        let datagram = HttpDatagram::new(8, payload.clone()).unwrap();
        assert_eq!(datagram.into_payload(), payload);
    }

    #[test]
    fn http_datagram_splits_into_parts() {
        let payload = vec![1, 2, 3];
        let datagram = HttpDatagram::new(12, payload.clone()).unwrap();
        assert_eq!(datagram.into_parts(), (12, payload));
    }

    #[test]
    fn http_datagram_is_cloneable() {
        let datagram = HttpDatagram::new(0, vec![1, 2, 3]).unwrap();
        let cloned = datagram.clone();
        assert_eq!(datagram, cloned);
    }

    #[test]
    fn http_datagram_rejects_invalid_stream_id() {
        let err = HttpDatagram::new(1, vec![1]).unwrap_err();
        assert!(matches!(err, Error::H3DatagramError { .. }));
        assert!(
            err.to_string()
                .contains("not a client-initiated bidirectional stream ID")
        );
    }

    #[test]
    fn http_datagram_rejects_stream_id_above_quic_limit() {
        let err = HttpDatagram::new(MAX_QUIC_STREAM_ID + 1, vec![1]).unwrap_err();
        assert!(matches!(err, Error::H3DatagramError { .. }));
        assert!(
            err.to_string()
                .contains("exceeds the maximum QUIC stream ID")
        );
    }

    /// A small example payload type used to exercise the [`DatagramPayload`] trait.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct EchoPayload(Vec<u8>);

    impl DatagramPayload for EchoPayload {
        type Error = Error;

        fn encode(&self) -> std::result::Result<Vec<u8>, Self::Error> {
            Ok(self.0.clone())
        }

        fn decode(payload: &[u8]) -> std::result::Result<Self, Self::Error> {
            Ok(Self(payload.to_vec()))
        }
    }

    #[test]
    fn datagram_payload_trait_round_trips_bytes() {
        let original = EchoPayload(vec![1, 2, 3]);
        let encoded = original.encode().unwrap();
        let decoded = EchoPayload::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn datagram_payload_trait_decodes_empty_payload() {
        let decoded = EchoPayload::decode(&[]).unwrap();
        assert_eq!(decoded, EchoPayload(Vec::new()));
    }

    /// A payload type whose [`DatagramPayload::decode`] always fails.
    #[derive(Debug)]
    struct FailingPayload;

    impl DatagramPayload for FailingPayload {
        type Error = Error;

        fn encode(&self) -> std::result::Result<Vec<u8>, Self::Error> {
            Ok(Vec::new())
        }

        fn decode(_payload: &[u8]) -> std::result::Result<Self, Self::Error> {
            Err(Error::H3DatagramError {
                kind: H3DatagramErrorKind::Generic,
                message: "malformed payload".into(),
            })
        }
    }

    #[test]
    fn datagram_payload_trait_returns_decode_error() {
        let err = FailingPayload::decode(&[1, 2, 3]).unwrap_err();
        assert!(matches!(err, Error::H3DatagramError { .. }));
        assert_eq!(
            err.to_string(),
            "HTTP/3 datagram or capsule protocol error (0x33): malformed payload"
        );
    }
}
