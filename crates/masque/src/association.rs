//! UDP association management for CONNECT-UDP.
//!
//! A [`UdpAssociation`] represents the binding between a CONNECT-UDP request
//! stream and a local UDP socket connected to the target. HTTP/3 Datagrams are
//! correlated with this association by the request stream identifier
//! ([`UdpAssociation::request_stream_id`]). The [`AssociationId`] is reserved
//! for future Context ID support (RFC 9298 Section 8.2) and is not currently
//! used to frame or unframe datagram payloads.
//!
//! The association also carries a [`Session`] that records negotiated HTTP/3
//! capabilities.
//!
//! # Security note
//!
//! This module provides a low-level UDP relay primitive. Production proxies
//! must enforce per-association rate limits, payload quotas, and target
//! allowlists above this layer to prevent open-relay abuse and amplification
//! attacks.

use std::fmt;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::types::Protocol;
use crate::{
    DatagramCapsule, Error, H3DatagramErrorKind, HttpDatagram, Result, Session, TransportKind,
};

/// A context identifier for a UDP association.
///
/// RFC 9298 Section 8.2 uses a Context ID encoded as a QUIC variable-length
/// integer. This newtype wraps the identifier value and enforces the QUIC
/// varint range (`0..=2^62 - 1`) at construction time.
///
/// Currently `AssociationId` is stored on the association but is not used to
/// correlate HTTP/3 Datagrams; correlation is done by the request stream
/// identifier. Context ID handling may be added in the future.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssociationId(u64);

impl AssociationId {
    /// The maximum value a QUIC variable-length integer can represent.
    ///
    /// RFC 9000 limits QUIC varints to 62-bit values.
    #[must_use]
    pub const fn max_value() -> u64 {
        crate::quic_varint::MAX_VARINT
    }

    /// Create a new association identifier from a raw value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAssociationId`] if `value` exceeds
    /// [`AssociationId::max_value`].
    pub fn new(value: u64) -> Result<Self> {
        if value > Self::max_value() {
            return Err(Error::InvalidAssociationId {
                value,
                max: Self::max_value(),
            });
        }
        Ok(Self(value))
    }

    /// Return the raw identifier value.
    #[must_use]
    pub const fn get(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for AssociationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Maximum payload size for a standard UDP datagram over IPv4.
///
/// IPv4 total length is 65,535 bytes; subtract the minimum 20-byte IPv4
/// header and the 8-byte UDP header.
pub const MAX_UDP_PAYLOAD_IPV4: usize = 65_507;

/// Maximum payload size for a standard UDP datagram over IPv6.
///
/// IPv6 payload length is 65,535 bytes; subtract the 8-byte UDP header.
pub const MAX_UDP_PAYLOAD_IPV6: usize = 65_527;

/// Maximum payload size for a standard UDP datagram.
///
/// This is the larger of [`MAX_UDP_PAYLOAD_IPV4`] and
/// [`MAX_UDP_PAYLOAD_IPV6`], matching the IPv6 limit.
pub const MAX_UDP_PAYLOAD: usize = MAX_UDP_PAYLOAD_IPV6;

/// Return the maximum UDP payload size for a single datagram sent to `addr`.
///
/// IPv4 and IPv6 have different header overhead, so the limit depends on the
/// address family of the target.
#[must_use]
pub const fn max_payload_for_addr(addr: SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(_) => MAX_UDP_PAYLOAD_IPV4,
        SocketAddr::V6(_) => MAX_UDP_PAYLOAD_IPV6,
    }
}

/// A UDP association for a CONNECT-UDP tunnel.
///
/// Owns a local UDP socket connected to the target and carries the session
/// context used to decide whether HTTP/3 Datagrams are available for this
/// association.
#[derive(Debug)]
pub struct UdpAssociation {
    socket: Option<UdpSocket>,
    target: SocketAddr,
    session: Session,
    id: AssociationId,
    stream_id: u64,
}

impl UdpAssociation {
    /// Bind a local UDP socket and connect it to the target.
    ///
    /// `local` is the address to bind locally. `target` is the remote UDP
    /// endpoint. `session` records the negotiated MASQUE capabilities. `id` is
    /// the association context identifier, currently reserved for future
    /// Context ID support and not used to correlate datagrams.
    /// `stream_id` is the CONNECT-UDP request stream identifier; it must be a
    /// client-initiated bidirectional QUIC stream ID within the QUIC varint
    /// range (`stream_id <= 2^62 - 1` and `stream_id % 4 == 0`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if `session` is not for
    /// [`Protocol::ConnectUdp`] or if `stream_id` is invalid.
    ///
    /// Returns [`Error::Transport`] if binding the local socket
    /// ([`TransportKind::UdpBind`]) or connecting to the target
    /// ([`TransportKind::UdpConnect`]) fails.
    pub async fn bind(
        local: SocketAddr,
        target: SocketAddr,
        session: Session,
        id: AssociationId,
        stream_id: u64,
    ) -> Result<Self> {
        if session.protocol() != Protocol::ConnectUdp {
            return Err(Error::InvalidConfig {
                field: "session",
                message: "protocol must be connect-udp".into(),
            });
        }
        if stream_id > crate::quic_varint::MAX_VARINT {
            return Err(Error::InvalidConfig {
                field: "stream_id",
                message: format!("stream ID {stream_id} exceeds the maximum QUIC stream ID"),
            });
        }
        if stream_id % 4 != 0 {
            return Err(Error::InvalidConfig {
                field: "stream_id",
                message: format!(
                    "stream ID {stream_id} is not a client-initiated bidirectional stream ID"
                ),
            });
        }

        let socket = UdpSocket::bind(local).await.map_err(|e| {
            Error::transport_error(
                TransportKind::UdpBind,
                "failed to bind UDP socket",
                Some(Box::new(e)),
            )
        })?;

        socket.connect(target).await.map_err(|e| {
            Error::transport_error(
                TransportKind::UdpConnect,
                "failed to connect UDP socket",
                Some(Box::new(e)),
            )
        })?;

        Ok(Self {
            socket: Some(socket),
            target,
            session,
            id,
            stream_id,
        })
    }

    /// Return the association identifier.
    #[must_use]
    pub const fn id(&self) -> AssociationId {
        self.id
    }

    /// Return the CONNECT-UDP request stream identifier associated with this
    /// association.
    #[must_use]
    pub const fn request_stream_id(&self) -> u64 {
        self.stream_id
    }

    fn ensure_h3_datagrams_enabled(&self) -> Result<()> {
        if !self.session.is_h3_datagram_enabled() {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::NotNegotiated,
                "HTTP/3 Datagrams are not negotiated for this association",
            ));
        }
        Ok(())
    }

    /// Encode an outbound UDP payload as an HTTP/3 Datagram addressed to this
    /// association's request stream.
    ///
    /// The UDP payload is framed with the CONNECT-UDP default Context ID (0)
    /// encoded as a QUIC variable-length integer, per RFC 9298 Section 8.2.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::NotNegotiated`] if HTTP/3 Datagrams have not been
    /// negotiated for this association.
    ///
    /// Returns [`Error::InvalidConfig`] if `payload` exceeds the address-family
    /// UDP payload limit.
    pub fn encode_h3_datagram(&self, payload: impl Into<Vec<u8>>) -> Result<HttpDatagram> {
        self.ensure_h3_datagrams_enabled()?;
        let payload = payload.into();
        let max = max_payload_for_addr(self.target);
        if payload.len() > max {
            return Err(Error::InvalidConfig {
                field: "payload",
                message: format!(
                    "payload length {} exceeds maximum UDP payload size {} for {}",
                    payload.len(),
                    max,
                    self.target.ip()
                ),
            });
        }
        let mut framed = payload;
        framed.insert(0, 0x00);
        HttpDatagram::new(self.stream_id, framed)
    }

    /// Decode an inbound HTTP/3 Datagram into a UDP payload to forward to the
    /// target.
    ///
    /// The CONNECT-UDP Context ID is parsed from the start of the HTTP/3
    /// Datagram payload and must be the default context (0), per RFC 9298
    /// Section 8.2. The remaining bytes are returned as the UDP payload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::NotNegotiated`] if HTTP/3 Datagrams have not been
    /// negotiated for this association.
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::MismatchedStreamId`] if the datagram is not
    /// addressed to this association's request stream.
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::InvalidContextId`] if the Context ID is missing,
    /// malformed, or not the default context (0).
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::PayloadTooLarge`] if the decoded UDP payload
    /// exceeds the address-family UDP payload limit.
    pub fn decode_h3_datagram(&self, datagram: HttpDatagram) -> Result<Vec<u8>> {
        self.ensure_h3_datagrams_enabled()?;
        if datagram.stream_id() != self.stream_id {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::MismatchedStreamId,
                "datagram is not addressed to this association's request stream",
            ));
        }
        let payload = datagram.into_payload();
        let (context_id, consumed) = crate::quic_varint::decode(&payload).map_err(|e| {
            Error::h3_datagram_error_with_source(
                H3DatagramErrorKind::InvalidContextId,
                "failed to decode CONNECT-UDP Context ID",
                e,
            )
        })?;
        if context_id != 0 {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::InvalidContextId,
                format!("unsupported CONNECT-UDP Context ID {context_id}, expected 0"),
            ));
        }
        if consumed != 1 {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::InvalidContextId,
                "CONNECT-UDP Context ID 0 must use the canonical 1-byte varint encoding",
            ));
        }
        let udp_payload = &payload[consumed..];
        let max = max_payload_for_addr(self.target);
        if udp_payload.len() > max {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::PayloadTooLarge,
                format!(
                    "decoded UDP payload length {} exceeds maximum UDP payload size {} for {}",
                    udp_payload.len(),
                    max,
                    self.target.ip()
                ),
            ));
        }
        Ok(udp_payload.to_vec())
    }

    /// Encode an outbound UDP payload as a `DATAGRAM` capsule on this
    /// association's request stream.
    ///
    /// The UDP payload is framed with the CONNECT-UDP default Context ID (0)
    /// encoded as a QUIC variable-length integer, per RFC 9298 Section 8.2, then
    /// wrapped in a [`DatagramCapsule`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if `payload` exceeds the address-family
    /// UDP payload limit.
    pub fn encode_datagram_capsule(&self, payload: impl Into<Vec<u8>>) -> Result<DatagramCapsule> {
        let payload = payload.into();
        let max = max_payload_for_addr(self.target);
        if payload.len() > max {
            return Err(Error::InvalidConfig {
                field: "payload",
                message: format!(
                    "payload length {} exceeds maximum UDP payload size {} for {}",
                    payload.len(),
                    max,
                    self.target.ip()
                ),
            });
        }
        let mut framed = payload;
        framed.insert(0, 0x00);
        let datagram = HttpDatagram::new(self.stream_id, framed)?;
        Ok(DatagramCapsule::new(datagram))
    }

    /// Decode an inbound `DATAGRAM` capsule into a UDP payload to forward to the
    /// target.
    ///
    /// The CONNECT-UDP Context ID is parsed from the start of the capsule value
    /// and must be the default context (0). The remaining bytes are returned as
    /// the UDP payload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::MismatchedStreamId`] if the capsule is not
    /// addressed to this association's request stream.
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::InvalidContextId`] if the Context ID is missing,
    /// malformed, or not the default context (0).
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::PayloadTooLarge`] if the decoded UDP payload
    /// exceeds the address-family UDP payload limit.
    pub fn decode_datagram_capsule(&self, capsule: DatagramCapsule) -> Result<Vec<u8>> {
        let datagram = capsule.into_datagram();
        if datagram.stream_id() != self.stream_id {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::MismatchedStreamId,
                "datagram capsule is not addressed to this association's request stream",
            ));
        }
        let payload = datagram.into_payload();
        let (context_id, consumed) = crate::quic_varint::decode(&payload).map_err(|e| {
            Error::h3_datagram_error_with_source(
                H3DatagramErrorKind::InvalidContextId,
                "failed to decode CONNECT-UDP Context ID",
                e,
            )
        })?;
        if context_id != 0 {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::InvalidContextId,
                format!("unsupported CONNECT-UDP Context ID {context_id}, expected 0"),
            ));
        }
        if consumed != 1 {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::InvalidContextId,
                "CONNECT-UDP Context ID 0 must use the canonical 1-byte varint encoding",
            ));
        }
        let udp_payload = &payload[consumed..];
        let max = max_payload_for_addr(self.target);
        if udp_payload.len() > max {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::PayloadTooLarge,
                format!(
                    "decoded UDP payload length {} exceeds maximum UDP payload size {} for {}",
                    udp_payload.len(),
                    max,
                    self.target.ip()
                ),
            ));
        }
        Ok(udp_payload.to_vec())
    }

    /// Return the local socket address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the local address cannot be retrieved or
    /// if the association has been closed.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            Error::transport_error(TransportKind::UdpLocalAddr, "association is closed", None)
        })?;
        socket.local_addr().map_err(|e| {
            Error::transport_error(
                TransportKind::UdpLocalAddr,
                "failed to get local address",
                Some(Box::new(e)),
            )
        })
    }

    /// Return the target UDP address.
    #[must_use]
    pub const fn target_addr(&self) -> SocketAddr {
        self.target
    }

    /// Return the session context.
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// Send a UDP payload to the target.
    ///
    /// `payload` must fit in a single UDP datagram. The maximum supported size
    /// depends on the target address family:
    ///
    /// - IPv4: [`MAX_UDP_PAYLOAD_IPV4`] bytes
    /// - IPv6: [`MAX_UDP_PAYLOAD_IPV6`] bytes
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if `payload` exceeds the address-family
    /// limit.
    ///
    /// Returns [`Error::Transport`] if the association has been closed or the
    /// datagram cannot be sent.
    pub async fn send(&self, payload: &[u8]) -> Result<usize> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            Error::transport_error(TransportKind::UdpSend, "association is closed", None)
        })?;

        let max = max_payload_for_addr(self.target);
        if payload.len() > max {
            return Err(Error::InvalidConfig {
                field: "payload",
                message: format!(
                    "payload length {} exceeds maximum UDP payload size {} for {}",
                    payload.len(),
                    max,
                    self.target.ip()
                ),
            });
        }
        socket.send(payload).await.map_err(|e| {
            Error::transport_error(
                TransportKind::UdpSend,
                "failed to send UDP datagram",
                Some(Box::new(e)),
            )
        })
    }

    /// Receive a UDP payload from the target into the provided buffer.
    ///
    /// On success, returns the number of bytes written to `buf`. If the
    /// received datagram is larger than `buf`, the behavior depends on the
    /// platform: on Unix-like systems the portion that fits is written and the
    /// remainder is discarded without error, while on Windows a
    /// `WSAEMSGSIZE` error is returned. Use a buffer of at least
    /// [`MAX_UDP_PAYLOAD`] to avoid truncation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the association has been closed or
    /// receiving fails.
    pub async fn recv_into(&self, buf: &mut [u8]) -> Result<usize> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            Error::transport_error(TransportKind::UdpRecv, "association is closed", None)
        })?;
        socket.recv(buf).await.map_err(|e| {
            Error::transport_error(
                TransportKind::UdpRecv,
                "failed to receive UDP datagram",
                Some(Box::new(e)),
            )
        })
    }

    /// Receive a UDP payload from the target.
    ///
    /// This is a convenience wrapper around [`Self::recv_into`] that allocates
    /// a buffer of [`MAX_UDP_PAYLOAD`] bytes. Datagrams larger than that may be
    /// truncated depending on the platform; see [`Self::recv_into`] for
    /// details.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the association has been closed or
    /// receiving fails.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        let n = self.recv_into(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Close the UDP socket and invalidate the association.
    ///
    /// After closing, subsequent `send`/`recv` calls return a
    /// [`TransportKind::UdpSend`] / [`TransportKind::UdpRecv`] error.
    pub fn close(&mut self) {
        let _ = self.socket.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::H3DatagramSettingValue;

    fn test_stream_id() -> u64 {
        12
    }

    fn test_session() -> Session {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        session
    }

    #[tokio::test]
    async fn association_stores_request_stream_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(7).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        assert_eq!(assoc.request_stream_id(), test_stream_id());
    }

    #[tokio::test]
    async fn encode_h3_datagram_succeeds_when_enabled() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = b"hello";
        let datagram = assoc.encode_h3_datagram(payload.as_slice()).unwrap();

        assert_eq!(datagram.stream_id(), test_stream_id());
        // RFC 9298 prefixes the UDP payload with the default Context ID (0).
        assert_eq!(datagram.payload(), &[0x00, b'h', b'e', b'l', b'l', b'o']);

        let encoded = datagram.encode_h3();
        let decoded = HttpDatagram::decode_h3(&encoded).unwrap();
        assert_eq!(decoded.stream_id(), test_stream_id());
        assert_eq!(
            assoc.decode_h3_datagram(decoded).unwrap(),
            payload.as_slice()
        );
    }

    #[tokio::test]
    async fn encode_h3_datagram_fails_when_disabled() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();

        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            session,
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let err = assoc.encode_h3_datagram(b"hello").unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::NotNegotiated,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn encode_h3_datagram_rejects_oversized_payload() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = vec![0u8; MAX_UDP_PAYLOAD_IPV4 + 1];
        let err = assoc.encode_h3_datagram(payload).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConfig {
                field: "payload",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn encode_h3_datagram_round_trips_empty_payload() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let datagram = assoc.encode_h3_datagram(Vec::new()).unwrap();
        assert_eq!(datagram.stream_id(), test_stream_id());
        // Empty UDP payload still carries the default Context ID (0) prefix.
        assert_eq!(datagram.payload(), &[0x00]);

        let decoded = assoc.decode_h3_datagram(datagram).unwrap();
        assert_eq!(decoded, &[]);
    }

    #[tokio::test]
    async fn decode_h3_datagram_succeeds_when_enabled() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = b"hello";
        let mut framed = vec![0x00];
        framed.extend_from_slice(payload);
        let datagram = HttpDatagram::new(test_stream_id(), framed).unwrap();
        let decoded = assoc.decode_h3_datagram(datagram).unwrap();

        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn decode_h3_datagram_fails_when_disabled() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();

        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            session,
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let datagram =
            HttpDatagram::new(test_stream_id(), [0x00, b'h', b'e', b'l', b'l', b'o']).unwrap();
        let err = assoc.decode_h3_datagram(datagram).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::NotNegotiated,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_h3_datagram_rejects_oversized_payload() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let mut payload = vec![0x00];
        payload.extend_from_slice(&vec![0u8; MAX_UDP_PAYLOAD_IPV4 + 1]);
        let datagram = HttpDatagram::new(test_stream_id(), payload).unwrap();
        let err = assoc.decode_h3_datagram(datagram).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::PayloadTooLarge,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_h3_datagram_fails_for_mismatched_stream_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let datagram = HttpDatagram::new(test_stream_id() + 4, b"hello").unwrap();
        let err = assoc.decode_h3_datagram(datagram).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::MismatchedStreamId,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_h3_datagram_rejects_missing_context_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let datagram = HttpDatagram::new(test_stream_id(), Vec::new()).unwrap();
        let err = assoc.decode_h3_datagram(datagram).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::InvalidContextId,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_h3_datagram_rejects_nonzero_context_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let datagram = HttpDatagram::new(test_stream_id(), [0x01, b'x']).unwrap();
        let err = assoc.decode_h3_datagram(datagram).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::InvalidContextId,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_h3_datagram_rejects_truncated_context_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        // 0x40 signals a 2-byte varint, but the second byte is missing.
        let datagram = HttpDatagram::new(test_stream_id(), [0x40]).unwrap();
        let err = assoc.decode_h3_datagram(datagram).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::InvalidContextId,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_h3_datagram_rejects_noncanonical_zero_context_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        // 0x40 0x00 is a valid 2-byte varint representing 0, but QUIC varints
        // are required to use the shortest encoding, so it must be rejected.
        let datagram = HttpDatagram::new(test_stream_id(), [0x40, 0x00, b'x']).unwrap();
        let err = assoc.decode_h3_datagram(datagram).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::InvalidContextId,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_rejects_non_client_bidirectional_stream_id() {
        let result = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            test_session(),
            AssociationId::new(1).unwrap(),
            1,
        )
        .await;

        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidConfig {
                field: "stream_id",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_accepts_minimum_request_stream_id() {
        let result = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            test_session(),
            AssociationId::new(1).unwrap(),
            0,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn association_accepts_maximum_valid_request_stream_id() {
        let max_valid = crate::quic_varint::MAX_VARINT - 3;
        assert_eq!(max_valid % 4, 0);

        let result = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            test_session(),
            AssociationId::new(1).unwrap(),
            max_valid,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn association_rejects_request_stream_id_above_max() {
        // Use a value that is a multiple of 4 but exceeds the QUIC varint
        // range, so the test isolates the varint-range check.
        let result = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            test_session(),
            AssociationId::new(1).unwrap(),
            crate::quic_varint::MAX_VARINT + 4,
        )
        .await;

        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidConfig {
                field: "stream_id",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_rejects_max_varint_stream_id_due_to_modulo() {
        // MAX_VARINT is within the varint range but is not a multiple of 4,
        // so it must be rejected as a non-client-bidirectional stream ID.
        let result = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            test_session(),
            AssociationId::new(1).unwrap(),
            crate::quic_varint::MAX_VARINT,
        )
        .await;

        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidConfig {
                field: "stream_id",
                ..
            }
        ));
    }

    #[test]
    fn association_id_validates_varint_range() {
        let max = AssociationId::max_value();
        assert!(AssociationId::new(max).is_ok());
        assert!(AssociationId::new(max + 1).is_err());
    }

    #[test]
    fn association_id_display_formats_raw_value() {
        assert_eq!(AssociationId::new(7).unwrap().to_string(), "7");
    }

    #[tokio::test]
    async fn association_binds_and_exposes_addresses() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            test_session(),
            AssociationId::new(7).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        assert_eq!(assoc.id(), AssociationId::new(7).unwrap());
        assert_eq!(assoc.target_addr(), target);
        assert!(assoc.local_addr().unwrap().ip().is_loopback());
        assert!(assoc.session().is_h3_datagram_enabled());
    }

    #[tokio::test]
    async fn association_rejects_non_connect_udp_session() {
        let result = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            Session::new(Protocol::ConnectIp),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await;
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidConfig {
                field: "session",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_rejects_duplicate_bind_address() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let first = UdpSocket::bind(addr).await.unwrap();
        let occupied = first.local_addr().unwrap();

        let result = UdpAssociation::bind(
            occupied,
            "127.0.0.1:1".parse().unwrap(),
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await;
        assert!(matches!(
            result.unwrap_err(),
            Error::Transport {
                kind: TransportKind::UdpBind,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_rejects_address_family_mismatch_on_connect() {
        let result = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            "[::1]:53".parse().unwrap(),
            test_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await;
        assert!(matches!(
            result.unwrap_err(),
            Error::Transport {
                kind: TransportKind::UdpConnect,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_echoes_udp_datagram() {
        let session = test_session();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            listener_addr,
            session,
            AssociationId::new(42).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = b"hello association";
        let sent = assoc.send(payload).await.unwrap();
        assert_eq!(sent, payload.len());

        let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
        let (n, peer) = listener.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload);

        let reply = b"reply";
        listener.send_to(reply, peer).await.unwrap();

        let received = assoc.recv().await.unwrap();
        assert_eq!(received, reply);
    }

    #[tokio::test]
    async fn association_send_accepts_empty_payload() {
        let session = test_session();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            listener_addr,
            session,
            AssociationId::new(42).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let sent = assoc.send(b"").await.unwrap();
        assert_eq!(sent, 0);
    }

    #[tokio::test]
    async fn association_send_rejects_ipv4_oversized_payload() {
        let session = test_session();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            listener_addr,
            session,
            AssociationId::new(42).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = vec![0u8; MAX_UDP_PAYLOAD_IPV4 + 1];
        let err = assoc.send(&payload).await.unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConfig {
                field: "payload",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_send_rejects_ipv6_oversized_payload() {
        let session = test_session();
        let listener = UdpSocket::bind("[::1]:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let assoc = UdpAssociation::bind(
            "[::1]:0".parse().unwrap(),
            listener_addr,
            session,
            AssociationId::new(42).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = vec![0u8; MAX_UDP_PAYLOAD_IPV6 + 1];
        let err = assoc.send(&payload).await.unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConfig {
                field: "payload",
                ..
            }
        ));
    }

    #[test]
    fn max_payload_for_addr_matches_address_family() {
        assert_eq!(
            max_payload_for_addr("127.0.0.1:1".parse().unwrap()),
            MAX_UDP_PAYLOAD_IPV4
        );
        assert_eq!(
            max_payload_for_addr("[::1]:1".parse().unwrap()),
            MAX_UDP_PAYLOAD_IPV6
        );
    }

    #[tokio::test]
    async fn association_send_returns_error_after_close() {
        let session = test_session();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let mut assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            listener_addr,
            session,
            AssociationId::new(42).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        assoc.close();

        let err = assoc.send(b"ping").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Transport {
                kind: TransportKind::UdpSend,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_recv_returns_error_after_close() {
        let session = test_session();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let mut assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            listener_addr,
            session,
            AssociationId::new(42).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        assoc.close();

        let mut buf = [0u8; 64];
        let err = assoc.recv_into(&mut buf).await.unwrap_err();
        assert!(matches!(
            err,
            Error::Transport {
                kind: TransportKind::UdpRecv,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn association_recv_into_reuses_buffer() {
        let session = test_session();
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            listener_addr,
            session,
            AssociationId::new(42).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = b"recv_into";
        listener
            .send_to(payload, assoc.local_addr().unwrap())
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let n = assoc.recv_into(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload);
    }

    fn capsule_only_session() -> Session {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        session.set_local_capsule_protocol(true).unwrap();
        session.negotiate_peer_capsule_protocol(true).unwrap();
        session
    }

    #[tokio::test]
    async fn encode_datagram_capsule_round_trips_payload() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            capsule_only_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = b"hello";
        let capsule = assoc.encode_datagram_capsule(payload.as_slice()).unwrap();
        let decoded = assoc.decode_datagram_capsule(capsule).unwrap();
        assert_eq!(decoded, payload.as_slice());
    }

    #[tokio::test]
    async fn encode_datagram_capsule_round_trips_empty_payload() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            capsule_only_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let capsule = assoc.encode_datagram_capsule(Vec::new()).unwrap();
        let decoded = assoc.decode_datagram_capsule(capsule).unwrap();
        assert_eq!(decoded, &[]);
    }

    #[tokio::test]
    async fn encode_datagram_capsule_rejects_oversized_payload() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            capsule_only_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let payload = vec![0u8; MAX_UDP_PAYLOAD_IPV4 + 1];
        let err = assoc.encode_datagram_capsule(payload).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConfig {
                field: "payload",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_datagram_capsule_rejects_mismatched_stream_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            capsule_only_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let datagram = HttpDatagram::new(test_stream_id() + 4, vec![0x00, b'x']).unwrap();
        let capsule = DatagramCapsule::new(datagram);
        let err = assoc.decode_datagram_capsule(capsule).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::MismatchedStreamId,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_datagram_capsule_rejects_nonzero_context_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            capsule_only_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let datagram = HttpDatagram::new(test_stream_id(), vec![0x01, b'x']).unwrap();
        let capsule = DatagramCapsule::new(datagram);
        let err = assoc.decode_datagram_capsule(capsule).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::InvalidContextId,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn decode_datagram_capsule_rejects_missing_context_id() {
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let assoc = UdpAssociation::bind(
            "127.0.0.1:0".parse().unwrap(),
            target,
            capsule_only_session(),
            AssociationId::new(1).unwrap(),
            test_stream_id(),
        )
        .await
        .unwrap();

        let datagram = HttpDatagram::new(test_stream_id(), Vec::new()).unwrap();
        let capsule = DatagramCapsule::new(datagram);
        let err = assoc.decode_datagram_capsule(capsule).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::InvalidContextId,
                ..
            }
        ));
    }
}
