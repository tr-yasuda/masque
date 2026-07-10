//! UDP association management for CONNECT-UDP.
//!
//! A [`UdpAssociation`] represents the binding between a CONNECT-UDP request
//! stream and a local UDP socket connected to the target. It carries an
//! [`AssociationId`] that can be used to correlate HTTP/3 Datagrams with this
//! association, and a [`Session`] that records negotiated HTTP/3 capabilities.
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
use crate::{Error, Result, Session, TransportKind};

/// A context identifier for a UDP association.
///
/// RFC 9298 Section 8.2 uses a Context ID encoded as a QUIC variable-length
/// integer. This newtype wraps the identifier value and enforces the QUIC
/// varint range (`0..=2^62 - 1`) at construction time.
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
}

impl UdpAssociation {
    /// Bind a local UDP socket and connect it to the target.
    ///
    /// `local` is the address to bind locally. `target` is the remote UDP
    /// endpoint. `session` records the negotiated MASQUE capabilities. `id` is
    /// the association context identifier used to correlate datagrams.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if `session` is not for
    /// [`Protocol::ConnectUdp`].
    ///
    /// Returns [`Error::Transport`] if binding the local socket
    /// ([`TransportKind::UdpBind`]) or connecting to the target
    /// ([`TransportKind::UdpConnect`]) fails.
    pub async fn bind(
        local: SocketAddr,
        target: SocketAddr,
        session: Session,
        id: AssociationId,
    ) -> Result<Self> {
        if session.protocol() != Protocol::ConnectUdp {
            return Err(Error::InvalidConfig {
                field: "session",
                message: "protocol must be connect-udp".into(),
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
        })
    }

    /// Return the association identifier.
    #[must_use]
    pub const fn id(&self) -> AssociationId {
        self.id
    }

    /// Return the local socket address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the local address cannot be retrieved or
    /// if the association has been closed.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            Error::transport_error(TransportKind::UdpBind, "association is closed", None)
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

        let socket = self.socket.as_ref().ok_or_else(|| {
            Error::transport_error(TransportKind::UdpSend, "association is closed", None)
        })?;
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
    /// received datagram is larger than `buf`, the portion that fits is written
    /// and the remainder is discarded by the OS; no truncation error is
    /// returned on all platforms.
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
    /// a buffer of [`MAX_UDP_PAYLOAD`] bytes. Datagrams larger than that are
    /// truncated by the OS; only the portion that fits is returned.
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
}
