//! Core types used by MASQUE protocols.

use std::fmt;

use crate::settings::{H3DatagramSettingValue, SETTINGS_H3_DATAGRAM};
use crate::{Error, H3DatagramErrorKind, Result};

/// Identifies a MASQUE target protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protocol {
    /// CONNECT-UDP as defined in RFC 9298.
    ConnectUdp,

    /// CONNECT-IP draft.
    ConnectIp,

    /// CONNECT-Ethernet draft.
    ConnectEthernet,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::ConnectUdp => write!(f, "connect-udp"),
            Protocol::ConnectIp => write!(f, "connect-ip"),
            Protocol::ConnectEthernet => write!(f, "connect-ethernet"),
        }
    }
}

/// The carrier used to transport UDP payloads for a CONNECT-UDP association.
///
/// `Session::select_udp_carrier` returns this value based on negotiated
/// capabilities. Callers then invoke the matching `UdpAssociation` encode/decode
/// method for the selected carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpCarrier {
    /// UDP payloads are carried in HTTP/3 Datagram frames.
    H3Datagram,
    /// UDP payloads are carried as `DATAGRAM` capsules on the request stream.
    DatagramCapsule,
}

/// Negotiated capabilities for a MASQUE session.
///
/// Keeping related HTTP/3 capability state in a dedicated inner type lets
/// `Session` grow without turning into an unstructured bag of fields and
/// keeps the public `Session` shape stable.
///
/// `Option<H3DatagramSettingValue>` encodes the invariant that each direction's
/// `SETTINGS_H3_DATAGRAM` value is recorded at most once: `None` means not yet
/// negotiated, and `Some(value)` means the value has been finalized.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NegotiatedCaps {
    /// The local endpoint's advertised `SETTINGS_H3_DATAGRAM` value, if any.
    local_h3_datagram: Option<H3DatagramSettingValue>,
    /// The peer endpoint's advertised `SETTINGS_H3_DATAGRAM` value, if any.
    peer_h3_datagram: Option<H3DatagramSettingValue>,
    /// The local endpoint's advertised `Capsule-Protocol` value, if any.
    local_capsule_protocol: Option<bool>,
    /// The peer endpoint's advertised `Capsule-Protocol` value, if any.
    peer_capsule_protocol: Option<bool>,
}

/// A MASQUE session context.
///
/// `Session` tracks the target protocol and negotiated HTTP/3 capabilities
/// (currently HTTP/3 Datagram support per RFC 9297). New negotiated state
/// should be added inside the internal `NegotiatedCaps` type rather than
/// appended directly to this struct.
///
/// # Equality semantics
///
/// Two sessions compare equal only when both their protocol and their
/// negotiated capabilities match.
///
/// # Concurrency note
///
/// This type uses `&mut self` for all state changes. It is designed to be
/// owned by a single task; callers that need to share it across tasks or
/// async boundaries should wrap it in their own synchronization primitive
/// (e.g., `Mutex`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    protocol: Protocol,
    caps: NegotiatedCaps,
}

impl Session {
    /// Create a new session for the given protocol.
    ///
    /// The session starts with all negotiated capabilities unset.
    #[must_use]
    pub const fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            caps: NegotiatedCaps {
                local_h3_datagram: None,
                peer_h3_datagram: None,
                local_capsule_protocol: None,
                peer_capsule_protocol: None,
            },
        }
    }

    /// Return the protocol associated with this session.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Return whether HTTP/3 Datagrams are fully negotiated for this session.
    ///
    /// Per RFC 9297 Section 2.1.1, this returns `true` only when **both**
    /// endpoints have sent `SETTINGS_H3_DATAGRAM` with a value of `1`.
    #[must_use]
    pub const fn is_h3_datagram_enabled(&self) -> bool {
        match (self.caps.local_h3_datagram, self.caps.peer_h3_datagram) {
            (Some(local), Some(peer)) => local.is_enabled() && peer.is_enabled(),
            _ => false,
        }
    }

    /// Record the local endpoint's advertised `SETTINGS_H3_DATAGRAM` value.
    ///
    /// This should be called once after the local HTTP/3 SETTINGS frame has
    /// been sent. Because HTTP/3 SETTINGS are sent once per connection and
    /// duplicate setting identifiers are not allowed, any second call is
    /// rejected as a conflict even if the value is identical.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3SettingsConflict`] if the local setting has already
    /// been recorded.
    pub fn set_local_h3_datagram(&mut self, value: H3DatagramSettingValue) -> Result<()> {
        if let Some(previous) = self.caps.local_h3_datagram {
            return Err(Error::H3SettingsConflict {
                setting: SETTINGS_H3_DATAGRAM,
                previous: previous.get(),
                received: value.get(),
            });
        }
        self.caps.local_h3_datagram = Some(value);
        Ok(())
    }

    /// Apply a peer `SETTINGS_H3_DATAGRAM` value received from the remote endpoint.
    ///
    /// Records the peer advertisement. Because HTTP/3 SETTINGS are sent once
    /// per connection and duplicate setting identifiers are not allowed, any
    /// second call is rejected as a conflict even if the value is identical.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3SettingsConflict`] if the peer setting has already
    /// been recorded.
    pub fn negotiate_peer_h3_datagram(&mut self, value: H3DatagramSettingValue) -> Result<()> {
        if let Some(previous) = self.caps.peer_h3_datagram {
            return Err(Error::H3SettingsConflict {
                setting: SETTINGS_H3_DATAGRAM,
                previous: previous.get(),
                received: value.get(),
            });
        }
        self.caps.peer_h3_datagram = Some(value);
        Ok(())
    }

    /// Record the local endpoint's advertised `Capsule-Protocol` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CapsuleProtocolConflict`] if the local value has already
    /// been recorded.
    pub fn set_local_capsule_protocol(&mut self, enabled: bool) -> Result<()> {
        if let Some(previous) = self.caps.local_capsule_protocol {
            return Err(Error::CapsuleProtocolConflict {
                previous,
                received: enabled,
            });
        }
        self.caps.local_capsule_protocol = Some(enabled);
        Ok(())
    }

    /// Apply a peer `Capsule-Protocol` value received from the remote endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CapsuleProtocolConflict`] if the peer value has already
    /// been recorded.
    pub fn negotiate_peer_capsule_protocol(&mut self, enabled: bool) -> Result<()> {
        if let Some(previous) = self.caps.peer_capsule_protocol {
            return Err(Error::CapsuleProtocolConflict {
                previous,
                received: enabled,
            });
        }
        self.caps.peer_capsule_protocol = Some(enabled);
        Ok(())
    }

    /// Return whether DATAGRAM capsules are enabled for this session.
    ///
    /// This is `true` only when HTTP/3 Datagrams are not enabled and both
    /// endpoints have agreed to `Capsule-Protocol: ?1`.
    #[must_use]
    pub(crate) fn is_datagram_capsule_enabled(&self) -> bool {
        !self.is_h3_datagram_enabled()
            && matches!(
                (
                    self.caps.local_capsule_protocol,
                    self.caps.peer_capsule_protocol
                ),
                (Some(true), Some(true))
            )
    }

    /// Select the carrier to use for UDP payload transport.
    ///
    /// HTTP/3 Datagrams are preferred when available. If not, DATAGRAM capsules
    /// are selected when negotiated. Otherwise returns
    /// [`Error::H3DatagramError`] with kind [`H3DatagramErrorKind::NotNegotiated`].
    pub fn select_udp_carrier(&self) -> Result<UdpCarrier> {
        if self.is_h3_datagram_enabled() {
            Ok(UdpCarrier::H3Datagram)
        } else if self.is_datagram_capsule_enabled() {
            Ok(UdpCarrier::DatagramCapsule)
        } else {
            Err(Error::h3_datagram_error(
                H3DatagramErrorKind::NotNegotiated,
                "no UDP transport carrier is negotiated for this session",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::ConnectUdp.to_string(), "connect-udp");
        assert_eq!(Protocol::ConnectIp.to_string(), "connect-ip");
        assert_eq!(Protocol::ConnectEthernet.to_string(), "connect-ethernet");
    }

    #[test]
    fn session_stores_all_protocol_variants() {
        for protocol in [
            Protocol::ConnectUdp,
            Protocol::ConnectIp,
            Protocol::ConnectEthernet,
        ] {
            let session = Session::new(protocol);
            assert_eq!(session.protocol(), protocol);
        }
    }

    #[test]
    fn session_starts_without_h3_datagram_enabled() {
        let session = Session::new(Protocol::ConnectUdp);
        assert!(!session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_reports_h3_datagram_enabled_only_when_both_sides_agree() {
        let mut session = Session::new(Protocol::ConnectUdp);

        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert!(!session.is_h3_datagram_enabled());

        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert!(session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_reports_disabled_when_either_side_disables() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        assert!(!session.is_h3_datagram_enabled());

        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert!(!session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_negotiates_peer_h3_datagram_with_zero() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        assert!(!session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_negotiates_peer_h3_datagram_with_one() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert!(!session.is_h3_datagram_enabled());

        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert!(session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_rejects_duplicate_local_setting() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        let err = session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap_err();
        assert!(matches!(
            err,
            Error::H3SettingsConflict {
                setting: SETTINGS_H3_DATAGRAM,
                previous: 1,
                received: 1,
            }
        ));
    }

    #[test]
    fn session_rejects_duplicate_peer_negotiation() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        let err = session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap_err();
        assert!(matches!(
            err,
            Error::H3SettingsConflict {
                setting: SETTINGS_H3_DATAGRAM,
                previous: 0,
                received: 0,
            }
        ));
    }

    #[test]
    fn session_rejects_conflicting_local_setting() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        let err = session
            .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap_err();
        assert!(matches!(
            err,
            Error::H3SettingsConflict {
                setting: SETTINGS_H3_DATAGRAM,
                previous: 1,
                received: 0,
            }
        ));
    }

    #[test]
    fn session_rejects_conflicting_peer_negotiation() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        let err = session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap_err();
        assert!(matches!(
            err,
            Error::H3SettingsConflict {
                setting: SETTINGS_H3_DATAGRAM,
                previous: 1,
                received: 0,
            }
        ));
        assert_eq!(
            err.to_string(),
            "HTTP/3 setting 0x33 already negotiated with value 1; received conflicting value 0"
        );
    }

    #[test]
    fn session_negotiation_preserves_enabled_state_on_duplicate_value() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert!(session.is_h3_datagram_enabled());

        let err = session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap_err();
        assert!(matches!(
            err,
            Error::H3SettingsConflict {
                setting: SETTINGS_H3_DATAGRAM,
                previous: 1,
                received: 0,
            }
        ));
        assert!(session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_equality_depends_on_protocol_and_caps() {
        let s1 = Session::new(Protocol::ConnectUdp);
        let mut s2 = Session::new(Protocol::ConnectUdp);
        assert_eq!(s1, s2);

        s2.set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert_ne!(s1, s2);

        let mut s3 = Session::new(Protocol::ConnectUdp);
        s3.negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert_ne!(s2, s3);
    }

    #[test]
    fn session_accepts_validated_setting_values_only() {
        // Ensures the public Session API consumes H3DatagramSettingValue rather
        // than raw u64, so the RFC 9297 0/1 constraint is enforced at the type
        // level for both local and peer settings.
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert!(session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_selects_h3_datagram_when_enabled() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
            .unwrap();
        assert_eq!(
            session.select_udp_carrier().unwrap(),
            UdpCarrier::H3Datagram
        );
    }

    #[test]
    fn session_selects_datagram_capsule_when_h3_disabled_and_capsule_protocol_enabled() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session
            .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        session
            .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
            .unwrap();
        session.set_local_capsule_protocol(true).unwrap();
        session.negotiate_peer_capsule_protocol(true).unwrap();
        assert_eq!(
            session.select_udp_carrier().unwrap(),
            UdpCarrier::DatagramCapsule
        );
    }

    #[test]
    fn session_select_udp_carrier_fails_when_nothing_enabled() {
        let session = Session::new(Protocol::ConnectUdp);
        let err = session.select_udp_carrier().unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::NotNegotiated,
                ..
            }
        ));
    }

    #[test]
    fn session_rejects_conflicting_local_capsule_protocol() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session.set_local_capsule_protocol(true).unwrap();
        let err = session.set_local_capsule_protocol(false).unwrap_err();
        assert!(matches!(
            err,
            Error::CapsuleProtocolConflict {
                previous: true,
                received: false,
            }
        ));
    }

    #[test]
    fn session_rejects_conflicting_peer_capsule_protocol() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session.negotiate_peer_capsule_protocol(true).unwrap();
        let err = session.negotiate_peer_capsule_protocol(false).unwrap_err();
        assert!(matches!(
            err,
            Error::CapsuleProtocolConflict {
                previous: true,
                received: false,
            }
        ));
    }
}
