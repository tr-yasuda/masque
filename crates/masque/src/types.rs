//! Core types used by MASQUE protocols.

use std::fmt;

use crate::Result;
use crate::settings::SETTINGS_H3_DATAGRAM;

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

/// Negotiated capabilities for a MASQUE session.
///
/// Keeping related HTTP/3 capability state in a dedicated inner type lets
/// `Session` grow without turning into an unstructured bag of fields and
/// keeps the public `Session` shape stable.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NegotiatedCaps {
    /// Whether the local endpoint advertised `SETTINGS_H3_DATAGRAM = 1`.
    local_h3_datagram: bool,
    /// Whether the peer sent `SETTINGS_H3_DATAGRAM = 1`.
    peer_h3_datagram: bool,
    /// Whether a peer `SETTINGS_H3_DATAGRAM` value has already been processed.
    peer_h3_datagram_negotiated: bool,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    protocol: Protocol,
    caps: NegotiatedCaps,
}

impl Session {
    /// Create a new session for the given protocol.
    ///
    /// The session starts with all negotiated capabilities disabled.
    #[must_use]
    pub const fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            caps: NegotiatedCaps {
                local_h3_datagram: false,
                peer_h3_datagram: false,
                peer_h3_datagram_negotiated: false,
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
        self.caps.local_h3_datagram && self.caps.peer_h3_datagram
    }

    /// Record whether the local endpoint advertised `SETTINGS_H3_DATAGRAM = 1`.
    ///
    /// This should be called after the local HTTP/3 SETTINGS frame has been
    /// sent. It does not validate the value; the caller is responsible for
    /// sending only `0` or `1`.
    pub fn set_local_h3_datagram(&mut self, enabled: bool) {
        self.caps.local_h3_datagram = enabled;
    }

    /// Apply a peer `SETTINGS_H3_DATAGRAM` value received from the remote endpoint.
    ///
    /// Validates that `value` is `0` or `1`, records the peer advertisement,
    /// and rejects any later call that would change the already-negotiated
    /// value, since HTTP/3 SETTINGS are sent only once per connection.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::H3Settings`] if `value` is not `0` or `1`.
    /// Returns [`crate::Error::H3SettingsConflict`] if the setting has already
    /// been negotiated with a different value.
    pub fn negotiate_peer_h3_datagram(&mut self, value: u64) -> Result<()> {
        crate::settings::validate_h3_datagram_setting_value(value)?;
        let enabled = value == 1;
        if self.caps.peer_h3_datagram_negotiated && self.caps.peer_h3_datagram != enabled {
            return Err(crate::Error::H3SettingsConflict {
                setting: SETTINGS_H3_DATAGRAM,
                previous: if self.caps.peer_h3_datagram { 1 } else { 0 },
                received: value,
            });
        }
        self.caps.peer_h3_datagram = enabled;
        self.caps.peer_h3_datagram_negotiated = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::settings::{SETTINGS_H3_DATAGRAM, validate_h3_datagram_setting_value};

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

        session.set_local_h3_datagram(true);
        assert!(!session.is_h3_datagram_enabled());

        session.negotiate_peer_h3_datagram(1).unwrap();
        assert!(session.is_h3_datagram_enabled());

        session.set_local_h3_datagram(false);
        assert!(!session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_negotiates_peer_h3_datagram_with_zero() {
        let mut session = Session::new(Protocol::ConnectUdp);
        assert!(session.negotiate_peer_h3_datagram(0).is_ok());
        assert!(!session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_negotiates_peer_h3_datagram_with_one() {
        let mut session = Session::new(Protocol::ConnectUdp);
        assert!(session.negotiate_peer_h3_datagram(1).is_ok());
        assert!(!session.is_h3_datagram_enabled());

        session.set_local_h3_datagram(true);
        assert!(session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_rejects_invalid_peer_h3_datagram_value() {
        let mut session = Session::new(Protocol::ConnectUdp);
        let err = session.negotiate_peer_h3_datagram(2).unwrap_err();
        assert!(matches!(
            err,
            Error::H3Settings {
                setting: SETTINGS_H3_DATAGRAM,
                value: 2,
            }
        ));
        assert_eq!(
            err.to_string(),
            "invalid HTTP/3 setting 0x33: value must be 0 or 1, got 2"
        );
        assert!(!session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_negotiation_preserves_enabled_state_on_invalid_value() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session.set_local_h3_datagram(true);
        session.negotiate_peer_h3_datagram(1).unwrap();
        assert!(session.is_h3_datagram_enabled());

        let err = session.negotiate_peer_h3_datagram(2).unwrap_err();
        assert!(matches!(
            err,
            Error::H3Settings {
                setting: SETTINGS_H3_DATAGRAM,
                value: 2,
            }
        ));
        assert!(session.is_h3_datagram_enabled());
    }

    #[test]
    fn session_allows_idempotent_peer_negotiation() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session.negotiate_peer_h3_datagram(1).unwrap();
        assert!(session.negotiate_peer_h3_datagram(1).is_ok());
        assert!(session.negotiate_peer_h3_datagram(0).is_err());
    }

    #[test]
    fn session_rejects_conflicting_peer_negotiation() {
        let mut session = Session::new(Protocol::ConnectUdp);
        session.negotiate_peer_h3_datagram(1).unwrap();
        let err = session.negotiate_peer_h3_datagram(0).unwrap_err();
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
    fn session_equality_depends_on_protocol_and_caps() {
        let s1 = Session::new(Protocol::ConnectUdp);
        let mut s2 = Session::new(Protocol::ConnectUdp);
        assert_eq!(s1, s2);

        s2.set_local_h3_datagram(true);
        assert_ne!(s1, s2);
    }

    #[test]
    fn validate_is_used_by_negotiate_peer_h3_datagram() {
        // Ensures the helper is the single source of truth for validation.
        let mut session = Session::new(Protocol::ConnectUdp);
        assert!(
            session
                .negotiate_peer_h3_datagram(0)
                .is_ok_and(|_| validate_h3_datagram_setting_value(0).is_ok())
        );
    }
}
