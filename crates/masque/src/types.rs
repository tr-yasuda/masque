//! Core types used by MASQUE protocols.

use std::fmt;

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

/// A placeholder for a MASQUE session context.
///
/// This type will eventually hold connection state, negotiated parameters,
/// and flow identifiers. For now it serves as a structural placeholder while
/// the crate's public API is being designed.
///
/// # Design note
///
/// Future state additions should be grouped into cohesive inner types
/// (e.g., transport state, flow identifiers, negotiated caps) rather than
/// appended as unrelated fields. Consider wrapping a private inner struct so
/// that internal growth does not break the public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    protocol: Protocol,
}

impl Session {
    /// Create a new session placeholder for the given protocol.
    #[must_use]
    pub const fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }

    /// Return the protocol associated with this session.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.protocol
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
}
