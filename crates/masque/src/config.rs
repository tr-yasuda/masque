//! Configuration primitives for MASQUE clients and proxies.

use std::net::SocketAddr;
use std::str::FromStr;

use crate::{Error, Result};

/// Basic configuration shared by MASQUE clients and proxies.
///
/// Both addresses are validated at construction time and stored as
/// [`SocketAddr`] values to guarantee that they are well-formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    bind_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl Config {
    /// Create a new configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if either address is empty, whitespace-only,
    /// or not a valid socket address.
    pub fn new(bind_addr: impl Into<String>, peer_addr: impl Into<String>) -> Result<Self> {
        let bind_addr = parse_address(bind_addr.into(), "bind_addr")?;
        let peer_addr = parse_address(peer_addr.into(), "peer_addr")?;

        Ok(Self {
            bind_addr,
            peer_addr,
        })
    }

    /// Return the local address to bind to.
    #[must_use]
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Return the peer or upstream address.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

fn parse_address(value: String, field: &'static str) -> Result<SocketAddr> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidConfig {
            field,
            message: format!("{field} must not be empty"),
        });
    }
    SocketAddr::from_str(trimmed).map_err(|e| Error::InvalidConfig {
        field,
        message: format!("{field} is not a valid socket address: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_accepts_valid_input() {
        let cfg = Config::new("0.0.0.0:0", "127.0.0.1:1234").unwrap();
        assert_eq!(cfg.bind_addr(), "0.0.0.0:0".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.peer_addr(), "127.0.0.1:1234".parse().unwrap());
    }

    #[test]
    fn config_rejects_empty_bind_addr() {
        let err = Config::new("", "127.0.0.1:1234").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConfig {
                field: "bind_addr",
                ..
            }
        ));
        assert!(err.to_string().contains("bind_addr must not be empty"));
    }

    #[test]
    fn config_rejects_empty_peer_addr() {
        let err = Config::new("0.0.0.0:0", "").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConfig {
                field: "peer_addr",
                ..
            }
        ));
        assert!(err.to_string().contains("peer_addr must not be empty"));
    }

    #[test]
    fn config_rejects_whitespace_only_address() {
        let err = Config::new("   ", "127.0.0.1:1234").unwrap_err();
        assert!(err.to_string().contains("bind_addr must not be empty"));
    }

    #[test]
    fn config_rejects_missing_port() {
        let err = Config::new("127.0.0.1", "127.0.0.1:1234").unwrap_err();
        assert!(
            err.to_string()
                .contains("bind_addr is not a valid socket address")
        );
    }

    #[test]
    fn config_rejects_invalid_address() {
        let err = Config::new("not-an-address", "127.0.0.1:1234").unwrap_err();
        assert!(
            err.to_string()
                .contains("bind_addr is not a valid socket address")
        );
    }
}
