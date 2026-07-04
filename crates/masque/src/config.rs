//! Configuration primitives for MASQUE clients and proxies.

use std::net::SocketAddr;
use std::str::FromStr;

use crate::{Error, Result};

/// Basic configuration shared by MASQUE clients and proxies.
///
/// Both addresses are validated at construction time and stored as
/// [`SocketAddr`] values to guarantee that they are well-formed.
///
/// # Accepted input
///
/// Addresses must be IP:port literals such as `127.0.0.1:443` or
/// `[::1]:443`. Hostnames and DNS names are not accepted; resolve them
/// before constructing a `Config`.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// or not a valid `IP:port` socket address literal.
    pub fn new(bind_addr: impl AsRef<str>, peer_addr: impl AsRef<str>) -> Result<Self> {
        let bind_addr = parse_address(bind_addr.as_ref(), "bind_addr")?;
        let peer_addr = parse_address(peer_addr.as_ref(), "peer_addr")?;

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

fn parse_address(value: &str, field: &'static str) -> Result<SocketAddr> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidConfig {
            field,
            message: "must not be empty".into(),
        });
    }
    SocketAddr::from_str(trimmed).map_err(|e| Error::InvalidConfig {
        field,
        message: format!("not a valid socket address: {e}"),
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
    fn config_accepts_ipv6_literals() {
        let cfg = Config::new("[::]:0", "[::1]:443").unwrap();
        assert_eq!(cfg.bind_addr(), "[::]:0".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.peer_addr(), "[::1]:443".parse().unwrap());
    }

    #[test]
    fn config_rejects_hostname() {
        let err = Config::new("example.com:443", "127.0.0.1:53").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConfig {
                field: "bind_addr",
                ..
            }
        ));
        assert!(err.to_string().contains("not a valid socket address"));
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
        assert!(err.to_string().contains("must not be empty"));
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
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn config_rejects_whitespace_only_bind_addr() {
        let err = Config::new("   ", "127.0.0.1:1234").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn config_rejects_whitespace_only_peer_addr() {
        let err = Config::new("127.0.0.1:1234", "   ").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn config_rejects_missing_port_in_bind_addr() {
        let err = Config::new("127.0.0.1", "127.0.0.1:1234").unwrap_err();
        assert!(err.to_string().contains("not a valid socket address"));
    }

    #[test]
    fn config_rejects_missing_port_in_peer_addr() {
        let err = Config::new("127.0.0.1:1234", "127.0.0.1").unwrap_err();
        assert!(err.to_string().contains("not a valid socket address"));
    }

    #[test]
    fn config_rejects_invalid_bind_addr() {
        let err = Config::new("not-an-address", "127.0.0.1:1234").unwrap_err();
        assert!(err.to_string().contains("not a valid socket address"));
    }

    #[test]
    fn config_rejects_invalid_peer_addr() {
        let err = Config::new("127.0.0.1:1234", "not-an-address").unwrap_err();
        assert!(err.to_string().contains("not a valid socket address"));
    }
}
