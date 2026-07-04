//! Configuration primitives for MASQUE clients and proxies.

use crate::{Error, Result};

/// Basic configuration shared by MASQUE clients and proxies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Local address to bind to.
    pub bind_addr: String,

    /// Peer or upstream address.
    pub peer_addr: String,
}

impl Config {
    /// Create a new configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if required fields are empty.
    pub fn new(bind_addr: impl Into<String>, peer_addr: impl Into<String>) -> Result<Self> {
        let bind_addr = bind_addr.into();
        let peer_addr = peer_addr.into();

        if bind_addr.is_empty() {
            return Err(Error::InvalidConfig {
                message: "bind_addr must not be empty".into(),
            });
        }
        if peer_addr.is_empty() {
            return Err(Error::InvalidConfig {
                message: "peer_addr must not be empty".into(),
            });
        }

        Ok(Self {
            bind_addr,
            peer_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_accepts_valid_input() {
        let cfg = Config::new("0.0.0.0:0", "127.0.0.1:1234").unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0:0");
        assert_eq!(cfg.peer_addr, "127.0.0.1:1234");
    }

    #[test]
    fn config_rejects_empty_bind_addr() {
        let err = Config::new("", "127.0.0.1:1234").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig { .. }));
    }

    #[test]
    fn config_rejects_empty_peer_addr() {
        let err = Config::new("0.0.0.0:0", "").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig { .. }));
    }
}
