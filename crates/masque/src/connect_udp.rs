//! CONNECT-UDP request type and URI template helpers.
//!
//! This module implements the request target URI template from RFC 9298
//! Section 3.1:
//!
//! ```text
//! https://<proxy>:<port>/masque?target_host=<target>&target_port=<port>
//! ```
//!
//! An optional `udp_proxy_config` query parameter may also be present.

use crate::{Error, Result};

/// The HTTP method used for CONNECT-UDP requests per RFC 9298.
pub const CONNECT_UDP_METHOD: &str = "CONNECT-UDP";

/// A parsed CONNECT-UDP request per RFC 9298.
///
/// The request target is represented by the RFC 9298 URI template. The fields
/// are validated at construction time: `target_host` must be non-empty and
/// `target_port` must be in the range `1..=65535`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUdpRequest {
    target_host: String,
    target_port: u16,
    udp_proxy_config: Option<String>,
}

impl ConnectUdpRequest {
    /// Create a new CONNECT-UDP request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConnectUdpRequest`] if `target_host` is empty or
    /// `target_port` is zero.
    pub fn new(
        target_host: impl Into<String>,
        target_port: u16,
        udp_proxy_config: Option<impl Into<String>>,
    ) -> Result<Self> {
        let target_host = target_host.into();
        validate_target_host(&target_host)?;
        validate_target_port(target_port)?;
        Ok(Self {
            target_host,
            target_port,
            udp_proxy_config: udp_proxy_config.map(Into::into),
        })
    }

    /// Parse a CONNECT-UDP request from an RFC 9298 URI template.
    ///
    /// The URI must contain the `/masque` path and the query parameters
    /// `target_host` and `target_port`. An optional `udp_proxy_config`
    /// parameter is also recognized.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConnectUdpRequest`] if the URI does not match
    /// the expected template, if a required parameter is missing, or if the
    /// port is not a valid non-zero `u16`.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let (_scheme_authority, path_and_query) =
            uri.split_once("/masque")
                .ok_or_else(|| Error::InvalidConnectUdpRequest {
                    field: "path",
                    message: "URI must contain '/masque' path".into(),
                })?;

        let query = path_and_query
            .strip_prefix("/masque")
            .unwrap_or(path_and_query);
        let query = query.strip_prefix('?').unwrap_or(query);

        let mut target_host: Option<String> = None;
        let mut target_port: Option<u16> = None;
        let mut udp_proxy_config: Option<String> = None;

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) =
                pair.split_once('=')
                    .ok_or_else(|| Error::InvalidConnectUdpRequest {
                        field: "query",
                        message: format!("query parameter '{pair}' is missing '='"),
                    })?;
            match key {
                "target_host" => target_host = Some(value.into()),
                "target_port" => {
                    let port =
                        value
                            .parse::<u16>()
                            .map_err(|_| Error::InvalidConnectUdpRequest {
                                field: "target_port",
                                message: format!("'{value}' is not a valid port number"),
                            })?;
                    validate_target_port(port)?;
                    target_port = Some(port);
                }
                "udp_proxy_config" => udp_proxy_config = Some(value.into()),
                _ => {}
            }
        }

        let target_host = target_host.ok_or_else(|| Error::InvalidConnectUdpRequest {
            field: "target_host",
            message: "missing query parameter 'target_host'".into(),
        })?;
        validate_target_host(&target_host)?;

        let target_port = target_port.ok_or_else(|| Error::InvalidConnectUdpRequest {
            field: "target_port",
            message: "missing query parameter 'target_port'".into(),
        })?;

        Ok(Self {
            target_host,
            target_port,
            udp_proxy_config,
        })
    }

    /// Generate the RFC 9298 URI for this request.
    ///
    /// `proxy_authority` is the proxy host and port, e.g. `proxy.example:443`.
    #[must_use]
    pub fn to_uri(&self, proxy_authority: &str) -> String {
        let host = &self.target_host;
        let port = self.target_port;
        let mut uri =
            format!("https://{proxy_authority}/masque?target_host={host}&target_port={port}");
        if let Some(config) = &self.udp_proxy_config {
            uri.push_str("&udp_proxy_config=");
            uri.push_str(config);
        }
        uri
    }

    /// Return the target host.
    #[must_use]
    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    /// Return the target port.
    #[must_use]
    pub fn target_port(&self) -> u16 {
        self.target_port
    }

    /// Return the optional UDP proxy configuration.
    #[must_use]
    pub fn udp_proxy_config(&self) -> Option<&str> {
        self.udp_proxy_config.as_deref()
    }
}

fn validate_target_host(host: &str) -> Result<()> {
    if host.trim().is_empty() {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_host",
            message: "must not be empty".into(),
        });
    }
    Ok(())
}

fn validate_target_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_port",
            message: "must be between 1 and 65535".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_stores_valid_fields() {
        let req = ConnectUdpRequest::new("example.com", 443, None::<String>).unwrap();
        assert_eq!(req.target_host(), "example.com");
        assert_eq!(req.target_port(), 443);
        assert_eq!(req.udp_proxy_config(), None);
    }

    #[test]
    fn request_accepts_optional_udp_proxy_config() {
        let req = ConnectUdpRequest::new("example.com", 443, Some("config1")).unwrap();
        assert_eq!(req.udp_proxy_config(), Some("config1"));
    }

    #[test]
    fn request_rejects_empty_target_host() {
        let err = ConnectUdpRequest::new("", 443, None::<String>).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_host",
                ..
            }
        ));
    }

    #[test]
    fn request_rejects_whitespace_only_target_host() {
        let err = ConnectUdpRequest::new("   ", 443, None::<String>).unwrap_err();
        assert!(err.to_string().contains("target_host"));
    }

    #[test]
    fn request_rejects_zero_target_port() {
        let err = ConnectUdpRequest::new("example.com", 0, None::<String>).unwrap_err();
        assert!(err.to_string().contains("target_port"));
    }

    #[test]
    fn from_uri_parses_minimal_template() {
        let req = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=53",
        )
        .unwrap();
        assert_eq!(req.target_host(), "target.example");
        assert_eq!(req.target_port(), 53);
        assert_eq!(req.udp_proxy_config(), None);
    }

    #[test]
    fn from_uri_parses_template_with_udp_proxy_config() {
        let req = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=53&udp_proxy_config=cfg",
        )
        .unwrap();
        assert_eq!(req.udp_proxy_config(), Some("cfg"));
    }

    #[test]
    fn from_uri_and_to_uri_round_trip() {
        let original = ConnectUdpRequest::new("target.example", 53, Some("cfg")).unwrap();
        let uri = original.to_uri("proxy.example:443");
        let parsed = ConnectUdpRequest::from_uri(&uri).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn from_uri_rejects_missing_target_host() {
        let err = ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_port=53")
            .unwrap_err();
        assert!(err.to_string().contains("target_host"));
    }

    #[test]
    fn from_uri_rejects_missing_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example",
        )
        .unwrap_err();
        assert!(err.to_string().contains("target_port"));
    }

    #[test]
    fn from_uri_rejects_non_numeric_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=abc",
        )
        .unwrap_err();
        assert!(err.to_string().contains("target_port"));
    }

    #[test]
    fn from_uri_rejects_zero_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=0",
        )
        .unwrap_err();
        assert!(err.to_string().contains("target_port"));
    }

    #[test]
    fn from_uri_rejects_out_of_range_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=65536",
        )
        .unwrap_err();
        assert!(err.to_string().contains("target_port"));
    }

    #[test]
    fn from_uri_rejects_missing_masque_path() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/other?target_host=target.example&target_port=53",
        )
        .unwrap_err();
        assert!(err.to_string().contains("path"));
    }

    #[test]
    fn from_uri_rejects_empty_target_host() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=&target_port=53",
        )
        .unwrap_err();
        assert!(err.to_string().contains("target_host"));
    }

    #[test]
    fn from_uri_rejects_query_parameter_without_equals() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host&target_port=53",
        )
        .unwrap_err();
        assert!(err.to_string().contains("query"));
    }
}
