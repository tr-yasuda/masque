//! CONNECT-UDP request type and URI template helpers.
//!
//! This module implements the request target URI template from RFC 9298
//! Section 3.1:
//!
//! ```text
//! https://<proxy>:<port>/masque?target_host=<target>&target_port=<port>
//! ```
//!
//! An optional `udp_proxy_config` query parameter may also be present. Query
//! parameter values are percent-encoded on generation and percent-decoded on
//! parsing so that arbitrary valid values round-trip correctly.

use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, percent_encode};

use crate::{Error, Result};

/// The HTTP method used for CONNECT-UDP requests per RFC 9298.
pub const CONNECT_UDP_METHOD: &str = "CONNECT-UDP";

/// Maximum length of a `target_host` value in bytes.
const MAX_TARGET_HOST_LEN: usize = 253;

/// Maximum length of a `udp_proxy_config` value in bytes.
const MAX_UDP_PROXY_CONFIG_LEN: usize = 4096;

/// Maximum length of an input URI in bytes.
const MAX_URI_LEN: usize = 8192;

/// A parsed CONNECT-UDP request per RFC 9298.
///
/// The request target is represented by the RFC 9298 URI template. The fields
/// are validated at construction time: `target_host` must be a non-empty
/// trimmed string and `target_port` must be in the range `1..=65535`.
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
    /// only whitespace, if it exceeds the maximum host length, or if
    /// `target_port` is zero.
    pub fn new(
        target_host: impl Into<String>,
        target_port: u16,
        udp_proxy_config: Option<impl Into<String>>,
    ) -> Result<Self> {
        let target_host = validate_target_host(target_host.into())?;
        validate_target_port(target_port)?;
        let udp_proxy_config = udp_proxy_config
            .map(Into::into)
            .map(validate_udp_proxy_config)
            .transpose()?;

        Ok(Self {
            target_host,
            target_port,
            udp_proxy_config,
        })
    }

    /// Parse a CONNECT-UDP request from an RFC 9298 URI template.
    ///
    /// The URI must use the `https` scheme, contain the `/masque` path exactly,
    /// and include the query parameters `target_host` and `target_port`. An
    /// optional `udp_proxy_config` parameter is also recognized. Query values
    /// are percent-decoded before validation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConnectUdpRequest`] if the URI does not match
    /// the expected template, if a required parameter is missing, if an
    /// unknown or duplicate parameter is present, or if the port is not a valid
    /// non-zero `u16`.
    pub fn from_uri(uri: &str) -> Result<Self> {
        if uri.len() > MAX_URI_LEN {
            return Err(Error::InvalidConnectUdpRequest {
                field: "uri",
                message: "URI is too long".into(),
            });
        }

        validate_scheme(uri)?;

        // Strip the fragment component before parsing the rest of the URI.
        let uri = uri.split_once('#').map(|(before, _)| before).unwrap_or(uri);
        let after_scheme = &uri["https://".len()..];

        let (authority, path_and_query) =
            after_scheme
                .split_once('/')
                .ok_or_else(|| Error::InvalidConnectUdpRequest {
                    field: "path",
                    message: "URI must contain '/masque' path".into(),
                })?;

        if authority.is_empty() {
            return Err(Error::InvalidConnectUdpRequest {
                field: "authority",
                message: "URI authority must not be empty".into(),
            });
        }

        // The path must be exactly `/masque` (optionally followed by `?...`).
        if !(path_and_query == "masque" || path_and_query.starts_with("masque?")) {
            return Err(Error::InvalidConnectUdpRequest {
                field: "path",
                message: "URI path must be '/masque'".into(),
            });
        }

        let query = path_and_query.strip_prefix("masque?").unwrap_or("");

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
                        message: "query parameter is missing '='".into(),
                    })?;

            let value = decode_query_value(value)?;

            match key {
                "target_host" => {
                    if target_host.is_some() {
                        return Err(Error::InvalidConnectUdpRequest {
                            field: "target_host",
                            message: "duplicate query parameter 'target_host'".into(),
                        });
                    }
                    target_host = Some(validate_target_host(value)?);
                }
                "target_port" => {
                    if target_port.is_some() {
                        return Err(Error::InvalidConnectUdpRequest {
                            field: "target_port",
                            message: "duplicate query parameter 'target_port'".into(),
                        });
                    }
                    let port =
                        value
                            .parse::<u16>()
                            .map_err(|_| Error::InvalidConnectUdpRequest {
                                field: "target_port",
                                message: "target_port is not a valid port number".into(),
                            })?;
                    validate_target_port(port)?;
                    target_port = Some(port);
                }
                "udp_proxy_config" => {
                    if udp_proxy_config.is_some() {
                        return Err(Error::InvalidConnectUdpRequest {
                            field: "udp_proxy_config",
                            message: "duplicate query parameter 'udp_proxy_config'".into(),
                        });
                    }
                    udp_proxy_config = Some(validate_udp_proxy_config(value)?);
                }
                _ => {
                    return Err(Error::InvalidConnectUdpRequest {
                        field: "query",
                        message: "unknown query parameter".into(),
                    });
                }
            }
        }

        let target_host = target_host.ok_or_else(|| Error::InvalidConnectUdpRequest {
            field: "target_host",
            message: "missing query parameter 'target_host'".into(),
        })?;

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
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConnectUdpRequest`] if `proxy_authority` is empty
    /// or contains characters that would produce an invalid URI.
    #[must_use = "the generated URI should be used or handled"]
    pub fn to_uri(&self, proxy_authority: &str) -> Result<String> {
        validate_proxy_authority(proxy_authority)?;
        let host = percent_encode(self.target_host.as_bytes(), NON_ALPHANUMERIC).to_string();
        let port = self.target_port;
        let mut uri =
            format!("https://{proxy_authority}/masque?target_host={host}&target_port={port}");
        if let Some(config) = &self.udp_proxy_config {
            let config = percent_encode(config.as_bytes(), NON_ALPHANUMERIC).to_string();
            uri.push_str("&udp_proxy_config=");
            uri.push_str(&config);
        }
        Ok(uri)
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

fn validate_scheme(uri: &str) -> Result<()> {
    let is_https = uri
        .as_bytes()
        .get(.."https://".len())
        .is_some_and(|b| b.eq_ignore_ascii_case(b"https://"));
    if !is_https {
        return Err(Error::InvalidConnectUdpRequest {
            field: "scheme",
            message: "URI scheme must be 'https'".into(),
        });
    }
    Ok(())
}

fn validate_target_host(host: impl Into<String>) -> Result<String> {
    let host = host.into();
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_host",
            message: "must not be empty".into(),
        });
    }
    if trimmed.len() > MAX_TARGET_HOST_LEN {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_host",
            message: "target_host is too long".into(),
        });
    }
    Ok(trimmed.to_string())
}

fn validate_target_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_port",
            message: "must not be zero".into(),
        });
    }
    Ok(())
}

fn validate_udp_proxy_config(config: impl Into<String>) -> Result<String> {
    let config = config.into();
    if config.len() > MAX_UDP_PROXY_CONFIG_LEN {
        return Err(Error::InvalidConnectUdpRequest {
            field: "udp_proxy_config",
            message: "udp_proxy_config is too long".into(),
        });
    }
    Ok(config)
}

fn validate_proxy_authority(authority: &str) -> Result<()> {
    if authority.is_empty() {
        return Err(Error::InvalidConnectUdpRequest {
            field: "proxy_authority",
            message: "must not be empty".into(),
        });
    }
    if authority.len() > MAX_TARGET_HOST_LEN {
        return Err(Error::InvalidConnectUdpRequest {
            field: "proxy_authority",
            message: "proxy_authority is too long".into(),
        });
    }
    if authority
        .chars()
        .any(|c| matches!(c, '/' | '?' | '#' | '@' | ' ' | '\t' | '\r' | '\n'))
    {
        return Err(Error::InvalidConnectUdpRequest {
            field: "proxy_authority",
            message: "proxy_authority contains invalid characters".into(),
        });
    }
    Ok(())
}

fn decode_query_value(value: &str) -> Result<String> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .map_err(|_| Error::InvalidConnectUdpRequest {
            field: "query",
            message: "query value is not valid UTF-8".into(),
        })
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
    fn request_trims_target_host() {
        let req = ConnectUdpRequest::new("  example.com  ", 443, None::<String>).unwrap();
        assert_eq!(req.target_host(), "example.com");
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
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_host",
                ..
            }
        ));
    }

    #[test]
    fn request_rejects_zero_target_port() {
        let err = ConnectUdpRequest::new("example.com", 0, None::<String>).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_port",
                ..
            }
        ));
        assert_eq!(
            err.to_string(),
            "invalid CONNECT-UDP request for target_port: must not be zero"
        );
    }

    #[test]
    fn request_rejects_long_target_host() {
        let host = "a".repeat(MAX_TARGET_HOST_LEN + 1);
        let err = ConnectUdpRequest::new(&host, 443, None::<String>).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_host",
                ..
            }
        ));
    }

    #[test]
    fn request_rejects_long_udp_proxy_config() {
        let config = "a".repeat(MAX_UDP_PROXY_CONFIG_LEN + 1);
        let err = ConnectUdpRequest::new("example.com", 443, Some(config)).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "udp_proxy_config",
                ..
            }
        ));
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
    fn from_uri_decodes_percent_encoded_values() {
        let req = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target%2Eexample&target_port=53&udp_proxy_config=a%26b",
        )
        .unwrap();
        assert_eq!(req.target_host(), "target.example");
        assert_eq!(req.udp_proxy_config(), Some("a&b"));
    }

    #[test]
    fn from_uri_and_to_uri_round_trip() {
        let original = ConnectUdpRequest::new("target.example", 53, Some("cfg")).unwrap();
        let uri = original.to_uri("proxy.example:443").unwrap();
        let parsed = ConnectUdpRequest::from_uri(&uri).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn to_uri_encodes_reserved_characters() {
        let req = ConnectUdpRequest::new("a&b.com", 53, Some("c=d#e")).unwrap();
        let uri = req.to_uri("proxy.example:443").unwrap();
        assert_eq!(
            uri,
            "https://proxy.example:443/masque?target_host=a%26b%2Ecom&target_port=53&udp_proxy_config=c%3Dd%23e"
        );
        let parsed = ConnectUdpRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.target_host(), "a&b.com");
        assert_eq!(parsed.udp_proxy_config(), Some("c=d#e"));
    }

    #[test]
    fn from_uri_rejects_missing_target_host() {
        let err = ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_port=53")
            .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_host",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_missing_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_port",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_empty_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_port",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_non_numeric_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=abc",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_port",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_zero_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=0",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_port",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_out_of_range_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=65536",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_port",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_non_https_scheme() {
        let err = ConnectUdpRequest::from_uri(
            "http://proxy.example:443/masque?target_host=target.example&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "scheme",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_missing_masque_path() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/other?target_host=target.example&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest { field: "path", .. }
        ));
    }

    #[test]
    fn from_uri_rejects_masque_path_prefix() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/prefix/masque?target_host=target.example&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest { field: "path", .. }
        ));
    }

    #[test]
    fn from_uri_rejects_masque_path_suffix() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masquefoo?target_host=target.example&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest { field: "path", .. }
        ));
    }

    #[test]
    fn from_uri_rejects_empty_target_host() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_host",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_query_parameter_without_equals() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest { field: "query", .. }
        ));
    }

    #[test]
    fn from_uri_rejects_unknown_query_parameter() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=53&typo=value",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest { field: "query", .. }
        ));
    }

    #[test]
    fn from_uri_rejects_duplicate_target_host() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=foo&target_host=bar&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_host",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_duplicate_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=53&target_port=54",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_port",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_strips_fragment() {
        let req = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=53#fragment",
        )
        .unwrap();
        assert_eq!(req.target_host(), "target.example");
        assert_eq!(req.target_port(), 53);
    }

    #[test]
    fn from_uri_rejects_too_long_uri() {
        let host = "a".repeat(MAX_URI_LEN);
        let uri = format!("https://proxy.example:443/masque?target_host={host}&target_port=53");
        let err = ConnectUdpRequest::from_uri(&uri).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest { field: "uri", .. }
        ));
    }

    #[test]
    fn to_uri_rejects_invalid_proxy_authority() {
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let err = req.to_uri("proxy.example:443/evil").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "proxy_authority",
                ..
            }
        ));
    }

    #[test]
    fn to_uri_rejects_empty_proxy_authority() {
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let err = req.to_uri("").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "proxy_authority",
                ..
            }
        ));
    }
}
