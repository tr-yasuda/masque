//! CONNECT-UDP request type and URI template helpers.
//!
//! This module implements the request target URI template used by CONNECT-UDP
//! (RFC 9298). RFC 9298 Section 2 defines the template as:
//!
//! ```text
//! https://<proxy>:<port>/masque?target_host=<target>&target_port=<port>
//! ```
//!
//! An optional `udp_proxy_config` query parameter may also be present. Query
//! parameter values are percent-encoded on generation and percent-decoded on
//! parsing so that arbitrary valid values round-trip correctly.
//!
//! Note: the HTTP/2 and HTTP/3 `:method` pseudo-header for CONNECT-UDP is
//! `"CONNECT"` and the `:protocol` pseudo-header is `"connect-udp"`. For
//! HTTP/1.1 the method is `"GET"` with an `Upgrade: connect-udp` header. The
//! constant exported by this module is the protocol token, not a method name.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::{Error, Result};

/// The HTTP `:protocol` pseudo-header value used for CONNECT-UDP requests per
/// RFC 9298.
pub const CONNECT_UDP_PROTOCOL: &str = "connect-udp";

/// Maximum length of a `target_host` value in bytes.
const MAX_TARGET_HOST_LEN: usize = 253;

/// Maximum length of a `udp_proxy_config` value in bytes.
const MAX_UDP_PROXY_CONFIG_LEN: usize = 4096;

/// Maximum length of an input URI in bytes.
const MAX_URI_LEN: usize = 8192;

/// Maximum length of a proxy authority (`host:port` or `[ipv6]:port`) in bytes.
const MAX_PROXY_AUTHORITY_LEN: usize = 1024;

/// A parsed CONNECT-UDP request per RFC 9298.
///
/// The request target is represented by the RFC 9298 URI template. The fields
/// are validated at construction time: `target_host` must be a non-empty,
/// syntactically valid host or IP literal and `target_port` must be in the
/// range `1..=65535`.
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
    /// Returns [`Error::InvalidConnectUdpRequest`] if `target_host` is empty,
    /// only whitespace, syntactically invalid, too long, or if `target_port`
    /// is zero.
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
    /// The URI must use the `https` scheme, contain the `/masque` path exactly
    /// (after normalizing percent-encoded unreserved characters), and include
    /// the query parameters `target_host` and `target_port`. An optional
    /// `udp_proxy_config` parameter is also recognized. Query values are
    /// percent-decoded before validation.
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

        if uri.contains('#') {
            return Err(Error::InvalidConnectUdpRequest {
                field: "fragment",
                message: "URI must not contain a fragment".into(),
            });
        }

        validate_scheme(uri)?;

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

        if authority.contains('@') {
            return Err(Error::InvalidConnectUdpRequest {
                field: "authority",
                message: "URI authority must not contain userinfo".into(),
            });
        }
        validate_authority(authority)?;

        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((path_and_query, ""));
        if normalize_path_segment(path)? != "masque" {
            return Err(Error::InvalidConnectUdpRequest {
                field: "path",
                message: "URI path must be '/masque'".into(),
            });
        }

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

            let value = decode_query_value(value).map_err(|e| match e {
                Error::InvalidConnectUdpRequest { message, .. } => {
                    Error::InvalidConnectUdpRequest {
                        field: "query",
                        message: format!("query parameter '{key}' {message}"),
                    }
                }
                other => other,
            })?;

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
                    let port = parse_target_port(&value)?;
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
                        message: format!("unknown query parameter '{key}'"),
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
    /// `proxy_authority` is the proxy host and port, e.g. `proxy.example:443`
    /// or `[::1]:443`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConnectUdpRequest`] if `proxy_authority` is empty
    /// or not a valid `host:port` / `[ipv6]:port` authority.
    #[must_use = "the generated URI should be used or handled"]
    pub fn to_uri(&self, proxy_authority: &str) -> Result<String> {
        validate_proxy_authority(proxy_authority)?;
        let host = encode_query_value(&self.target_host);
        let port = self.target_port;
        let mut uri =
            format!("https://{proxy_authority}/masque?target_host={host}&target_port={port}");
        if let Some(config) = &self.udp_proxy_config {
            let config = encode_query_value(config);
            uri.push_str("&udp_proxy_config=");
            uri.push_str(&config);
        }
        if uri.len() > MAX_URI_LEN {
            return Err(Error::InvalidConnectUdpRequest {
                field: "uri",
                message: "generated URI is too long".into(),
            });
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
    if has_control_character(trimmed) {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_host",
            message: "target_host contains control characters".into(),
        });
    }
    validate_host("target_host", trimmed)?;
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
    if has_control_character(&config) {
        return Err(Error::InvalidConnectUdpRequest {
            field: "udp_proxy_config",
            message: "udp_proxy_config contains control characters".into(),
        });
    }
    Ok(config)
}

fn validate_proxy_authority(authority: &str) -> Result<()> {
    validate_host_port("proxy_authority", authority)
}

fn validate_authority(authority: &str) -> Result<()> {
    validate_host_port("authority", authority)
}

fn validate_host_port(field: &'static str, authority: &str) -> Result<()> {
    if authority.is_empty() {
        return Err(Error::InvalidConnectUdpRequest {
            field,
            message: "must not be empty".into(),
        });
    }
    if authority.len() > MAX_PROXY_AUTHORITY_LEN {
        return Err(Error::InvalidConnectUdpRequest {
            field,
            message: format!("{field} is too long"),
        });
    }
    if has_control_character(authority) {
        return Err(Error::InvalidConnectUdpRequest {
            field,
            message: format!("{field} contains control characters"),
        });
    }

    let (host, port_str) = if authority.starts_with('[') {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return Err(Error::InvalidConnectUdpRequest {
                field,
                message: "IPv6 authority must be '[ipv6]:port'".into(),
            });
        };
        if !host.ends_with(']') {
            return Err(Error::InvalidConnectUdpRequest {
                field,
                message: "IPv6 authority must end with ']'".into(),
            });
        }
        let inner = &host[1..host.len() - 1];
        validate_ipv6_literal(field, inner)?;
        (inner, port)
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return Err(Error::InvalidConnectUdpRequest {
                field,
                message: format!("{field} must be 'host:port'"),
            });
        };
        if host.is_empty() {
            return Err(Error::InvalidConnectUdpRequest {
                field,
                message: format!("{field} host must not be empty"),
            });
        }
        validate_host(field, host)?;
        (host, port)
    };

    if port_str.is_empty() {
        return Err(Error::InvalidConnectUdpRequest {
            field,
            message: format!("{field} port must not be empty"),
        });
    }
    if !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidConnectUdpRequest {
            field,
            message: format!("{field} port '{port_str}' is not numeric"),
        });
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| Error::InvalidConnectUdpRequest {
            field,
            message: format!("{field} port '{port_str}' is out of range"),
        })?;
    if port == 0 {
        return Err(Error::InvalidConnectUdpRequest {
            field,
            message: format!("{field} port must not be zero"),
        });
    }

    // `host` is unused after validation, but suppress the unused warning.
    let _ = host;
    Ok(())
}

fn validate_host(field: &'static str, host: &str) -> Result<()> {
    // IPv6 bracket literal.
    if host.starts_with('[') && host.ends_with(']') {
        return validate_ipv6_literal(field, &host[1..host.len() - 1]);
    }

    // IPv4 literal: only digits and dots, and parses as IPv4.
    // Hosts like `1234.example.com` that look numeric but do not parse as
    // IPv4 fall through to reg-name validation per RFC 3986.
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') && Ipv4Addr::from_str(host).is_ok() {
        return Ok(());
    }

    // Registered name: unreserved / sub-delims per RFC 3986.
    if !host.chars().all(is_valid_reg_name_char) {
        return Err(Error::InvalidConnectUdpRequest {
            field,
            message: format!("{field} contains invalid characters"),
        });
    }
    Ok(())
}

fn validate_ipv6_literal(field: &'static str, s: &str) -> Result<()> {
    Ipv6Addr::from_str(s).map_err(|_| Error::InvalidConnectUdpRequest {
        field,
        message: format!("'{s}' is not a valid IPv6 address"),
    })?;
    Ok(())
}

fn is_valid_reg_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.'
                | '_'
                | '~'
                | '!'
                | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
        )
}

fn has_control_character(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7F)
}

fn parse_target_port(value: &str) -> Result<u16> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_port",
            message: format!("target_port '{value}' is not a valid port number"),
        });
    }
    value
        .parse::<u16>()
        .map_err(|_| Error::InvalidConnectUdpRequest {
            field: "target_port",
            message: format!("target_port '{value}' is out of range"),
        })
}

fn encode_query_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if is_unreserved(b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn decode_query_value(value: &str) -> Result<String> {
    if !value.bytes().any(|b| b == b'%') {
        return Ok(value.to_string());
    }

    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(Error::InvalidConnectUdpRequest {
                    field: "query",
                    message: "has an incomplete percent-encoding sequence".into(),
                });
            }
            let hi = hex_value(bytes[i + 1]).ok_or_else(|| Error::InvalidConnectUdpRequest {
                field: "query",
                message: "has an invalid percent-encoding sequence".into(),
            })?;
            let lo = hex_value(bytes[i + 2]).ok_or_else(|| Error::InvalidConnectUdpRequest {
                field: "query",
                message: "has an invalid percent-encoding sequence".into(),
            })?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidConnectUdpRequest {
        field: "query",
        message: "is not valid UTF-8".into(),
    })
}

fn normalize_path_segment(segment: &str) -> Result<String> {
    if !segment.bytes().any(|b| b == b'%') {
        return Ok(segment.to_string());
    }

    let mut out = Vec::with_capacity(segment.len());
    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(Error::InvalidConnectUdpRequest {
                    field: "path",
                    message: "path has an incomplete percent-encoding sequence".into(),
                });
            }
            let hi = hex_value(bytes[i + 1]).ok_or_else(|| Error::InvalidConnectUdpRequest {
                field: "path",
                message: "path has an invalid percent-encoding sequence".into(),
            })?;
            let lo = hex_value(bytes[i + 2]).ok_or_else(|| Error::InvalidConnectUdpRequest {
                field: "path",
                message: "path has an invalid percent-encoding sequence".into(),
            })?;
            let decoded = (hi << 4) | lo;
            if is_unreserved(decoded) {
                out.push(decoded);
            } else {
                out.extend_from_slice(&bytes[i..i + 3]);
            }
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidConnectUdpRequest {
        field: "path",
        message: "path is not valid UTF-8".into(),
    })
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
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
    fn request_rejects_control_character_in_target_host() {
        let err = ConnectUdpRequest::new("evil\0.com", 443, None::<String>).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_host",
                ..
            }
        ));
    }

    #[test]
    fn request_rejects_control_character_in_udp_proxy_config() {
        let err = ConnectUdpRequest::new("example.com", 443, Some("cfg\0")).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "udp_proxy_config",
                ..
            }
        ));
    }

    #[test]
    fn request_accepts_ipv4_target_host() {
        let req = ConnectUdpRequest::new("192.0.2.1", 53, None::<String>).unwrap();
        assert_eq!(req.target_host(), "192.0.2.1");
    }

    #[test]
    fn request_accepts_ipv6_target_host() {
        let req = ConnectUdpRequest::new("[::1]", 53, None::<String>).unwrap();
        assert_eq!(req.target_host(), "[::1]");
    }

    #[test]
    fn request_accepts_ipv4_like_reg_name() {
        let req = ConnectUdpRequest::new("1234.example.com", 53, None::<String>).unwrap();
        assert_eq!(req.target_host(), "1234.example.com");
    }

    #[test]
    fn request_rejects_invalid_target_host() {
        let err = ConnectUdpRequest::new("foo/bar", 53, None::<String>).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "target_host",
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
    fn from_uri_accepts_bracketed_ipv6_target_host() {
        let req = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=%5B%3A%3A1%5D&target_port=53",
        )
        .unwrap();
        assert_eq!(req.target_host(), "[::1]");
        assert_eq!(req.target_port(), 53);
    }

    #[test]
    fn from_uri_and_to_uri_round_trip() {
        let original = ConnectUdpRequest::new("target.example", 53, Some("cfg")).unwrap();
        let uri = original.to_uri("proxy.example:443").unwrap();
        let parsed = ConnectUdpRequest::from_uri(&uri).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn to_uri_leaves_unreserved_characters_unencoded() {
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let uri = req.to_uri("proxy.example:443").unwrap();
        assert_eq!(
            uri,
            "https://proxy.example:443/masque?target_host=target.example&target_port=53"
        );
    }

    #[test]
    fn to_uri_encodes_reserved_characters() {
        let req = ConnectUdpRequest::new("a&b.com", 53, Some("c=d#e")).unwrap();
        let uri = req.to_uri("proxy.example:443").unwrap();
        assert_eq!(
            uri,
            "https://proxy.example:443/masque?target_host=a%26b.com&target_port=53&udp_proxy_config=c%3Dd%23e"
        );
        let parsed = ConnectUdpRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.target_host(), "a&b.com");
        assert_eq!(parsed.udp_proxy_config(), Some("c=d#e"));
    }

    #[test]
    fn to_uri_accepts_ipv6_proxy_authority() {
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let uri = req.to_uri("[::1]:443").unwrap();
        assert!(uri.starts_with("https://[::1]:443/masque?"));
    }

    #[test]
    fn to_uri_preserves_bracketed_ipv6_target_host() {
        let req = ConnectUdpRequest::new("[::1]", 53, None::<String>).unwrap();
        let uri = req.to_uri("[::1]:443").unwrap();
        assert_eq!(
            uri,
            "https://[::1]:443/masque?target_host=%5B%3A%3A1%5D&target_port=53"
        );
    }

    #[test]
    fn to_uri_rejects_proxy_authority_without_port() {
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let err = req.to_uri("proxy.example").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "proxy_authority",
                ..
            }
        ));
    }

    #[test]
    fn to_uri_rejects_proxy_authority_with_userinfo() {
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let err = req.to_uri("user:pass@proxy.example:443").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "proxy_authority",
                ..
            }
        ));
    }

    #[test]
    fn to_uri_rejects_proxy_authority_with_percent_encoding() {
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let err = req.to_uri("user%40proxy.example:443").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "proxy_authority",
                ..
            }
        ));
    }

    #[test]
    fn to_uri_rejects_invalid_ipv6_proxy_authority() {
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let err = req.to_uri("[:::]:443").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "proxy_authority",
                ..
            }
        ));
    }

    #[test]
    fn to_uri_rejects_too_long_generated_uri() {
        let config = "&".repeat(MAX_UDP_PROXY_CONFIG_LEN);
        let req = ConnectUdpRequest::new("example.com", 53, Some(config)).unwrap();
        let err = req.to_uri("proxy.example:443").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest { field: "uri", .. }
        ));
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
        assert!(err.to_string().contains("abc"));
    }

    #[test]
    fn from_uri_rejects_plus_target_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=+53",
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
    fn from_uri_rejects_empty_authority() {
        let err = ConnectUdpRequest::from_uri(
            "https:///masque?target_host=target.example&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "authority",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_authority_with_userinfo() {
        let err = ConnectUdpRequest::from_uri(
            "https://user:pass@proxy.example:443/masque?target_host=target.example&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "authority",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_authority_without_port() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example/masque?target_host=target.example&target_port=53",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "authority",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_rejects_invalid_ipv6_target_host() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=%5B%3A%3A%3A%5D&target_port=53",
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
    fn from_uri_accepts_normalized_path() {
        let req = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/%6Dasque?target_host=target.example&target_port=53",
        )
        .unwrap();
        assert_eq!(req.target_host(), "target.example");
        assert_eq!(req.target_port(), 53);
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
    fn from_uri_rejects_control_character_in_target_host() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=evil%00.com&target_port=53",
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
        assert!(err.to_string().contains("typo"));
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
    fn from_uri_rejects_duplicate_udp_proxy_config() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=53&udp_proxy_config=cfg1&udp_proxy_config=cfg2",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "udp_proxy_config",
                ..
            }
        ));
    }

    #[test]
    fn from_uri_accepts_empty_udp_proxy_config() {
        let req = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=53&udp_proxy_config=",
        )
        .unwrap();
        assert_eq!(req.udp_proxy_config(), Some(""));
    }

    #[test]
    fn from_uri_rejects_fragment() {
        let err = ConnectUdpRequest::from_uri(
            "https://proxy.example:443/masque?target_host=target.example&target_port=53#fragment",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "fragment",
                ..
            }
        ));
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

    #[test]
    fn to_uri_rejects_long_proxy_authority() {
        let authority = format!("{}.example.com:443", "a".repeat(MAX_PROXY_AUTHORITY_LEN));
        let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
        let err = req.to_uri(&authority).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidConnectUdpRequest {
                field: "proxy_authority",
                ..
            }
        ));
    }

    #[test]
    fn connect_udp_protocol_constant_matches_rfc9298_token() {
        assert_eq!(CONNECT_UDP_PROTOCOL, "connect-udp");
    }
}
