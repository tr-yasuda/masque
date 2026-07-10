//! Error types for the `masque` crate.

use std::fmt;
use std::sync::Arc;

/// A specialized [`Result`] type for `masque` operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The HTTP/3 error code registered in RFC 9297 Section 5.2 for datagram
/// or Capsule Protocol parse errors.
///
/// Note that this error code has the same numeric value (`0x33`) as the
/// `SETTINGS_H3_DATAGRAM` setting identifier, but the two belong to different
/// namespaces and must not be used interchangeably.
pub const H3_DATAGRAM_ERROR_CODE: u64 = 0x33;

/// A classifier for [`Error::Transport`] that lets callers distinguish the
/// phase of the transport stack where the failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportKind {
    /// Creating a local QUIC endpoint failed.
    EndpointCreation,
    /// Initiating or accepting a QUIC connection failed.
    Connect,
    /// The QUIC handshake failed.
    QuicHandshake,
    /// The HTTP/3 handshake failed.
    H3Handshake,
    /// Accepting an HTTP/3 request failed.
    RequestAccept,
    /// The HTTP/3 connection driver closed abnormally.
    DriverClosed,
    /// Closing the connection failed.
    Close,
    /// A transport error that does not fit a more specific kind.
    Other,
}

/// Errors that can occur when using `masque`.
///
/// The `Transport` and `InvalidCertificate` variants are always present so that
/// the public enum shape does not change depending on Cargo feature unification.
/// When the `h3` feature is disabled these variants are never constructed by
/// the crate, but they remain part of the public API for forward compatibility.
#[non_exhaustive]
pub enum Error {
    /// The provided configuration was invalid.
    InvalidConfig {
        /// The configuration field that caused the error.
        field: &'static str,
        /// A human-readable description of what is wrong.
        message: String,
    },

    /// The variable-length integer encoding or decoding failed.
    InvalidVarInt {
        /// The kind of varint failure.
        kind: VarIntErrorKind,
        /// A human-readable description of what is wrong.
        message: String,
    },

    /// A requested operation is not yet implemented.
    NotImplemented {
        /// Description of the missing feature.
        message: String,
    },

    /// The provided CONNECT-UDP request was invalid.
    InvalidConnectUdpRequest {
        /// The request field that caused the error.
        field: &'static str,
        /// A human-readable description of what is wrong.
        message: String,
    },

    /// A transport-level error occurred while establishing or using an HTTP/3
    /// connection.
    Transport {
        /// The phase of the transport stack where the failure occurred.
        kind: TransportKind,
        /// A human-readable description of what went wrong.
        message: String,
        /// The underlying error from the transport stack, if available.
        ///
        /// This field is preserved for observability and debugging. It is not
        /// used in equality comparisons; it is kept when the error is cloned
        /// by storing it in an [`Arc`].
        source: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// A TLS certificate was invalid or could not be generated.
    InvalidCertificate {
        /// A human-readable description of what is wrong.
        message: String,
        /// The underlying error from the TLS stack, if available.
        ///
        /// This field is preserved for observability and debugging. It is not
        /// used in equality comparisons; it is kept when the error is cloned
        /// by storing it in an [`Arc`].
        source: Option<Arc<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// A `SETTINGS_H3_DATAGRAM` value was invalid.
    ///
    /// RFC 9297 Section 2.1.1 limits this setting to `0` or `1`. Any other
    /// value is treated as an `H3_SETTINGS_ERROR` condition.
    H3DatagramSetting {
        /// The setting identifier that was invalid (`0x33`).
        setting: u64,
        /// The invalid value received from the peer.
        value: u64,
    },

    /// `SETTINGS_H3_DATAGRAM` was negotiated more than once with conflicting
    /// values.
    H3SettingsConflict {
        /// The setting identifier that was re-negotiated (`0x33`).
        setting: u64,
        /// The value that was already negotiated.
        previous: u64,
        /// The conflicting value received from the peer.
        received: u64,
    },

    /// An HTTP/3 datagram or Capsule Protocol parse error occurred.
    ///
    /// This corresponds to the `H3_DATAGRAM_ERROR` error code defined in
    /// RFC 9297 Section 5.2, whose numeric value is [`H3_DATAGRAM_ERROR_CODE`].
    /// Per RFC 9297 Sections 2.1 and 3.3, this is an HTTP/3 connection or stream
    /// error; callers that produce this error must abort the affected request
    /// stream or terminate the connection.
    ///
    /// The `message` field uses [`H3DatagramErrorMessage`], which can only be
    /// constructed inside this crate. This ensures that the message is always
    /// generated internally and never contains raw peer-supplied data.
    H3DatagramError {
        /// The kind of datagram or capsule error.
        kind: H3DatagramErrorKind,
        /// A human-readable description of what is wrong.
        ///
        /// This message is always generated internally and never contains raw
        /// peer-supplied data, because it may be logged or returned to callers.
        message: H3DatagramErrorMessage,
        /// The underlying error that caused this datagram parse error, if any.
        ///
        /// This allows callers and operators to inspect the root cause (for
        /// example, a variable-length integer decode failure) without parsing
        /// the human-readable message string. The source is optional because
        /// some datagram errors have no lower-level origin.
        source: Option<Box<Error>>,
    },
}

/// The kind of variable-length integer failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VarIntErrorKind {
    /// The buffer was empty.
    EmptyBuffer,
    /// The buffer was too short to contain the encoded integer.
    BufferTooShort,
    /// The offset was out of bounds.
    OffsetOutOfBounds,
    /// The value exceeds the maximum representable varint.
    ValueTooLarge,
}

/// The kind of HTTP/3 datagram or Capsule Protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum H3DatagramErrorKind {
    /// A generic error not covered by a more specific kind.
    Generic,
    /// A QUIC variable-length integer in a capsule header was malformed.
    InvalidVarint,
    /// A QUIC variable-length integer value was out of range.
    VarintOutOfRange,
    /// The capsule length does not fit in a platform `usize`.
    LengthTooLarge,
    /// The capsule header or value length overflows the buffer offset.
    LengthOverflow,
    /// The capsule value was truncated.
    Truncated,
    /// The capsule type was not the expected DATAGRAM type.
    UnexpectedCapsuleType,
}

/// A human-readable message for [`Error::H3DatagramError`].
///
/// This newtype is intentionally constructible only inside the `masque` crate,
/// ensuring that the message is always generated internally and never contains
/// raw peer-supplied data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3DatagramErrorMessage(String);

impl H3DatagramErrorMessage {
    /// Create a new internally-generated error message.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Error {
    /// Create an [`Error::Transport`] with an internally-generated message.
    #[cfg(feature = "h3")]
    pub(crate) fn transport_error(
        kind: TransportKind,
        message: impl Into<String>,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self::Transport {
            kind,
            message: message.into(),
            source: source.map(Arc::from),
        }
    }

    /// Create an [`Error::InvalidCertificate`] with an internally-generated message.
    #[cfg(any(test, feature = "test-utils"))]
    #[allow(dead_code)]
    pub(crate) fn invalid_certificate_error(
        message: impl Into<String>,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self::InvalidCertificate {
            message: message.into(),
            source: source.map(Arc::from),
        }
    }

    /// Create an [`Error::H3DatagramError`] with an internally-generated message.
    pub(crate) fn h3_datagram_error(kind: H3DatagramErrorKind, message: impl Into<String>) -> Self {
        Self::H3DatagramError {
            kind,
            message: H3DatagramErrorMessage::new(message),
            source: None,
        }
    }

    /// Create an [`Error::H3DatagramError`] with an internally-generated message
    /// and an optional underlying source error.
    pub(crate) fn h3_datagram_error_with_source(
        kind: H3DatagramErrorKind,
        message: impl Into<String>,
        source: Error,
    ) -> Self {
        Self::H3DatagramError {
            kind,
            message: H3DatagramErrorMessage::new(message),
            source: Some(Box::new(source)),
        }
    }
}

impl Clone for Error {
    fn clone(&self) -> Self {
        match self {
            Self::InvalidConfig { field, message } => Self::InvalidConfig {
                field,
                message: message.clone(),
            },
            Self::InvalidVarInt { kind, message } => Self::InvalidVarInt {
                kind: *kind,
                message: message.clone(),
            },
            Self::NotImplemented { message } => Self::NotImplemented {
                message: message.clone(),
            },
            Self::InvalidConnectUdpRequest { field, message } => Self::InvalidConnectUdpRequest {
                field,
                message: message.clone(),
            },
            Self::Transport {
                kind,
                message,
                source,
            } => Self::Transport {
                kind: *kind,
                message: message.clone(),
                source: source.clone(),
            },
            Self::InvalidCertificate { message, source } => Self::InvalidCertificate {
                message: message.clone(),
                source: source.clone(),
            },
            Self::H3DatagramSetting { setting, value } => Self::H3DatagramSetting {
                setting: *setting,
                value: *value,
            },
            Self::H3SettingsConflict {
                setting,
                previous,
                received,
            } => Self::H3SettingsConflict {
                setting: *setting,
                previous: *previous,
                received: *received,
            },
            Self::H3DatagramError {
                kind,
                message,
                source,
            } => Self::H3DatagramError {
                kind: *kind,
                message: message.clone(),
                source: source.clone(),
            },
        }
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::InvalidConfig {
                    field: field_a,
                    message: message_a,
                },
                Self::InvalidConfig {
                    field: field_b,
                    message: message_b,
                },
            ) => field_a == field_b && message_a == message_b,
            (
                Self::InvalidVarInt {
                    kind: kind_a,
                    message: message_a,
                },
                Self::InvalidVarInt {
                    kind: kind_b,
                    message: message_b,
                },
            ) => kind_a == kind_b && message_a == message_b,
            (
                Self::NotImplemented { message: message_a },
                Self::NotImplemented { message: message_b },
            ) => message_a == message_b,
            (
                Self::InvalidConnectUdpRequest {
                    field: field_a,
                    message: message_a,
                },
                Self::InvalidConnectUdpRequest {
                    field: field_b,
                    message: message_b,
                },
            ) => field_a == field_b && message_a == message_b,
            (
                Self::Transport {
                    kind: kind_a,
                    message: message_a,
                    ..
                },
                Self::Transport {
                    kind: kind_b,
                    message: message_b,
                    ..
                },
            ) => kind_a == kind_b && message_a == message_b,
            (
                Self::InvalidCertificate {
                    message: message_a, ..
                },
                Self::InvalidCertificate {
                    message: message_b, ..
                },
            ) => message_a == message_b,
            (
                Self::H3DatagramSetting {
                    setting: setting_a,
                    value: value_a,
                },
                Self::H3DatagramSetting {
                    setting: setting_b,
                    value: value_b,
                },
            ) => setting_a == setting_b && value_a == value_b,
            (
                Self::H3SettingsConflict {
                    setting: setting_a,
                    previous: previous_a,
                    received: received_a,
                },
                Self::H3SettingsConflict {
                    setting: setting_b,
                    previous: previous_b,
                    received: received_b,
                },
            ) => setting_a == setting_b && previous_a == previous_b && received_a == received_b,
            (
                Self::H3DatagramError {
                    kind: kind_a,
                    message: message_a,
                    source: source_a,
                },
                Self::H3DatagramError {
                    kind: kind_b,
                    message: message_b,
                    source: source_b,
                },
            ) => kind_a == kind_b && message_a == message_b && source_a == source_b,
            _ => false,
        }
    }
}

impl Eq for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig { field, message } => {
                write!(f, "invalid configuration for {field}: {message}")
            }
            Error::InvalidVarInt { kind, message } => {
                write!(f, "invalid varint ({kind:?}): {message}")
            }
            Error::NotImplemented { message } => write!(f, "not implemented: {message}"),
            Error::InvalidConnectUdpRequest { field, message } => {
                write!(f, "invalid CONNECT-UDP request for {field}: {message}")
            }
            Error::Transport { kind, message, .. } => {
                write!(f, "transport error ({kind:?}): {message}")
            }
            Error::InvalidCertificate { message, .. } => {
                write!(f, "invalid certificate: {message}")
            }
            Error::H3DatagramSetting { setting, value } => write!(
                f,
                "invalid HTTP/3 datagram setting {setting:#x}: value must be 0 or 1, got {value}"
            ),
            Error::H3SettingsConflict {
                setting,
                previous,
                received,
            } => write!(
                f,
                "HTTP/3 setting {setting:#x} already negotiated with value {previous}; received conflicting value {received}"
            ),
            Error::H3DatagramError { message, .. } => write!(
                f,
                "HTTP/3 datagram or capsule protocol error ({H3_DATAGRAM_ERROR_CODE:#x}): {}",
                message.0
            ),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig { field, message } => f
                .debug_struct("InvalidConfig")
                .field("field", field)
                .field("message", message)
                .finish(),
            Error::InvalidVarInt { kind, message } => f
                .debug_struct("InvalidVarInt")
                .field("kind", kind)
                .field("message", message)
                .finish(),
            Error::NotImplemented { message } => f
                .debug_struct("NotImplemented")
                .field("message", message)
                .finish(),
            Error::InvalidConnectUdpRequest { field, message } => f
                .debug_struct("InvalidConnectUdpRequest")
                .field("field", field)
                .field("message", message)
                .finish(),
            Error::Transport { kind, message, .. } => f
                .debug_struct("Transport")
                .field("kind", kind)
                .field("message", message)
                .finish_non_exhaustive(),
            Error::InvalidCertificate { message, .. } => f
                .debug_struct("InvalidCertificate")
                .field("message", message)
                .finish_non_exhaustive(),
            Error::H3DatagramSetting { setting, value } => f
                .debug_struct("H3DatagramSetting")
                .field("setting", setting)
                .field("value", value)
                .finish(),
            Error::H3SettingsConflict {
                setting,
                previous,
                received,
            } => f
                .debug_struct("H3SettingsConflict")
                .field("setting", setting)
                .field("previous", previous)
                .field("received", received)
                .finish(),
            Error::H3DatagramError { kind, message, .. } => f
                .debug_struct("H3DatagramError")
                .field("kind", kind)
                .field("message", &message.0)
                .finish_non_exhaustive(),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::H3DatagramError { source, .. } => source
                .as_deref()
                .map(|e| e as &(dyn std::error::Error + 'static)),
            Error::Transport { source, .. } | Error::InvalidCertificate { source, .. } => source
                .as_deref()
                .map(|e| e as &(dyn std::error::Error + 'static)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use super::*;

    #[test]
    fn invalid_config_display_includes_field_and_message() {
        let err = Error::InvalidConfig {
            field: "bind_addr",
            message: "must not be empty".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid configuration for bind_addr: must not be empty"
        );
    }

    #[test]
    fn not_implemented_display_includes_message() {
        let err = Error::NotImplemented {
            message: "CONNECT-UDP proxy".into(),
        };
        assert_eq!(err.to_string(), "not implemented: CONNECT-UDP proxy");
    }

    #[test]
    fn invalid_connect_udp_request_display_includes_field_and_message() {
        let err = Error::InvalidConnectUdpRequest {
            field: "target_port",
            message: "must be a valid port".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid CONNECT-UDP request for target_port: must be a valid port"
        );
    }

    #[test]
    fn transport_error_display_includes_message() {
        let err = Error::Transport {
            kind: TransportKind::Other,
            message: "connection refused".into(),
            source: None,
        };
        assert_eq!(
            err.to_string(),
            "transport error (Other): connection refused"
        );
    }

    #[test]
    fn transport_error_preserves_source() {
        let inner = Error::InvalidVarInt {
            kind: VarIntErrorKind::BufferTooShort,
            message: "buffer too short".into(),
        };
        let err = Error::Transport {
            kind: TransportKind::Connect,
            message: "connection refused".into(),
            source: Some(Arc::new(inner.clone())),
        };
        assert_eq!(err.source().map(|e| e.to_string()), Some(inner.to_string()));
    }

    #[test]
    fn transport_error_preserves_source_after_clone() {
        let inner = Error::InvalidVarInt {
            kind: VarIntErrorKind::BufferTooShort,
            message: "buffer too short".into(),
        };
        let err = Error::Transport {
            kind: TransportKind::Connect,
            message: "connection refused".into(),
            source: Some(Arc::new(inner.clone())),
        };
        let cloned = err.clone();
        assert_eq!(
            cloned.source().map(|e| e.to_string()),
            Some(inner.to_string())
        );
    }

    #[test]
    fn transport_error_equality_ignores_source() {
        let a = Error::Transport {
            kind: TransportKind::Connect,
            message: "failed".into(),
            source: Some(Arc::new(Error::NotImplemented {
                message: "a".into(),
            })),
        };
        let b = Error::Transport {
            kind: TransportKind::Connect,
            message: "failed".into(),
            source: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn invalid_certificate_error_display_includes_message() {
        let err = Error::InvalidCertificate {
            message: "bad cert".into(),
            source: None,
        };
        assert_eq!(err.to_string(), "invalid certificate: bad cert");
    }

    #[test]
    fn h3_datagram_error_display_includes_message() {
        let err = Error::h3_datagram_error(H3DatagramErrorKind::Generic, "invalid datagram length");
        assert_eq!(
            err.to_string(),
            "HTTP/3 datagram or capsule protocol error (0x33): invalid datagram length"
        );
    }

    #[test]
    fn h3_datagram_error_preserves_source_error() {
        let inner = Error::InvalidVarInt {
            kind: VarIntErrorKind::BufferTooShort,
            message: "buffer too short".into(),
        };
        let err = Error::h3_datagram_error_with_source(
            H3DatagramErrorKind::InvalidVarint,
            "invalid quarter stream ID",
            inner.clone(),
        );
        assert_eq!(err.source().map(|e| e.to_string()), Some(inner.to_string()));
    }

    #[test]
    fn h3_datagram_error_is_cloneable() {
        let err = Error::h3_datagram_error(H3DatagramErrorKind::Generic, "parse failed");
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn h3_datagram_error_is_equal() {
        let err = Error::h3_datagram_error(H3DatagramErrorKind::Generic, "parse failed");
        let same = Error::h3_datagram_error(H3DatagramErrorKind::Generic, "parse failed");
        let different = Error::h3_datagram_error(H3DatagramErrorKind::Generic, "other");
        assert_eq!(err, same);
        assert_ne!(err, different);
    }

    #[test]
    fn error_is_cloneable() {
        let errors = [
            Error::InvalidConfig {
                field: "peer_addr",
                message: "invalid".into(),
            },
            Error::NotImplemented {
                message: "CONNECT-UDP proxy".into(),
            },
            Error::InvalidConnectUdpRequest {
                field: "target_port",
                message: "must not be zero".into(),
            },
            Error::Transport {
                kind: TransportKind::Other,
                message: "connection refused".into(),
                source: None,
            },
            Error::InvalidCertificate {
                message: "bad cert".into(),
                source: None,
            },
            Error::H3DatagramSetting {
                setting: 0x33,
                value: 2,
            },
            Error::H3SettingsConflict {
                setting: 0x33,
                previous: 1,
                received: 0,
            },
            Error::h3_datagram_error(H3DatagramErrorKind::Generic, "parse failed"),
            Error::InvalidVarInt {
                kind: VarIntErrorKind::ValueTooLarge,
                message: "value too large".into(),
            },
        ];
        for err in errors {
            let cloned = err.clone();
            assert_eq!(err.to_string(), cloned.to_string());
            assert_eq!(err, cloned);
        }
    }

    #[test]
    fn h3_datagram_setting_display_includes_setting_and_value() {
        let err = Error::H3DatagramSetting {
            setting: 0x33,
            value: 2,
        };
        assert_eq!(
            err.to_string(),
            "invalid HTTP/3 datagram setting 0x33: value must be 0 or 1, got 2"
        );
    }

    #[test]
    fn h3_settings_conflict_display_includes_previous_and_received_values() {
        let err = Error::H3SettingsConflict {
            setting: 0x33,
            previous: 1,
            received: 0,
        };
        assert_eq!(
            err.to_string(),
            "HTTP/3 setting 0x33 already negotiated with value 1; received conflicting value 0"
        );
    }

    #[test]
    fn invalid_var_int_display_includes_kind_and_message() {
        let err = Error::InvalidVarInt {
            kind: VarIntErrorKind::ValueTooLarge,
            message: "value too large".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid varint (ValueTooLarge): value too large"
        );
    }
}
