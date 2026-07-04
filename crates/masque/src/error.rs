//! Error types for the `masque` crate.

use std::fmt;

/// A specialized [`Result`] type for `masque` operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The HTTP/3 error code registered in RFC 9297 Section 5.2 for datagram
/// or Capsule Protocol parse errors.
pub const H3_DATAGRAM_ERROR_CODE: u64 = 0x33;

/// Errors that can occur when using `masque`.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// An HTTP/3 datagram or Capsule Protocol parse error occurred.
    ///
    /// This corresponds to the `H3_DATAGRAM_ERROR` error code defined in
    /// RFC 9297 Section 5.2, whose numeric value is [`H3_DATAGRAM_ERROR_CODE`].
    /// Per RFC 9297 Sections 2.1 and 3.3, this is an HTTP/3 connection or stream
    /// error; callers that produce this error must abort the affected request
    /// stream or terminate the connection.
    H3DatagramError {
        /// A human-readable description of what is wrong.
        ///
        /// This message must be generated internally and must not contain raw
        /// peer-supplied data, because it may be logged or returned to callers.
        message: String,
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig { field, message } => {
                write!(f, "invalid configuration for {field}: {message}")
            }
            Error::InvalidVarInt { kind, message } => write!(f, "invalid varint ({kind:?}): {message}"),
            Error::NotImplemented { message } => write!(f, "not implemented: {message}"),
            Error::H3DatagramError { message } => write!(
                f,
                "HTTP/3 datagram or capsule protocol error ({H3_DATAGRAM_ERROR_CODE:#x}): {message}"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
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
    fn h3_datagram_error_display_includes_message() {
        let err = Error::H3DatagramError {
            message: "invalid datagram length".into(),
        };
        assert_eq!(
            err.to_string(),
            "HTTP/3 datagram or capsule protocol error (0x33): invalid datagram length"
        );
    }

    #[test]
    fn h3_datagram_error_is_cloneable() {
        let err = Error::H3DatagramError {
            message: "parse failed".into(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn h3_datagram_error_is_equal() {
        let err = Error::H3DatagramError {
            message: "parse failed".into(),
        };
        let same = Error::H3DatagramError {
            message: "parse failed".into(),
        };
        let different = Error::H3DatagramError {
            message: "other".into(),
        };
        assert_eq!(err, same);
        assert_ne!(err, different);
    }

    #[test]
    fn error_is_cloneable() {
        let err = Error::InvalidConfig {
            field: "peer_addr",
            message: "invalid".into(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);

        let err = Error::NotImplemented {
            message: "CONNECT-UDP proxy".into(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
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
