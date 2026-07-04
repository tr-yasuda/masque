//! Error types for the `masque` crate.

use std::fmt;

/// A specialized [`Result`] type for `masque` operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

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

    /// A requested operation is not yet implemented.
    NotImplemented {
        /// Description of the missing feature.
        message: String,
    },

    /// An HTTP/3 settings value was invalid.
    H3Settings {
        /// The setting identifier that was invalid.
        setting: u64,
        /// The invalid value received from the peer.
        value: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig { field, message } => {
                write!(f, "invalid configuration for {field}: {message}")
            }
            Error::NotImplemented { message } => write!(f, "not implemented: {message}"),
            Error::H3Settings { setting, value } => write!(
                f,
                "invalid HTTP/3 setting {setting:#x}: value must be 0 or 1, got {value}"
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
    fn error_is_cloneable() {
        let errors = [
            Error::InvalidConfig {
                field: "peer_addr",
                message: "invalid".into(),
            },
            Error::NotImplemented {
                message: "CONNECT-UDP proxy".into(),
            },
            Error::H3Settings {
                setting: 0x33,
                value: 2,
            },
        ];
        for err in errors {
            let cloned = err.clone();
            assert_eq!(err.to_string(), cloned.to_string());
            assert_eq!(err, cloned);
        }
    }

    #[test]
    fn h3_settings_display_includes_setting_and_value() {
        let err = Error::H3Settings {
            setting: 0x33,
            value: 2,
        };
        assert_eq!(
            err.to_string(),
            "invalid HTTP/3 setting 0x33: value must be 0 or 1, got 2"
        );
    }
}
