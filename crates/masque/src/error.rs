//! Error types for the `masque` crate.

use std::fmt;

/// A specialized [`Result`] type for `masque` operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors that can occur when using `masque`.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The provided configuration was invalid.
    InvalidConfig {
        /// A human-readable description of what is wrong.
        message: String,
    },

    /// A requested operation is not yet implemented.
    NotImplemented {
        /// Description of the missing feature.
        message: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig { message } => write!(f, "invalid configuration: {message}"),
            Error::NotImplemented { message } => write!(f, "not implemented: {message}"),
        }
    }
}

impl std::error::Error for Error {}
