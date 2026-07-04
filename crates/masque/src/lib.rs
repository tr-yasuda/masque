//! # masque
//!
//! A Rust library for implementing and experimenting with MASQUE protocols,
//! starting with CONNECT-UDP over HTTP/3.
//!
//! This crate is intentionally small at the moment. It provides the initial
//! types, errors, configuration primitives, and a `Capsule-Protocol` header
//! helper that future protocol logic will build on.
//!
//! ## Current status
//!
//! The library is a learning and verification scaffold. Full QUIC / HTTP/3
//! integration is delegated to established crates rather than being built from
//! scratch.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod capsule_protocol;
pub mod config;
pub mod error;
pub mod quic_varint;
pub mod settings;
pub mod types;

pub use capsule_protocol::{CAPSULE_PROTOCOL, parse_capsule_protocol, serialize_capsule_protocol};
pub use config::Config;
pub use error::{Error, H3_DATAGRAM_ERROR_CODE, Result, VarIntErrorKind};
pub use settings::{
    H3DatagramSettingValue, SETTINGS_H3_DATAGRAM, validate_h3_datagram_setting_value,
};
pub use types::{Protocol, Session};
