//! # masque
//!
//! A Rust library for implementing and experimenting with MASQUE protocols,
//! starting with CONNECT-UDP over HTTP/3.
//!
//! This crate is intentionally small at the moment. It provides the initial
//! types, errors, and configuration primitives that future protocol logic will
//! build on.
//!
//! ## Current status
//!
//! The library is a learning and verification scaffold. Full QUIC / HTTP/3
//! integration is delegated to established crates rather than being built from
//! scratch.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod config;
pub mod datagram;
pub mod error;
pub mod quic_varint;
pub mod settings;
pub mod types;

pub use config::Config;
pub use datagram::{DatagramPayload, HttpDatagram};
pub use error::{Error, H3_DATAGRAM_ERROR_CODE, Result, VarIntErrorKind};
pub use settings::{
    H3DatagramSettingValue, SETTINGS_H3_DATAGRAM, validate_h3_datagram_setting_value,
};
pub use types::{Protocol, Session};
