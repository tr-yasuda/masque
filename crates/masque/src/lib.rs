//! # masque
//!
//! A Rust library for implementing and experimenting with MASQUE protocols,
//! starting with CONNECT-UDP over HTTP/3.
//!
//! This crate provides the building blocks for MASQUE tunneling, including
//! HTTP/3 Datagram support and the Capsule Protocol as defined in RFC 9297:
//!
//! - [`HttpDatagram`] for HTTP/3 Datagram payloads (Quarter Stream ID + opaque
//!   payload) and their encoding/decoding.
//! - [`DatagramCapsule`] for carrying datagram payloads over request streams.
//! - [`Capsule`] and [`CapsuleParser`] for the Capsule Protocol message format.
//! - [`CAPSULE_PROTOCOL`], [`parse_capsule_protocol`], and
//!   [`serialize_capsule_protocol`] for the `Capsule-Protocol` header.
//! - [`H3DatagramSettingValue`], [`SETTINGS_H3_DATAGRAM`], and [`Session`] for
//!   negotiating and tracking HTTP/3 Datagram support.
//!
//! Higher-level CONNECT-UDP logic will be built on top of these primitives.
//!
//! ## Current status
//!
//! The library is a learning and verification scaffold. Full QUIC / HTTP/3
//! integration is delegated to established crates rather than being built from
//! scratch.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod capsule;
pub mod capsule_protocol;
pub mod config;
pub mod datagram;
pub mod datagram_capsule;
pub mod error;
pub mod quic_varint;
pub mod settings;
pub mod types;

pub use capsule::{Capsule, CapsuleParser, CapsuleType};
pub use capsule_protocol::{
    CAPSULE_PROTOCOL, CapsuleProtocolError, parse_capsule_protocol, serialize_capsule_protocol,
};
pub use config::Config;
pub use datagram::{DatagramPayload, HttpDatagram, MAX_QUARTER_STREAM_ID};
pub use datagram_capsule::DatagramCapsule;
pub use error::{Error, H3_DATAGRAM_ERROR_CODE, H3DatagramErrorKind, Result, VarIntErrorKind};
pub use settings::{
    H3DatagramSettingValue, SETTINGS_H3_DATAGRAM, validate_h3_datagram_setting_value,
};
pub use types::{Protocol, Session};
