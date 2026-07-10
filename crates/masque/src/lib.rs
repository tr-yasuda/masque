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
//! - [`ConnectUdpRequest`] and [`CONNECT_UDP_PROTOCOL`] for RFC 9298 CONNECT-UDP
//!   request targets and URI template parsing.
//!
//! Higher-level CONNECT-UDP logic will be built on top of these primitives.
//!
//! ## HTTP/3 transport scaffolding
//!
//! When the `h3` feature is enabled, the crate exposes:
//!
//! - `H3Client` for opening outbound HTTP/3 connections.
//! - `H3Server` and `H3Connection` for accepting inbound HTTP/3
//!   connections.
//! - `H3_ALPN` for the HTTP/3 ALPN identifier.
//! - `UdpAssociation` and `AssociationId` for managing the UDP socket bound to
//!   a CONNECT-UDP request.
//!
//! When the `test-utils` feature is also enabled, `generate_self_signed_cert`
//! and `dangerous_test_client_config` are available for local testing. These
//! helpers must not be used in production.
//!
//! These types are intentionally thin wrappers around `quinn` and `h3`,
//! focused on CONNECT-UDP rather than a generic HTTP/3 client/server framework.
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
pub mod connect_udp;
pub mod datagram;
pub mod datagram_capsule;
pub mod error;
pub mod quic_varint;
pub mod settings;
pub mod types;

#[cfg(feature = "h3")]
pub mod association;
#[cfg(feature = "h3")]
pub mod client;
#[cfg(feature = "h3")]
pub mod server;
#[cfg(feature = "h3")]
pub mod tls;

pub use capsule::{Capsule, CapsuleParser, CapsuleType};
pub use capsule_protocol::{
    CAPSULE_PROTOCOL, CapsuleProtocolError, parse_capsule_protocol, serialize_capsule_protocol,
};
pub use config::Config;
pub use connect_udp::{CONNECT_UDP_PROTOCOL, ConnectUdpRequest};
pub use datagram::{DatagramPayload, HttpDatagram, MAX_QUARTER_STREAM_ID};
pub use datagram_capsule::DatagramCapsule;
pub use error::{
    Error, H3_DATAGRAM_ERROR_CODE, H3DatagramErrorKind, Result, TransportKind, VarIntErrorKind,
};
pub use settings::{
    H3DatagramSettingValue, SETTINGS_H3_DATAGRAM, validate_h3_datagram_setting_value,
};
pub use types::{Protocol, Session};

#[cfg(feature = "h3")]
pub use association::{AssociationId, MAX_UDP_PAYLOAD, UdpAssociation};
#[cfg(feature = "h3")]
pub use client::H3Client;
#[cfg(feature = "h3")]
pub use server::{H3Connection, H3Server};
#[cfg(feature = "h3")]
pub use tls::H3_ALPN;
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub use tls::dangerous_test_client_config;
#[cfg(feature = "test-utils")]
pub use tls::generate_self_signed_cert;

#[cfg(feature = "h3")]
/// HTTP request/response types used by the `h3` feature public API.
pub use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
