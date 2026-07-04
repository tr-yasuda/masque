//! Stub for a CONNECT-UDP proxy demo.
//!
//! This example is a placeholder. The goal is to demonstrate how a MASQUE
//! CONNECT-UDP proxy can accept HTTP/3 datagrams and forward them over plain
//! UDP once the underlying HTTP/3 and QUIC plumbing is integrated.
//!
//! Usage:
//!
//! ```text
//! cargo run --package masque --example connect_udp_proxy -- 127.0.0.1:8443 127.0.0.1:53
//! ```
//!
//! TODO:
//! - Integrate an HTTP/3 client/server crate (see README for candidates).
//! - Accept CONNECT-UDP requests (`:method = CONNECT`, `:protocol = connect-udp`).
//! - Map HTTP Datagrams (RFC 9297) to UDP payloads.
//! - Implement Capsule Protocol handling for context IDs.

use std::env;

use masque::{Config, Error};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let bind_addr = args.get(1).map_or("127.0.0.1:8443", String::as_str);
    let peer_addr = args.get(2).map_or("127.0.0.1:53", String::as_str);

    let config = Config::new(bind_addr, peer_addr)?;
    println!("CONNECT-UDP proxy stub starting with config: {:?}", config);

    Err(Error::NotImplemented {
        message: "CONNECT-UDP proxy example is not yet implemented".into(),
    }
    .into())
}
