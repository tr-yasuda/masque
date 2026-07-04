//! Stub for a CONNECT-UDP proxy demo.
//!
//! This example is a placeholder. The goal is to demonstrate how a MASQUE
//! CONNECT-UDP proxy can accept HTTP/3 datagrams and forward them over plain
//! UDP once the underlying HTTP/3 and QUIC plumbing is integrated.
//!
//! TODO:
//! - Integrate an HTTP/3 client/server crate (see README for candidates).
//! - Accept CONNECT-UDP requests (`:method = CONNECT`, `:protocol = connect-udp`).
//! - Map HTTP Datagrams (RFC 9297) to UDP payloads.
//! - Implement Capsule Protocol handling for context IDs.

use masque::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new("0.0.0.0:8443", "127.0.0.1:53")?;
    println!("CONNECT-UDP proxy stub starting with config: {:?}", config);
    println!("NOTE: This example is not yet implemented. See TODO comments.");

    // TODO: Start HTTP/3 server, accept CONNECT-UDP, forward UDP.
    Ok(())
}
