//! A minimal UDP echo server used for learning and testing.
//!
//! This example is intentionally independent of HTTP/3 or MASQUE. It echoes
//! every UDP datagram it receives back to the sender.
//!
//! # Security note
//!
//! This example reflects UDP traffic without authentication or rate limiting.
//! It defaults to `127.0.0.1` and is intended for local learning only. Do not
//! expose it to untrusted networks.
//!
//! Usage:
//!
//! ```text
//! cargo run --package masque --example udp_echo_server -- 127.0.0.1:3456
//! ```

use std::env;
use std::net::UdpSocket;

/// The largest UDP payload for a standard IPv6 datagram (65 535 bytes IPv6
/// payload length minus 8 bytes UDP header). This size also covers the IPv4
/// maximum, so the example works correctly for both address families.
const MAX_UDP_PAYLOAD: usize = 65_527;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let bind_addr = args.get(1).map_or("127.0.0.1:3456", String::as_str);

    let socket = UdpSocket::bind(bind_addr)?;
    println!("UDP echo server listening on {}", socket.local_addr()?);
    println!("WARNING: This example is for local testing only.");

    // Using a Vec keeps the buffer off the stack in case this example is ever
    // spawned on threads with limited stack space.
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to receive datagram: {e}");
                continue;
            }
        };

        if let Err(e) = socket.send_to(&buf[..n], peer) {
            eprintln!("Failed to echo {} bytes to {}: {e}", n, peer);
            continue;
        }

        println!("Echoed {} bytes to {}", n, peer);
    }
}
