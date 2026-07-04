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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let bind_addr = args.get(1).map_or("127.0.0.1:3456", String::as_str);

    let socket = UdpSocket::bind(bind_addr)?;
    println!("UDP echo server listening on {}", socket.local_addr()?);
    println!("WARNING: This example is for local testing only.");

    // Largest possible UDP payload over IPv4. Datagrams larger than this are
    // truncated by the OS before they reach user space.
    let mut buf = [0u8; 65507];
    loop {
        let (n, peer) = socket.recv_from(&mut buf)?;
        socket.send_to(&buf[..n], peer)?;
        println!("Echoed {} bytes to {}", n, peer);
    }
}
