//! A minimal UDP echo client used for learning and testing.
//!
//! This example is intentionally independent of HTTP/3 or MASQUE. It sends a
//! small payload to a UDP echo server and prints the response.
//!
//! Usage:
//!
//! ```text
//! cargo run --package masque --example udp_echo_client -- 127.0.0.1:3456 "hello"
//! ```

use std::env;
use std::net::{SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

/// Buffer size large enough for the biggest standard IPv6 UDP payload (65 535
/// bytes IPv6 payload length minus 8 byte UDP header).
const MAX_UDP_PAYLOAD: usize = 65_527;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let server_addr = args.get(1).map_or("127.0.0.1:3456", String::as_str);
    let message = args.get(2).map_or("hello", String::as_str);

    let server_addr = SocketAddr::from_str(server_addr)?;

    // Bind a socket in the same address family as the server so IPv6 works.
    let bind_addr = match server_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.connect(server_addr)?;

    socket.send(message.as_bytes())?;
    println!("Sent {} bytes to {}", message.len(), server_addr);

    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
    let n = socket.recv(&mut buf)?;
    let response = String::from_utf8_lossy(&buf[..n]);
    println!("Received: {}", response);

    Ok(())
}
