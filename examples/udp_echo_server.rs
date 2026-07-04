//! A minimal UDP echo server used for learning and testing.
//!
//! This example is intentionally independent of HTTP/3 or MASQUE. It echoes
//! every UDP datagram it receives back to the sender.
//!
//! Usage:
//!
//! ```text
//! cargo run --example udp_echo_server -- 127.0.0.1:3456
//! ```

use std::env;
use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let bind_addr = args.get(1).map_or("127.0.0.1:3456", String::as_str);

    let socket = UdpSocket::bind(bind_addr)?;
    println!("UDP echo server listening on {}", socket.local_addr()?);

    let mut buf = [0u8; 1024];
    loop {
        let (n, peer) = socket.recv_from(&mut buf)?;
        socket.send_to(&buf[..n], peer)?;
        println!("Echoed {} bytes to {}", n, peer);
    }
}
