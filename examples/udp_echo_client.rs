//! A minimal UDP echo client used for learning and testing.
//!
//! This example is intentionally independent of HTTP/3 or MASQUE. It sends a
//! small payload to a UDP echo server and prints the response.
//!
//! Usage:
//!
//! ```text
//! cargo run --example udp_echo_client -- 127.0.0.1:3456 "hello"
//! ```

use std::env;
use std::net::UdpSocket;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <server_addr> <message>", args[0]);
        std::process::exit(1);
    }

    let server_addr = &args[1];
    let message = args[2].as_bytes();

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.connect(server_addr)?;

    socket.send(message)?;
    println!("Sent {} bytes to {}", message.len(), server_addr);

    let mut buf = [0u8; 1024];
    let n = socket.recv(&mut buf)?;
    let response = String::from_utf8_lossy(&buf[..n]);
    println!("Received: {}", response);

    Ok(())
}
