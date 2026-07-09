//! HTTP/3 server scaffolding for MASQUE.
//!
//! This module provides a thin wrapper around [`quinn`] and [`h3`] focused on
//! accepting HTTP/3 connections for CONNECT-UDP tunnels. It is intentionally
//! minimal and not a generic HTTP/3 server.

use std::fmt;
use std::net::SocketAddr;

use bytes::Bytes;

use crate::{Error, Result};

/// A minimal HTTP/3 server backed by Quinn.
///
/// `H3Server` listens on a UDP socket and accepts incoming QUIC connections,
/// returning an [`H3Connection`] for each successfully established HTTP/3
/// connection.
#[derive(Debug)]
pub struct H3Server {
    endpoint: quinn::Endpoint,
}

impl H3Server {
    /// Bind a UDP socket and start listening for HTTP/3 connections.
    ///
    /// `server_config` must advertise the `h3` ALPN and present a valid TLS
    /// certificate.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the QUIC endpoint cannot be created.
    pub fn bind(bind_addr: SocketAddr, server_config: quinn::ServerConfig) -> Result<Self> {
        let endpoint = quinn::Endpoint::server(server_config, bind_addr).map_err(|e| {
            Error::transport_error("failed to create server endpoint", Some(Box::new(e)))
        })?;
        Ok(Self { endpoint })
    }

    /// Accept the next incoming HTTP/3 connection.
    ///
    /// Returns `Ok(None)` when the endpoint has been closed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the QUIC handshake or HTTP/3 handshake
    /// fails.
    pub async fn accept(&mut self) -> Result<Option<H3Connection>> {
        let incoming = match self.endpoint.accept().await {
            Some(conn) => conn,
            None => return Ok(None),
        };

        let conn = incoming
            .await
            .map_err(|e| Error::transport_error("QUIC handshake failed", Some(Box::new(e))))?;
        let remote_addr = conn.remote_address();

        let h3_conn = h3::server::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| Error::transport_error("HTTP/3 handshake failed", Some(Box::new(e))))?;

        Ok(Some(H3Connection {
            connection: h3_conn,
            remote_addr,
        }))
    }

    /// Return the local socket address the server is bound to.
    #[must_use = "the returned address is the only way to discover the bound port when 0 is used"]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| Error::transport_error("failed to get local address", Some(Box::new(e))))
    }

    /// Close the underlying QUIC endpoint.
    ///
    /// Uses [`h3::error::Code::H3_NO_ERROR`] to signal a graceful HTTP/3 close.
    /// Existing connections accepted before this call are not forcibly
    /// terminated by this method.
    pub fn close(&self) {
        self.endpoint.close(
            quinn::VarInt::from_u32(h3::error::Code::H3_NO_ERROR.value() as u32),
            b"server closed",
        );
    }
}

/// An established HTTP/3 server connection.
pub struct H3Connection {
    connection: h3::server::Connection<h3_quinn::Connection, Bytes>,
    remote_addr: SocketAddr,
}

impl fmt::Debug for H3Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Connection")
            .field("connection", &"...")
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}

impl H3Connection {
    /// Return the remote socket address of this connection.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Accept the next incoming HTTP/3 request on this connection.
    ///
    /// Returns `Ok(None)` when the peer has sent a GOAWAY frame or the
    /// connection is otherwise closed to new requests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if an HTTP/3 error occurs while accepting.
    pub async fn accept_request(
        &mut self,
    ) -> Result<Option<h3::server::RequestResolver<h3_quinn::Connection, Bytes>>> {
        self.connection.accept().await.map_err(|e| {
            Error::transport_error("failed to accept HTTP/3 request", Some(Box::new(e)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_server_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<H3Server>();
        assert_send_sync::<H3Connection>();
    }
}
