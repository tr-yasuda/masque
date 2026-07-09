//! HTTP/3 client scaffolding for MASQUE.
//!
//! This module provides a thin wrapper around [`quinn`] and [`h3`] focused on
//! establishing HTTP/3 connections for CONNECT-UDP tunnels. It is intentionally
//! minimal and not a generic HTTP/3 client.
//!
//! # Runtime requirement
//!
//! [`H3Client::connect`] spawns a background task using [`tokio::spawn`], so it
//! must be called from within a Tokio runtime.

use std::fmt;
use std::net::SocketAddr;

use bytes::Bytes;

use crate::{Error, Result};

/// A minimal HTTP/3 client backed by Quinn.
///
/// `H3Client` owns the underlying QUIC endpoint and a cloneable handle for
/// sending HTTP/3 requests. The HTTP/3 connection driver is spawned onto the
/// current tokio runtime during [`H3Client::connect`].
pub struct H3Client {
    endpoint: quinn::Endpoint,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_handle: tokio::task::JoinHandle<Result<()>>,
}

impl fmt::Debug for H3Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Client")
            .field("endpoint", &self.endpoint)
            .field("send_request", &"...")
            .field("driver_handle", &self.driver_handle)
            .finish()
    }
}

impl H3Client {
    /// Connect to an HTTP/3 server.
    ///
    /// `bind_addr` is the local UDP socket address. `server_addr` is the remote
    /// QUIC address. `server_name` is the TLS server name (e.g. `"localhost"`).
    /// `client_config` must advertise the `h3` ALPN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if the endpoint, QUIC connection, or HTTP/3
    /// handshake cannot be established.
    ///
    /// # Panics
    ///
    /// Panics if called outside of a Tokio runtime, because the HTTP/3
    /// connection driver is spawned with [`tokio::spawn`].
    pub async fn connect(
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
        client_config: quinn::ClientConfig,
    ) -> Result<Self> {
        let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(|e| {
            Error::transport_error("failed to create client endpoint", Some(Box::new(e)))
        })?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(server_addr, server_name)
            .map_err(|e| {
                Error::transport_error("failed to initiate QUIC connection", Some(Box::new(e)))
            })?
            .await
            .map_err(|e| Error::transport_error("QUIC handshake failed", Some(Box::new(e))))?;

        let quinn_conn = h3_quinn::Connection::new(conn);
        let (mut driver, send_request) = h3::client::builder()
            .enable_datagram(true)
            .build(quinn_conn)
            .await
            .map_err(|e| Error::transport_error("HTTP/3 handshake failed", Some(Box::new(e))))?;

        // Drive the connection in the background so callers can issue requests
        // without polling the driver themselves.
        let driver_handle = tokio::spawn(async move {
            let result = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            Err(Error::transport_error(
                "HTTP/3 driver closed",
                Some(Box::new(result)),
            ))
        });

        Ok(Self {
            endpoint,
            send_request,
            driver_handle,
        })
    }

    /// Return the local socket address of the underlying endpoint.
    #[must_use = "the returned address is the only way to discover the bound port when 0 is used"]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| Error::transport_error("failed to get local address", Some(Box::new(e))))
    }

    /// Return a cloneable handle for sending HTTP/3 requests.
    ///
    /// The returned type is part of the [`h3`] public API. Callers that want to
    /// avoid coupling to [`h3`] should use higher-level MASQUE helpers built on
    /// top of this scaffold.
    #[must_use]
    pub fn send_request(&self) -> h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> {
        self.send_request.clone()
    }

    /// Close the underlying QUIC endpoint and wait for the HTTP/3 driver task
    /// to finish.
    ///
    /// `error_code` `0` signals a graceful application close. Any error raised
    /// by the driver task is returned so callers can observe abnormal
    /// connection termination.
    pub async fn close(self) -> Result<()> {
        self.endpoint.close(0u32.into(), b"client closed");
        self.driver_handle
            .await
            .map_err(|e| Error::transport_error("HTTP/3 driver task panicked", Some(Box::new(e))))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_client_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<H3Client>();
    }
}
