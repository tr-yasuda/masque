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
//!
//! # Configuration requirement
//!
//! The supplied `client_config` must advertise the HTTP/3 ALPN (`b"h3"`).
//! Quinn does not expose the configured ALPN for pre-flight validation, so the
//! caller is responsible for setting [`crate::H3_ALPN`] on the
//! [`quinn::ClientConfig`].

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;

use crate::{Error, Result, TransportKind};

/// A minimal HTTP/3 client backed by Quinn.
///
/// `H3Client` owns the underlying QUIC endpoint and a cloneable handle for
/// sending HTTP/3 requests. The HTTP/3 connection driver is spawned onto the
/// current tokio runtime during [`H3Client::connect`].
pub struct H3Client {
    endpoint: quinn::Endpoint,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver_handle: Option<tokio::task::JoinHandle<Result<()>>>,
    closing: Arc<AtomicBool>,
}

impl fmt::Debug for H3Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let local_addr = self.endpoint.local_addr().ok();
        f.debug_struct("H3Client")
            .field("local_addr", &local_addr)
            .finish_non_exhaustive()
    }
}

impl H3Client {
    /// Connect to an HTTP/3 server.
    ///
    /// `bind_addr` is the local UDP socket address. `server_addr` is the remote
    /// QUIC address. `server_name` is the TLS server name (e.g. `"localhost"`).
    /// `client_config` must advertise the `h3` ALPN (see [`crate::H3_ALPN`]).
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
            Error::transport_error(
                TransportKind::EndpointCreation,
                "failed to create client endpoint",
                Some(Box::new(e)),
            )
        })?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(server_addr, server_name)
            .map_err(|e| {
                Error::transport_error(
                    TransportKind::Connect,
                    "failed to initiate QUIC connection",
                    Some(Box::new(e)),
                )
            })?
            .await
            .map_err(|e| {
                Error::transport_error(
                    TransportKind::QuicHandshake,
                    "QUIC handshake failed",
                    Some(Box::new(e)),
                )
            })?;

        let quinn_conn = h3_quinn::Connection::new(conn);
        let (mut driver, send_request) = h3::client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build(quinn_conn)
            .await
            .map_err(|e| {
                Error::transport_error(
                    TransportKind::H3Handshake,
                    "HTTP/3 handshake failed",
                    Some(Box::new(e)),
                )
            })?;

        let closing = Arc::new(AtomicBool::new(false));

        // Drive the connection in the background so callers can issue requests
        // without polling the driver themselves.
        let driver_closing = Arc::clone(&closing);
        let driver_handle = Some(tokio::spawn(async move {
            let result = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            if result.is_h3_no_error() || driver_closing.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(Error::transport_error(
                    TransportKind::DriverClosed,
                    "HTTP/3 driver closed with error",
                    Some(Box::new(result)),
                ))
            }
        }));

        Ok(Self {
            endpoint,
            send_request,
            driver_handle,
            closing,
        })
    }

    /// Return the local socket address of the underlying endpoint.
    #[must_use = "the returned address is the only way to discover the bound port when 0 is used"]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(|e| {
            Error::transport_error(
                TransportKind::Other,
                "failed to get local address",
                Some(Box::new(e)),
            )
        })
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
    /// Uses [`h3::error::Code::H3_NO_ERROR`] to signal a graceful HTTP/3 close.
    /// Any error raised by the driver task is returned so callers can observe
    /// abnormal connection termination.
    pub async fn close(mut self) -> Result<()> {
        self.closing.store(true, Ordering::SeqCst);
        self.endpoint.close(h3_no_error_varint(), b"client closed");
        match self.driver_handle.take() {
            Some(handle) => handle.await.map_err(|e| {
                Error::transport_error(
                    TransportKind::Close,
                    "HTTP/3 driver task panicked",
                    Some(Box::new(e)),
                )
            })?,
            None => Ok(()),
        }
    }
}

impl Drop for H3Client {
    fn drop(&mut self) {
        // Close the endpoint so the driver observes a local close and the
        // background task can finish. Then abort the handle in case the driver
        // is still blocked.
        self.closing.store(true, Ordering::SeqCst);
        self.endpoint.close(h3_no_error_varint(), b"client dropped");
        if let Some(handle) = self.driver_handle.take() {
            handle.abort();
        }
    }
}

/// Returns the HTTP/3 `H3_NO_ERROR` code as a [`quinn::VarInt`].
fn h3_no_error_varint() -> quinn::VarInt {
    quinn::VarInt::from_u64(h3::error::Code::H3_NO_ERROR.value())
        .expect("H3_NO_ERROR fits in a QUIC varint")
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
