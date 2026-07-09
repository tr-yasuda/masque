//! TLS helpers for local HTTP/3 testing.
//!
//! The functions in this module are intended for examples and tests only. They
//! generate self-signed certificates and disable certificate verification; do
//! not use them in production.

/// HTTP/3 ALPN identifier used by both client and server.
pub const H3_ALPN: &[u8] = b"h3";

#[cfg(feature = "test-utils")]
pub use test_utils::{dangerous_test_client_config, generate_self_signed_cert};

#[cfg(feature = "test-utils")]
mod test_utils {
    use std::sync::Arc;

    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    };

    use crate::{Error, Result};

    /// Generate a self-signed certificate suitable for local testing.
    ///
    /// Returns the certificate chain and private key. The certificate is generated
    /// for the given subject alternative names (typically `&["localhost"]`).
    ///
    /// Empty names are rejected, and the list is bounded to avoid accidental
    /// denial-of-service during certificate generation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCertificate`] if the certificate cannot be generated,
    /// its key cannot be serialized, or the input is empty or unreasonably large.
    pub fn generate_self_signed_cert(
        subject_alt_names: &[&str],
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        const MAX_SANS: usize = 64;
        const MAX_SAN_LEN: usize = 253;

        if subject_alt_names.is_empty() {
            return Err(Error::invalid_certificate_error(
                "subject_alt_names must not be empty",
                None,
            ));
        }
        if subject_alt_names.len() > MAX_SANS {
            return Err(Error::invalid_certificate_error(
                "subject_alt_names must contain at most 64 entries",
                None,
            ));
        }
        for name in subject_alt_names {
            if name.is_empty() {
                return Err(Error::invalid_certificate_error(
                    "subject_alt_names must not contain empty strings",
                    None,
                ));
            }
            if name.len() > MAX_SAN_LEN {
                return Err(Error::invalid_certificate_error(
                    "subject_alt_names entry exceeds maximum length",
                    None,
                ));
            }
        }

        let names: Vec<String> = subject_alt_names.iter().map(|s| s.to_string()).collect();
        let certified_key = rcgen::generate_simple_self_signed(names).map_err(|e| {
            Error::invalid_certificate_error(
                "failed to generate self-signed certificate",
                Some(Box::new(e)),
            )
        })?;

        let cert = CertificateDer::from(certified_key.cert);
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            certified_key.key_pair.serialize_der(),
        ));

        Ok((vec![cert], key))
    }

    #[derive(Debug)]
    struct SkipServerVerification(Arc<CryptoProvider>);

    impl SkipServerVerification {
        fn new() -> Arc<Self> {
            Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
        }
    }

    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Build a [`quinn::ClientConfig`] that trusts any server certificate.
    ///
    /// This is intended for tests that use [`generate_self_signed_cert`] and must
    /// not be used in production.
    pub fn dangerous_test_client_config() -> crate::Result<quinn::ClientConfig> {
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        crypto.alpn_protocols = vec![super::H3_ALPN.into()];

        Ok(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
                crate::Error::transport_error(
                    crate::TransportKind::Other,
                    "failed to build QUIC client config",
                    Some(Box::new(e)),
                )
            })?,
        )))
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;

    #[test]
    fn generate_self_signed_cert_produces_cert_and_key() {
        let (certs, key) = generate_self_signed_cert(&["localhost"]).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_empty());
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn generate_self_signed_cert_rejects_empty_san_list() {
        assert!(generate_self_signed_cert(&[]).is_err());
    }

    #[test]
    fn dangerous_test_client_config_returns_ok() {
        // The helper must succeed and produce a config that can initialize a
        // Quinn endpoint. Whether ALPN is correctly set is verified by the
        // h3_connection integration tests.
        let _config = dangerous_test_client_config().unwrap();
    }
}
