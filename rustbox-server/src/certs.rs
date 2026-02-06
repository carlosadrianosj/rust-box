//! Self-signed TLS certificate generation for QUIC transport.
//!
//! Used by the server to generate a cert at startup. The CRISP layer handles
//! its own crypto, so TLS is only used as the QUIC transport wrapper.

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Generate a self-signed certificate and private key for QUIC/TLS.
///
/// The cert is valid for "localhost" and "127.0.0.1".
/// Returns (certificate_chain, private_key) suitable for rustls ServerConfig.
pub fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).expect("failed to generate cert");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    (vec![cert_der], key_der)
}
