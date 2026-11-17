// SPDX-License-Identifier: Apache-2.0
//! TLS 1.3 for the TCP listeners, as podman's `system service` has it
//! (`--tls-cert`, `--tls-key`, `--tls-client-ca`): the server's certificate
//! chain and key, and, with a client CA, only clients whose certificate that
//! CA signed.  The files are PEM and are read before the process confines
//! itself.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use std::path::Path;
use std::sync::Arc;

/// The configuration of the TLS listeners.  Clients that send no certificate
/// are refused when `client_ca` is given.
pub fn server_config(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?;
    let builder = match client_ca {
        None => builder.with_no_client_auth(),
        Some(path) => {
            let mut roots = rustls::RootCertStore::empty();
            for ca in CertificateDer::pem_file_iter(path)
                .map_err(|e| format!("{}: {e}", path.display()))?
            {
                let ca = ca.map_err(|e| format!("{}: {e}", path.display()))?;
                roots
                    .add(ca)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let mut config = builder
        .with_single_cert(chain, key)
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    // (the API is HTTP/1: the upgrades of attach and exec)
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
