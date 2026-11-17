// SPDX-License-Identifier: Apache-2.0
//! The check of the credentials of `login` (the `/auth` route) by a process
//! that reaches the registry itself: a confined pull worker when the pulls
//! are confined, else the daemon.  It is the registry client's check
//! (`GET /v2/` with the credentials, its token service when it has one), so
//! the connection, the certificates and the challenge are the ones of every
//! other request.

use std::path::PathBuf;
use velarx_registry::auth::RegistryAccess;
use velarx_registry::client::RegistryClient;
use velarx_registry::target::Target;
use velarx_registry::target::TransportConfig;
use velarx_registry::AuthConfig;
use velarx_types::{ImageReference, ImageResult};

/// Whether the registry HOST (`host[:port]`, docker.io as
/// registry-1.docker.io) accepts the credentials of ACCESS; else why
/// (`Unauthorized`: it refused them), in podman's words.  Without `tls_verify` the certificate is not checked and
/// the registry is tried over http too for a registry on the loopback.  The certificates of `access` come first, then the
/// directories CERTS_DIRS (a confined worker has none to read).
pub async fn check(
    host: &str,
    access: &RegistryAccess,
    tls_verify: bool,
    certs_dirs: Vec<PathBuf>,
) -> ImageResult<()> {
    let client = client(access, tls_verify, certs_dirs);
    let target = target(&client, host)?;
    client.check_login(&target).await
}

/// ACCESS with the certificates for HOST in it: its own, else those of the
/// directories CERTS_DIRS.  What a confined worker is given, as for a pull:
/// it reads no directory of certificates itself.
pub fn with_certificates(
    host: &str,
    access: &RegistryAccess,
    tls_verify: bool,
    certs_dirs: Vec<PathBuf>,
) -> ImageResult<RegistryAccess> {
    if access.certs.is_some() {
        return Ok(access.clone());
    }
    let target = target(&client(access, tls_verify, certs_dirs), host)?;
    Ok(RegistryAccess {
        certs: Some(target.certs.clone()),
        ..access.clone()
    })
}

/// The registry client of a login: no `registries.conf` (podman's login
/// asks the host it is given), the certificates of ACCESS, else those of
/// CERTS_DIRS.
fn client(access: &RegistryAccess, tls_verify: bool, certs_dirs: Vec<PathBuf>) -> RegistryClient {
    RegistryClient::with_config(
        TransportConfig {
            registries: Default::default(),
            certs_dirs,
            tls_verify,
        },
        AuthConfig::default(),
    )
    .with_access(access)
}

/// The registry HOST as a target of CLIENT.
fn target(client: &RegistryClient, host: &str) -> ImageResult<Target> {
    client.push_target(&ImageReference::parse(&format!("{host}/library/login"))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use velarx_content::pull::net::origin::failure_text;
    use velarx_types::ImageError;

    /// A registry over http that answers `/v2/` with STATUS, to the first
    /// request that has the Authorization header it wants.
    async fn registry(status: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = conn.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).to_string();
                    let answer = if request.starts_with("GET /v2/") {
                        status
                    } else {
                        "404 Not Found"
                    };
                    let _ = conn
                        .write_all(
                            format!("HTTP/1.1 {answer}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                .as_bytes(),
                        )
                        .await;
                });
            }
        });
        addr.to_string()
    }

    fn access() -> RegistryAccess {
        RegistryAccess {
            creds: Some(velarx_registry::Credentials {
                username: "user".into(),
                password: "secret".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// A self-signed CA, for its file in a directory of certificates.
    const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBiDCCAS2gAwIBAgIUSRyQakqoWzCbxx+1iHwqr2defKUwCgYIKoZIzj0EAwIw\nGDEWMBQGA1UEAwwNcmVnaXN0cnkudGVzdDAgFw0yNjExMDEyMDM3MjBaGA8yMTI2\nMTAwODIwMzcyMFowGDEWMBQGA1UEAwwNcmVnaXN0cnkudGVzdDBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABLSY++IXiMQyGwb4P/O4RZ/kFwWuw28QYtBQNS9+n93T\nsmIvPo6smsAMXvC6IlZTqRBR1LM8fqHlgG1fZMGKwvejUzBRMB0GA1UdDgQWBBRp\n5QbAr/OeSe2a9XdMjuzicyAfBzAfBgNVHSMEGDAWgBRp5QbAr/OeSe2a9XdMjuzi\ncyAfBzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCuM4I0cnBx\noLtKKMPwdDC9hVmgxck5UQ7Wj1uY/HvWcQIhAP7++Mzk4IBRucpB8etfWHBLdIId\nFxqkasKW0pCw4wGy\n-----END CERTIFICATE-----\n";

    /// A worker reads no directory of certificates: the ones of the host
    /// go in the request, those of the request first.
    #[test]
    fn the_certificates_of_the_host_go_to_the_worker() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("registry.test:5000");
        std::fs::create_dir(&host).unwrap();
        std::fs::write(host.join("ca.crt"), CA).unwrap();
        let dirs = vec![dir.path().to_path_buf()];
        let given = with_certificates("registry.test:5000", &access(), true, dirs.clone()).unwrap();
        assert_eq!(given.certs.unwrap().ca, vec![CA.to_string()]);
        assert_eq!(given.creds, access().creds);
        let other = with_certificates("other.test", &access(), true, dirs.clone()).unwrap();
        assert!(other.certs.unwrap().ca.is_empty());
        let own = RegistryAccess {
            certs: Some(Default::default()),
            ..access()
        };
        let kept = with_certificates("registry.test:5000", &own, true, dirs).unwrap();
        assert!(kept.certs.unwrap().ca.is_empty());
    }

    #[tokio::test]
    async fn a_registry_that_takes_the_credentials_is_ok() {
        let host = registry("200 OK").await;
        check(&host, &access(), false, Vec::new()).await.unwrap();
    }

    #[tokio::test]
    async fn a_registry_that_refuses_them_says_so_in_podmans_words() {
        let host = registry("401 Unauthorized").await;
        let e = check(&host, &access(), false, Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(e, ImageError::Unauthorized(_)), "{e}");
        assert_eq!(failure_text(&e), "invalid username/password");
    }

    /// With the certificate checked there is no http: a registry that
    /// speaks it only is unreachable, not one that accepted the login.
    #[tokio::test]
    async fn a_checked_registry_is_not_tried_over_http() {
        let host = registry("200 OK").await;
        let e = check(&host, &access(), true, Vec::new()).await.unwrap_err();
        assert!(!matches!(e, ImageError::Unauthorized(_)), "{e}");
        assert!(
            failure_text(&e).contains("pinging container registry"),
            "{e}"
        );
    }
}
