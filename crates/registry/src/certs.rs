// SPDX-License-Identifier: Apache-2.0
//! The certificates of a registry as files: what a client reads from a
//! `--cert-dir` and passes on to the engine, which parses them.

use std::path::Path;

/// The largest certificate file read.
pub const MAX_CERT_FILE_SIZE: u64 = 1024 * 1024;

/// The PEM files of a host.
#[derive(Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RawCerts {
    pub ca: Vec<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
}

/// Without the private key: a `{:?}` of a `RegistryAccess` goes to logs.
impl std::fmt::Debug for RawCerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawCerts")
            .field("ca", &self.ca.len())
            .field("cert", &self.cert.is_some())
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl RawCerts {
    /// The certificates of a `--cert-dir`: `*.crt` CA bundles, a `*.cert`
    /// client certificate with the `*.key` of the same name.  The files
    /// are only read (and capped): the daemon parses them.
    pub fn read_dir(dir: &Path) -> std::io::Result<Self> {
        let mut names: Vec<String> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.starts_with('.'))
            .collect();
        names.sort();
        let read = |name: &str| -> std::io::Result<String> {
            super::read_config_file(&dir.join(name), MAX_CERT_FILE_SIZE)
        };
        let mut raw = RawCerts::default();
        for name in &names {
            if name.ends_with(".crt") {
                raw.ca.push(read(name)?);
            } else if let Some(stem) = name.strip_suffix(".cert") {
                if raw.cert.is_some() {
                    continue;
                }
                let key = format!("{stem}.key");
                if !dir.join(&key).exists() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("missing key `{key}` for the client certificate `{name}`"),
                    ));
                }
                raw.cert = Some(read(name)?);
                raw.key = Some(read(&key)?);
            }
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_debug_of_certificates_has_no_private_key() {
        let c = super::RawCerts {
            ca: vec!["CA PEM".into()],
            cert: Some("CERT PEM".into()),
            key: Some("PRIVATE KEY PEM".into()),
        };
        let shown = format!("{c:?}");
        assert!(!shown.contains("PRIVATE KEY PEM"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }
}
