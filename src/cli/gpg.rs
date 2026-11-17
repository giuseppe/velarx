// SPDX-License-Identifier: Apache-2.0
//! GPG signatures of images (`image sign`, `push --sign-by`): a signature of
//! containers/image's simple signing, made by the `gpg` of the user (the
//! keys, the agent and the pinentry are gpg's: velarx reads no secret key),
//! and written to the signature storage of registries.d (the default
//! directory, or `--directory`).  They are verified by `signedBy` of the
//! policy.  It runs in the CLI, which is the user's process.

#[cfg(feature = "engine")]
mod engine {
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use velarx_signature::reference::DockerRef;
    use velarx_signature::registries_d::{self, RegistriesD};
    use velarx_signature::sigstore::SIMPLE_SIGNING_TYPE;

    /// The signed message of `payload`, by the key `key` of the keyring of
    /// gpg (uncompressed, SHA-256: what the verifier of `signedBy` reads).
    fn gpg_sign(
        key: &str,
        passphrase_file: Option<&Path>,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut gpg = Command::new("gpg");
        gpg.args(["--batch", "--quiet", "--sign", "--compress-algo", "none"])
            .args(["--digest-algo", "SHA256", "--output", "-"])
            .arg(format!("--local-user={key}"));
        if let Some(file) = passphrase_file {
            gpg.args(["--pinentry-mode", "loopback", "--passphrase-file"])
                .arg(file);
        }
        let mut child = gpg
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("cannot run gpg: {e}"))?;
        let mut stdin = child.stdin.take().expect("piped");
        let payload = payload.to_vec();
        // (gpg reads all of it before it writes: no deadlock, a thread anyway
        // for a gpg that stops reading)
        let writer = std::thread::spawn(move || stdin.write_all(&payload));
        let out = child.wait_with_output()?;
        let _ = writer.join();
        if !out.status.success() || out.stdout.is_empty() {
            anyhow::bail!("gpg failed to sign with {key}: {}", out.status);
        }
        Ok(out.stdout)
    }

    /// Where the signatures of an image go: its name in the signatures
    /// and the signature storage, known before anything is pushed or asked
    /// of the registry.
    pub struct Target {
        reference: DockerRef,
        base: String,
    }

    impl Target {
        /// The image named `name` (its tag, `latest` when it has neither a
        /// tag nor a digest), with the signature storage `directory` or the
        /// one registries.d says.
        pub fn new(name: &str, directory: Option<&Path>) -> anyhow::Result<Self> {
            let name = name.strip_prefix("docker://").unwrap_or(name);
            let mut reference = DockerRef::parse_normalized(name).map_err(anyhow::Error::msg)?;
            if reference.tag.is_none() && reference.digest.is_none() {
                reference.tag = Some("latest".into());
            }
            let base = match directory {
                Some(dir) => format!(
                    "file://{}/{}",
                    std::path::absolute(dir)?.display(),
                    reference.path
                ),
                None => RegistriesD::load()
                    .and_then(|c| c.lookaside_base(&reference, true))
                    .map_err(anyhow::Error::msg)?,
            };
            if registries_d::file_path(&base).is_none() {
                anyhow::bail!(
                    "pushing signatures to {base} is not supported: a signature storage to write to is a file: URL"
                );
            }
            Ok(Self { reference, base })
        }

        /// The fully qualified name of the image
        pub fn name(&self) -> String {
            self.reference.string()
        }

        /// Sign the manifest `digest` with `key`.
        pub fn sign(
            &self,
            key: &str,
            passphrase_file: Option<&Path>,
            digest: &str,
        ) -> anyhow::Result<()> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            let payload = velarx_signature::sign::payload(
                SIMPLE_SIGNING_TYPE,
                digest,
                &self.reference.string(),
                &format!("velarx {}", env!("CARGO_PKG_VERSION")),
                now,
            );
            let signed = gpg_sign(key, passphrase_file, &payload)?;
            registries_d::write_lookaside(&self.base, digest, &signed).map_err(anyhow::Error::msg)
        }
    }
}
#[cfg(feature = "engine")]
pub use engine::Target;

/// (the client binary runs these commands in the full one)
#[cfg(not(feature = "engine"))]
pub struct Target(std::convert::Infallible);

#[cfg(not(feature = "engine"))]
impl Target {
    pub fn new(_name: &str, _directory: Option<&std::path::Path>) -> anyhow::Result<Self> {
        unreachable!("GPG signing runs in the full binary")
    }
    pub fn name(&self) -> String {
        match self.0 {}
    }
    pub fn sign(
        &self,
        _key: &str,
        _passphrase_file: Option<&std::path::Path>,
        _digest: &str,
    ) -> anyhow::Result<()> {
        match self.0 {}
    }
}
