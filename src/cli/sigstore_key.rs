// SPDX-License-Identifier: Apache-2.0
//! `image generate-sigstore-key`: a key pair to sign images with, as
//! `skopeo generate-sigstore-key` writes it (and `cosign generate-key-pair`
//! reads it): PREFIX.private, the encrypted private key, and PREFIX.pub.
//! It runs in the CLI, with no engine.

#[cfg(feature = "engine")]
mod engine {
    use std::ffi::OsString;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use zeroize::Zeroizing;

    /// The passphrase of the new key: the first line of `file`, as the
    /// passphrase of `--sign-passphrase-file` is read, else what `ask`
    /// reads twice from the terminal, which must agree and not be empty.
    fn passphrase(
        file: Option<&Path>,
        ask: impl Fn(&str) -> std::io::Result<String>,
    ) -> anyhow::Result<Zeroizing<String>> {
        if let Some(file) = file {
            let text =
                Zeroizing::new(crate::cli::image_args::read_secret(file, 64 << 10).map_err(
                    |e| anyhow::anyhow!("reading the passphrase file {}: {e}", file.display()),
                )?);
            return Ok(Zeroizing::new(
                text.lines().next().unwrap_or_default().to_string(),
            ));
        }
        let first = Zeroizing::new(ask("Passphrase for the key: ")?);
        let second = Zeroizing::new(ask("Passphrase again: ")?);
        if first != second {
            anyhow::bail!("the passphrases do not match");
        }
        if first.is_empty() {
            anyhow::bail!(
                "the passphrase is empty: give an empty --passphrase-file for a key without one"
            );
        }
        Ok(first)
    }

    /// The prompt on the terminal, with no echo.
    fn prompt(text: &str) -> std::io::Result<String> {
        if !rustix::termios::isatty(std::io::stdin()) {
            return Err(std::io::Error::other(
                "no terminal to ask the passphrase on: give --passphrase-file",
            ));
        }
        crate::cli::image_args::prompt_password(text)
    }

    /// Create `path`, which must not exist, with `mode`; a link at its
    /// place is not followed.
    fn create(path: &Path, mode: u32, data: &[u8]) -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(mode)
            .open(path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    anyhow::anyhow!("{} exists: not overwritten", path.display())
                }
                _ => anyhow::anyhow!("creating {}: {e}", path.display()),
            })?;
        let written = f
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .and_then(|()| f.write_all(data))
            .and_then(|()| f.sync_all());
        if let Err(e) = written {
            drop(f);
            let _ = std::fs::remove_file(path);
            anyhow::bail!("writing {}: {e}", path.display());
        }
        Ok(())
    }

    fn with_suffix(prefix: &Path, suffix: &str) -> PathBuf {
        let mut name = OsString::from(prefix);
        name.push(suffix);
        name.into()
    }

    /// Make the key pair and write it to `prefix`.private (0600) and
    /// `prefix`.pub (0644); neither is replaced when it exists.
    fn generate(
        prefix: &Path,
        passphrase_file: Option<&Path>,
        ask: impl Fn(&str) -> std::io::Result<String>,
    ) -> anyhow::Result<(PathBuf, PathBuf)> {
        let private = with_suffix(prefix, ".private");
        let public = with_suffix(prefix, ".pub");
        // (before asking for a passphrase)
        for file in [&private, &public] {
            if std::fs::symlink_metadata(file).is_ok() {
                anyhow::bail!("{} exists: not overwritten", file.display());
            }
        }
        let pass = passphrase(passphrase_file, ask)?;
        let (key, pubkey) = velarx_signature::sign::generate_key_pair(pass.as_bytes())
            .map_err(anyhow::Error::msg)?;
        create(&private, 0o600, key.as_bytes())?;
        if let Err(e) = create(&public, 0o644, pubkey.as_bytes()) {
            let _ = std::fs::remove_file(&private);
            return Err(e);
        }
        Ok((private, public))
    }

    pub fn run(prefix: &Path, passphrase_file: Option<&Path>) -> anyhow::Result<()> {
        let (private, public) = generate(prefix, passphrase_file, prompt)?;
        println!(
            "Key written to {:?} and {:?}",
            private.display().to_string(),
            public.display().to_string()
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use velarx_signature::sign::{KeyFiles, Signer};

        fn never(_: &str) -> std::io::Result<String> {
            panic!("asked");
        }

        fn load(private: &Path, pass: &str) -> Result<Signer, velarx_signature::sigstore::Error> {
            Signer::load(&KeyFiles {
                key: std::fs::read(private).unwrap(),
                passphrase: pass.as_bytes().to_vec(),
            })
        }

        #[test]
        fn the_files_are_written_with_their_modes_and_load() {
            let dir = tempfile::tempdir().unwrap();
            let pass = dir.path().join("pass");
            std::fs::write(&pass, "secret\nsecond line\n").unwrap();
            let prefix = dir.path().join("k");
            let (private, public) = generate(&prefix, Some(&pass), never).unwrap();
            assert_eq!(private, dir.path().join("k.private"));
            assert_eq!(public, dir.path().join("k.pub"));
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&private), 0o600);
            assert_eq!(mode(&public), 0o644);
            assert!(std::fs::read_to_string(&public)
                .unwrap()
                .starts_with("-----BEGIN PUBLIC KEY-----"));
            load(&private, "secret").unwrap();
            assert!(load(&private, "other").is_err());
        }

        #[test]
        fn an_existing_file_is_not_replaced() {
            let dir = tempfile::tempdir().unwrap();
            let pass = dir.path().join("pass");
            std::fs::write(&pass, "x").unwrap();
            let prefix = dir.path().join("k");
            for (existing, other) in [("k.pub", "k.private"), ("k.private", "k.pub")] {
                std::fs::write(dir.path().join(existing), "mine").unwrap();
                let e = generate(&prefix, Some(&pass), never).unwrap_err();
                assert!(e.to_string().contains(existing), "{e}");
                assert_eq!(
                    std::fs::read_to_string(dir.path().join(existing)).unwrap(),
                    "mine"
                );
                assert!(!dir.path().join(other).exists());
                std::fs::remove_file(dir.path().join(existing)).unwrap();
            }
            // a dangling link is an existing file too
            std::os::unix::fs::symlink(dir.path().join("nowhere"), dir.path().join("k.private"))
                .unwrap();
            assert!(generate(&prefix, Some(&pass), never).is_err());
            assert!(!dir.path().join("nowhere").exists());
        }

        #[test]
        fn the_prompts_must_agree_and_not_be_empty() {
            let dir = tempfile::tempdir().unwrap();
            let prefix = dir.path().join("k");
            let answers = std::cell::RefCell::new(vec!["b".to_string(), "a".to_string()]);
            let ask = |_: &str| Ok(answers.borrow_mut().pop().unwrap());
            let e = generate(&prefix, None, ask).unwrap_err();
            assert_eq!(e.to_string(), "the passphrases do not match");
            let e = generate(&prefix, None, |_: &str| Ok(String::new())).unwrap_err();
            assert!(e.to_string().contains("empty"), "{e}");
            assert!(!dir.path().join("k.private").exists());
            let ok = generate(&prefix, None, |_: &str| Ok("same".to_string())).unwrap();
            load(&ok.0, "same").unwrap();
        }

        #[test]
        fn an_empty_passphrase_file_makes_a_key_without_one() {
            let dir = tempfile::tempdir().unwrap();
            let pass = dir.path().join("pass");
            std::fs::write(&pass, "").unwrap();
            let (private, _) = generate(&dir.path().join("k"), Some(&pass), never).unwrap();
            load(&private, "").unwrap();
        }
    }
}
#[cfg(feature = "engine")]
pub use engine::run;
