// SPDX-License-Identifier: Apache-2.0
//! The bearer token that a TCP listener of the API asks for: a secret in a
//! file only its owner reads, which a client sends as `Authorization: Bearer
//! TOKEN`.  The socket of a unix listener has the permissions of its file and
//! `SO_PEERCRED`; a TCP port has neither, so every local user that can connect
//! would control the engine without it.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The shortest token accepted: 16 bytes of a random source make a token
/// that cannot be guessed (`head -c 32 /dev/urandom | base64`).
pub const MIN_LEN: usize = 16;

/// The token of a TCP listener.
pub struct Token(Vec<u8>);

impl Token {
    /// The token in `path`: a regular file of this user (or of root) that no
    /// other user can read, with a token of at least [`MIN_LEN`] bytes made of
    /// printable characters (the end of line is not part of it).
    pub fn load(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let meta = file
            .metadata()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "{}: mode {:o}: the token must not be readable by others (chmod 600)",
                path.display(),
                meta.mode() & 0o777
            ));
        }
        let me = rustix::process::geteuid().as_raw();
        if meta.uid() != me && meta.uid() != 0 {
            return Err(format!(
                "{}: owned by uid {}, not by this user or root",
                path.display(),
                meta.uid()
            ));
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut &file, &mut bytes)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Self::new(&bytes).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn new(bytes: &[u8]) -> Result<Self, String> {
        let token = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        if token.len() < MIN_LEN {
            return Err(format!("the token has fewer than {MIN_LEN} bytes"));
        }
        if !token.iter().all(|b| b.is_ascii_graphic()) {
            return Err("the token has a space or a character that is not printable".into());
        }
        Ok(Self(token.to_vec()))
    }

    /// Whether `authorization` (the value of the header of a request) is
    /// `Bearer` and this token.  The comparison takes the same time wherever
    /// the two differ.
    pub fn accepts(&self, authorization: Option<&[u8]>) -> bool {
        let Some(value) = authorization else {
            return false;
        };
        let Some(given) = value.strip_prefix(b"Bearer ") else {
            return false;
        };
        let mut diff = (given.len() ^ self.0.len()) as u64;
        for (i, b) in self.0.iter().enumerate() {
            diff |= u64::from(b ^ given.get(i).copied().unwrap_or(0));
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const TOKEN: &[u8] = b"0123456789abcdefXYZ";

    fn file(mode: u32, content: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        (dir, path)
    }

    #[test]
    fn only_the_bearer_token_is_accepted() {
        let (_d, path) = file(0o600, b"0123456789abcdefXYZ\n");
        let t = Token::load(&path).unwrap();
        assert!(t.accepts(Some(b"Bearer 0123456789abcdefXYZ")));
        for bad in [
            None,
            Some(&b""[..]),
            Some(b"Bearer "),
            Some(b"Bearer 0123456789abcdefXY"),
            Some(b"Bearer 0123456789abcdefXYZ "),
            Some(b"Bearer 0123456789abcdefXYz"),
            Some(b"bearer 0123456789abcdefXYZ"),
            Some(b"0123456789abcdefXYZ"),
            Some(b"Basic 0123456789abcdefXYZ"),
        ] {
            assert!(!t.accepts(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_token_file_others_can_read_is_refused() {
        for mode in [0o644, 0o640, 0o604, 0o666] {
            let (_d, path) = file(mode, TOKEN);
            let e = Token::load(&path).err().unwrap();
            assert!(e.contains("must not be readable"), "{mode:o}: {e}");
        }
        assert!(Token::load(&file(0o400, TOKEN).1).is_ok());
    }

    #[test]
    fn a_token_that_is_short_or_not_printable_is_refused() {
        for content in [
            &b""[..],
            b"\n",
            b"short",
            b"0123456789abcde\n",
            b"0123456789 abcdefgh",
            b"0123456789abcdef\0\0",
        ] {
            let (_d, path) = file(0o600, content);
            assert!(Token::load(&path).is_err(), "{content:?}");
        }
    }

    #[test]
    fn a_missing_file_or_a_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Token::load(&dir.path().join("none")).is_err());
        assert!(Token::load(dir.path()).is_err());
    }
}
