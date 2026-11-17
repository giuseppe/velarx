// SPDX-License-Identifier: Apache-2.0
//! The fs-verity check of the files of an image when they are opened
//!.  The store measured each file's fs-verity digest when its
//! content had just been checked against its digest, and recorded it; the
//! daemon gives the monitor those of the files of its images.  A file of
//! the store is served only when it has that fs-verity digest: the kernel
//! then checks every page read against it, also through FUSE passthrough,
//! where this process sees no read.  A file of the store is named by its
//! fs-verity digest: where the store has fs-verity (`On`) that is the
//! digest it must have, as the kernel's overlay with `verity=on` checks
//! the digest of the stub of a file against the file it redirects to (a
//! file without fs-verity is refused); with `Require` every file must
//! have it, also those fetched elsewhere.
//!
//! Where the digests of an image are enforced (`enforced`) the file system
//! does what the kernel's overlay does with `verity=require` for the files
//! it cannot serve itself: the file is opened by `FileStore::open_object`,
//! measured on that descriptor, and must have the fs-verity digest the stub
//! of the EROFS image states, else the open fails with EIO.  What is read is
//! read from that descriptor; the verdict belongs to the open file, so a file
//! replaced between two opens is measured again.
//!
//! A file of the staging of a lazy pull was written by a fetcher, which is
//! not trusted: it is named by its fs-verity digest (the one the table of
//! contents gives) and must have it, whatever the mode, on the descriptor
//! that is served.  Where the file has no fs-verity (a store without it,
//! mode `Off`) the digest is computed from its content on that descriptor
//! at each open; the kernel then does not keep the file from changing
//! after the check (THREAT-MODEL, the staging of a store without
//! fs-verity).

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::sync::Mutex;
use tracing::{debug, error};
use velarx_storage::VerityMode;

/// The fs-verity digest of an open file: Some when it has fs-verity, None
/// when it has not or its file system cannot, Err on another failure.
pub type Measure = fn(&File) -> Result<Option<String>, String>;

/// The fs-verity digest of the content of an open file, computed from it,
/// in the algorithm of the digest it is named by.
pub type Compute = fn(&File, &str) -> Result<String, String>;

fn compute(file: &File, name: &str) -> Result<String, String> {
    let alg = velarx_types::digest::Digest::parse_fsverity(name)
        .map_err(|e| e.to_string())?
        .alg();
    velarx_storage::fsverity_digest_file(alg, file).map_err(|e| e.to_string())
}

fn measure(file: &File) -> Result<Option<String>, String> {
    use velarx_storage::FsVerityError;
    match velarx_storage::measure_file(file) {
        // (the object's name: its algorithm is the kernel's, the file's own)
        Ok(m) => Ok(m.object().map(|d| d.to_string())),
        Err(FsVerityError::NotEnabled | FsVerityError::NotSupported) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub struct Verity {
    /// By digest of file content: the fs-verity digest it must have.
    expected: HashMap<String, String>,
    /// What a file without an expectation must have: nothing (`Off`), the
    /// digest it is named by when it is a file of the store (`On`), or
    /// wherever it is (`Require`).
    mode: VerityMode,
    measure: Measure,
    compute: Compute,
    /// The digests of the image are enforced: `local` opens strictly and
    /// the failures are told once a file in the debug log.
    enforced: bool,
    /// The files already told as broken (one line each).
    told: Mutex<HashSet<String>>,
}

impl Default for Verity {
    fn default() -> Self {
        Self::new(HashMap::new(), VerityMode::Off)
    }
}

impl Verity {
    pub fn new(expected: HashMap<String, String>, mode: VerityMode) -> Self {
        Self::with_measure(expected, mode, measure, compute)
    }

    pub fn with_measure(
        expected: HashMap<String, String>,
        mode: VerityMode,
        measure: Measure,
        compute: Compute,
    ) -> Self {
        Self {
            expected,
            mode,
            measure,
            compute,
            enforced: false,
            told: Mutex::new(HashSet::new()),
        }
    }

    /// The same, for an image whose digests are enforced.
    pub fn enforced(mut self) -> Self {
        self.enforced = true;
        self
    }

    /// Whether the digests of the image are enforced.
    pub fn is_enforced(&self) -> bool {
        self.enforced
    }

    /// Say in the debug log that the file `digest` of the store broke the
    /// chain (expected, found): once for each file.
    pub fn broken(&self, digest: &str, expected: &str, found: &str) {
        if self.enforced
            && self
                .told
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(digest.to_string())
        {
            debug!(
                "verity chain: BROKEN fuse object {} expected {expected} found {found}",
                velarx_storage::Object::new(digest, false)
                    .map_or_else(|| digest.to_string(), |o| o.rel())
            );
        }
    }

    /// Whether `file`, opened for the content `digest` (from the store when
    /// `stored`, else from the staging), may be served: Err(EIO) when it
    /// does not have the fs-verity digest it must.  The kernel gives the
    /// digest of an open file in constant time.
    pub fn check(&self, digest: &str, file: &File, stored: bool) -> Result<(), i32> {
        // (a file of the store is named by its fs-verity digest where the
        // store has fs-verity)
        let named = self.mode != VerityMode::Off;
        // Enforced: the digest the stub of the verified image states, as the
        // kernel compares with; a file of the staging, written by a fetcher,
        // is named by its fs-verity digest whatever the mode.
        let expected = match self.enforced || !stored {
            true => Some(digest.to_string()),
            false => self
                .expected
                .get(digest)
                .cloned()
                .or_else(|| named.then(|| digest.to_string())),
        };
        let Some(expected) = expected else {
            return Ok(());
        };
        let measured = match (self.measure)(file) {
            // (a staged file of a store without fs-verity: its content)
            Ok(None) if !stored && self.mode == VerityMode::Off && !self.enforced => {
                (self.compute)(file, &expected).map(Some)
            }
            m => m,
        };
        match &measured {
            Ok(Some(m)) if *m == expected => Ok(()),
            _ => {
                self.broken(
                    digest,
                    &expected,
                    &match &measured {
                        Ok(Some(m)) => m.clone(),
                        Ok(None) => "none".into(),
                        Err(e) => format!("unknown ({e})"),
                    },
                );
                error!(
                    "{digest} of the store is not served: its fs-verity digest is {}, not {}",
                    match &measured {
                        Ok(Some(m)) => m.clone(),
                        Ok(None) => "none".into(),
                        Err(e) => format!("unknown ({e})"),
                    },
                    expected
                );
                Err(libc::EIO)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake measure: the first line of the file is its fs-verity
    /// digest, `none` for a file without.
    fn fake(file: &File) -> Result<Option<String>, String> {
        use std::io::Read;
        let mut s = String::new();
        (&*file).read_to_string(&mut s).map_err(|e| e.to_string())?;
        match s.lines().next() {
            Some("none") | None => Ok(None),
            Some("error") => Err("failed".into()),
            Some(l) => Ok(Some(l.to_string())),
        }
    }

    /// A fake computed digest: the last line of the file.
    fn fake_compute(file: &File, _name: &str) -> Result<String, String> {
        use std::io::{Read, Seek};
        let mut s = String::new();
        (&*file).rewind().map_err(|e| e.to_string())?;
        (&*file).read_to_string(&mut s).map_err(|e| e.to_string())?;
        Ok(s.lines().last().unwrap_or_default().to_string())
    }

    fn file(content: &str) -> File {
        let mut f = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut f, content.as_bytes()).unwrap();
        std::io::Seek::rewind(&mut f).unwrap();
        f
    }

    fn check(v: &Verity, digest: &str, content: &str) -> Result<(), i32> {
        v.check(digest, &file(content), true)
    }

    #[test]
    fn files_must_have_their_recorded_digest() {
        let expected = HashMap::from([("sha256:a".to_string(), "sha256:va".to_string())]);
        let v = Verity::with_measure(expected, VerityMode::Off, fake, fake_compute);
        assert_eq!(check(&v, "sha256:a", "sha256:va"), Ok(()));
        // replaced by another content, or without fs-verity, or unknown
        assert_eq!(check(&v, "sha256:a", "sha256:vb"), Err(libc::EIO));
        assert_eq!(check(&v, "sha256:a", "none"), Err(libc::EIO));
        assert_eq!(check(&v, "sha256:a", "error"), Err(libc::EIO));
        // a file without an expectation is served, whatever it has
        assert_eq!(check(&v, "sha256:b", "none"), Ok(()));
        assert_eq!(check(&v, "sha256:b", "sha256:x"), Ok(()));
    }

    #[test]
    fn required_verity_refuses_files_without_an_expectation() {
        let v = Verity::with_measure(HashMap::new(), VerityMode::Require, fake, fake_compute);
        assert_eq!(check(&v, "sha256:b", "sha256:x"), Err(libc::EIO));
        assert_eq!(check(&v, "sha256:b", "none"), Err(libc::EIO));
        // wherever it is: a staged file has the digest it is named by
        assert_eq!(v.check("sha256:c", &file("sha256:c"), false), Ok(()));
        assert_eq!(
            v.check("sha256:c", &file("sha256:x"), false),
            Err(libc::EIO)
        );
        // (never computed: it must have fs-verity)
        assert_eq!(
            v.check("sha256:c", &file("none\nsha256:c"), false),
            Err(libc::EIO)
        );
    }

    #[test]
    fn files_of_a_store_with_verity_must_have_their_name() {
        let v = Verity::with_measure(HashMap::new(), VerityMode::On, fake, fake_compute);
        assert_eq!(check(&v, "sha256:a", "sha256:a"), Ok(()));
        // replaced by another content, by a file without fs-verity (the
        // overlay's `verity=on` refuses it too), or not measured
        assert_eq!(check(&v, "sha256:a", "sha256:b"), Err(libc::EIO));
        assert_eq!(check(&v, "sha256:a", "none"), Err(libc::EIO));
        assert_eq!(check(&v, "sha256:a", "error"), Err(libc::EIO));
        // a file of the staging, written by a fetcher, must have its name
        // too: one without fs-verity is refused
        assert_eq!(v.check("sha256:s", &file("none"), false), Err(libc::EIO));
        assert_eq!(v.check("sha256:t", &file("sha256:t"), false), Ok(()));
        assert_eq!(
            v.check("sha256:t", &file("sha256:x"), false),
            Err(libc::EIO)
        );
        // without fs-verity in the store nothing of the store is measured
        let off = Verity::with_measure(
            HashMap::new(),
            VerityMode::Off,
            |_| unreachable!(),
            |_, _| unreachable!(),
        );
        assert_eq!(check(&off, "sha256:a", "none"), Ok(()));
    }

    /// A file of the staging is never served unchecked, also where the
    /// store has no fs-verity: its fs-verity digest is computed from its
    /// content.
    #[test]
    fn a_staged_file_is_checked_without_fs_verity() {
        let off = Verity::with_measure(HashMap::new(), VerityMode::Off, fake, fake_compute);
        assert_eq!(
            off.check("sha256:s", &file("none\nsha256:s"), false),
            Ok(())
        );
        assert_eq!(
            off.check("sha256:s", &file("none\nsha256:x"), false),
            Err(libc::EIO)
        );
        // one with fs-verity is measured
        assert_eq!(off.check("sha256:s", &file("sha256:s"), false), Ok(()));
        assert_eq!(
            off.check("sha256:s", &file("sha256:x"), false),
            Err(libc::EIO)
        );
        assert_eq!(off.check("sha256:s", &file("error"), false), Err(libc::EIO));
    }

    #[test]
    fn an_enforced_check_wants_the_name_of_every_file() {
        // (whatever the mode says: the digests of the image are enforced)
        let v =
            Verity::with_measure(HashMap::new(), VerityMode::Off, fake, fake_compute).enforced();
        assert!(v.is_enforced());
        assert_eq!(check(&v, "sha256:a", "sha256:a"), Ok(()));
        assert_eq!(v.check("sha256:a", &file("sha256:a"), false), Ok(()));
        for content in ["sha256:b", "none", "error"] {
            assert_eq!(check(&v, "sha256:a", content), Err(libc::EIO), "{content}");
        }
        // another algorithm or size is another string
        assert_eq!(check(&v, "sha256:a", "sha512:a"), Err(libc::EIO));
        let expected = HashMap::from([("sha256:a".to_string(), "sha256:b".to_string())]);
        let v = Verity::with_measure(expected, VerityMode::Off, fake, fake_compute).enforced();
        assert_eq!(check(&v, "sha256:a", "sha256:b"), Err(libc::EIO));
        assert_eq!(check(&v, "sha256:a", "sha256:a"), Ok(()));
        // told once for each file
        v.broken("sha256:a", "x", "y");
        v.broken("sha256:a", "x", "y");
        assert_eq!(v.told.lock().unwrap().len(), 1);
        let plain = Verity::with_measure(HashMap::new(), VerityMode::Off, fake, fake_compute);
        plain.broken("sha256:a", "x", "y");
        assert!(plain.told.lock().unwrap().is_empty());
    }
}
