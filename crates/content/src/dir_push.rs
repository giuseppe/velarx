// SPDX-License-Identifier: Apache-2.0
//! The directory as a pusher (`org.velarx.Pusher`): the origin of the
//! destinations that are a path, written by the process `velarx-dir --push`
//! that the engine starts for one push, with the destination it opened:
//!
//! * [`Mode::Layout`] (`oci:`): a directory in the OCI image layout.  Blobs
//!   are `blobs/ALGORITHM/HEX`, the index is `index.json`, replaced whole
//!   when the push ends, with the images of the layout that this push does
//!   not name.
//! * [`Mode::Dir`] (`dir:`): one manifest (`manifest.json`) and its blobs,
//!   each a file named by its hex, and `version`.
//! * [`Mode::Archive`] (`oci-archive:`, and what `save` writes): a tar of an
//!   OCI image layout in the file (or pipe) it was given, written in
//!   order: the blobs as they are placed, `index.json` last.
//!
//! The pusher never hashes: an object is named by the digest the engine
//! gave, and has exactly the bytes of its data file.  What it may write is
//! what the sandbox lets it ([`velarx_sandbox::fetch::Role::DirPush`]): the
//! destination directory and nothing else; for an archive, the one file.

use crate::pusher::push::{
    CommitReply, EventKind, Have, Object, Placed, Probed, PusherError, PutEvent,
};
use crate::serve_fetch::{Described, Out, StagingFetcher};
use crate::serve_push::{CommitCall, PushScope, Pushing, PutCall};
use crate::stager::{link_new, open_beneath};
use async_trait::async_trait;
use rustix::fs::{AtFlags, Mode as FileMode, OFlags};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use velarx_types::digest::Digest;

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const REF_NAME: &str = "org.opencontainers.image.ref.name";
const IMAGE_NAME: &str = "io.containerd.image.name";
const DIR_VERSION: &str = "Directory Transport Version: 1.1\n";
const OCI_LAYOUT: &str = r#"{"imageLayoutVersion":"1.0.0"}"#;
/// The largest `index.json` of a layout that is added to.
const MAX_INDEX: u64 = 4 * 1024 * 1024;

pub use velarx_base::push_path::{check_destination, Mode};

/// Reads exactly `left` bytes of `inner`: fewer or more is an error, as the
/// header of a tar entry says how many there are.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let max = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..max])?;
        if n == 0 {
            return Err(io::Error::other("the data is shorter than its object"));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

fn header(size: u64, dir: bool) -> tar::Header {
    let mut h = tar::Header::new_ustar();
    h.set_size(size);
    h.set_mode(if dir { 0o755 } else { 0o644 });
    h.set_entry_type(if dir {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    h.set_mtime(0);
    h.set_uid(0);
    h.set_gid(0);
    h
}

/// The entry of an index for the manifest `manifest` put as `name`: the
/// name (a tag, or the full name of an image) is the reference name of the
/// entry, and, when it is a full name, the image name too.
fn index_entry(manifest: &Object, name: Option<&str>) -> Value {
    let mut entry = json!({
        "mediaType": manifest.media_type,
        "digest": manifest.digest,
        "size": manifest.size,
    });
    if let Some(name) = name {
        let tag = name
            .rsplit_once(':')
            .filter(|(_, t)| !t.contains('/'))
            .map(|(_, t)| t);
        let mut annotations = serde_json::Map::new();
        if name.contains('/') || tag.is_some() {
            annotations.insert(IMAGE_NAME.into(), name.into());
        }
        annotations.insert(REF_NAME.into(), tag.unwrap_or(name).into());
        entry["annotations"] = Value::Object(annotations);
    }
    entry
}

fn names_of(entry: &Value) -> Vec<&str> {
    ["annotations"]
        .iter()
        .filter_map(|a| entry.get(a))
        .flat_map(|a| {
            [IMAGE_NAME, REF_NAME]
                .into_iter()
                .filter_map(|k| a[k].as_str())
        })
        .collect()
}

/// What the push has written so far.
struct State {
    /// The entries of the index this push makes, in order
    entries: Vec<Value>,
    /// The manifests committed: `dir:` takes one
    manifests: usize,
    /// An archive: the tar being written, the blobs and the directories in
    /// it
    tar: Option<tar::Builder<File>>,
    written: HashSet<String>,
    finished: bool,
}

struct Inner {
    mode: Mode,
    dest: OwnedFd,
    state: Mutex<State>,
}

/// What confines the process once the destination is open: the mode and
/// the destination (the directory, or the file of an archive).  It runs on
/// the thread that serves `Open`, and the process has no other thread then.
pub type Confine = Box<dyn Fn(Mode, &OwnedFd) -> Result<(), String> + Send + Sync>;

struct Shared {
    confine: Confine,
    inner: std::sync::OnceLock<Arc<Inner>>,
}

/// The pusher of a path: it learns its destination from `Open` (the scheme
/// of the destination says the mode, the target is the directory or the file
/// the client opened) and confines the process there.
#[derive(Clone)]
pub struct DirPush(Arc<Shared>);

fn failed(reason: impl std::fmt::Display) -> PusherError {
    PusherError::failed(reason.to_string())
}

fn digest_of(object: &Object) -> Result<Digest, PusherError> {
    object
        .digest
        .parse()
        .map_err(|_| PusherError::InvalidArgument {
            reason: format!("not a digest: {}", object.digest),
        })
}

impl DirPush {
    /// A pusher that has no destination until `Open`; `confine` is what
    /// restricts the process then.
    pub fn new(confine: Confine) -> Self {
        Self(Arc::new(Shared {
            confine,
            inner: std::sync::OnceLock::new(),
        }))
    }

    fn inner(&self) -> Result<Arc<Inner>, PusherError> {
        self.0
            .inner
            .get()
            .cloned()
            .ok_or_else(|| PusherError::InvalidArgument {
                reason: "Open comes first".into(),
            })
    }

    /// The destination `dest` as `mode`: an archive begins with its
    /// `oci-layout`.
    fn make(mode: Mode, dest: OwnedFd) -> io::Result<Inner> {
        let tar = if mode == Mode::Archive {
            let mut tar = tar::Builder::new(File::from(rustix::io::dup(&dest)?));
            tar.append_data(
                &mut header(OCI_LAYOUT.len() as u64, false),
                "oci-layout",
                OCI_LAYOUT.as_bytes(),
            )?;
            tar.append_data(&mut header(0, true), "blobs/", io::empty())?;
            Some(tar)
        } else {
            None
        };
        Ok(Inner {
            mode,
            dest,
            state: Mutex::new(State {
                entries: Vec::new(),
                manifests: 0,
                tar,
                written: HashSet::new(),
                finished: false,
            }),
        })
    }
}

impl Inner {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The directory the blob `digest` is in, and its name there.
    fn blob_place(&self, digest: &Digest, make: bool) -> io::Result<(OwnedFd, String)> {
        let dest = self.dest.as_fd();
        if self.mode == Mode::Dir {
            let dir = rustix::io::dup(dest)?;
            return Ok((dir, digest.hex().to_string()));
        }
        let blobs = open_beneath(dest, "blobs", make)?;
        let alg = open_beneath(blobs.as_fd(), &digest.alg().to_string(), make)?;
        Ok((alg, digest.hex().to_string()))
    }

    fn has_blob(&self, object: &Object, digest: &Digest) -> bool {
        if self.mode == Mode::Archive {
            return self.state().written.contains(&object.digest);
        }
        let Ok((dir, name)) = self.blob_place(digest, false) else {
            return false;
        };
        rustix::fs::statat(dir.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|s| {
            s.st_mode & libc::S_IFMT == libc::S_IFREG && s.st_size as u64 == object.size
        })
    }

    /// Place the bytes of `data` (`object.size` of them) as the blob
    /// `digest`: whether this call made it (false: it was there).
    fn place(
        &self,
        object: &Object,
        digest: &Digest,
        mut data: impl Read,
    ) -> Result<bool, PusherError> {
        if self.mode == Mode::Archive {
            let mut state = self.state();
            if !state.written.insert(object.digest.clone()) {
                return Ok(false);
            }
            // (a directory of each algorithm, before its first blob: a reader
            // that makes the directories itself may not be allowed to own them)
            let alg_dir = format!("blobs/{}/", digest.alg());
            if state.written.insert(alg_dir.clone()) {
                let tar = state
                    .tar
                    .as_mut()
                    .ok_or_else(|| failed("the archive is finished"))?;
                tar.append_data(&mut header(0, true), &alg_dir, io::empty())
                    .map_err(failed)?;
            }
            let tar = state
                .tar
                .as_mut()
                .ok_or_else(|| failed("the archive is finished"))?;
            let path = format!("blobs/{}/{}", digest.alg(), digest.hex());
            let mut exact = Exact {
                inner: &mut data,
                left: object.size,
            };
            tar.append_data(&mut header(object.size, false), &path, &mut exact)
                .map_err(|e| failed(format!("{path}: {e}")))?;
            return Ok(true);
        }
        let (dir, name) = self.blob_place(digest, true).map_err(failed)?;
        if self.has_blob(object, digest) {
            return Ok(false);
        }
        let file = rustix::fs::openat(
            dir.as_fd(),
            ".",
            OFlags::TMPFILE | OFlags::WRONLY | OFlags::CLOEXEC,
            FileMode::from_raw_mode(0o644),
        )
        .map_err(|e| failed(format!("a file in the destination: {e}")))?;
        let mut file = File::from(file);
        let copied = io::copy(
            &mut Exact {
                inner: data,
                left: object.size,
            },
            &mut file,
        )
        .map_err(failed)?;
        if copied != object.size {
            return Err(failed("the data is not its object"));
        }
        file.flush().map_err(failed)?;
        link_new(&file, dir.as_fd(), &name).map_err(failed)
    }

    /// A file of the destination directory with `bytes`, given its name once
    /// the bytes are in it; it was there: false.
    fn put_file(&self, name: &str, bytes: &[u8]) -> Result<bool, PusherError> {
        let file = rustix::fs::openat(
            self.dest.as_fd(),
            ".",
            OFlags::TMPFILE | OFlags::WRONLY | OFlags::CLOEXEC,
            FileMode::from_raw_mode(0o644),
        )
        .map_err(|e| failed(format!("a file in the destination: {e}")))?;
        let mut file = File::from(file);
        file.write_all(bytes).map_err(failed)?;
        link_new(&file, self.dest.as_fd(), name).map_err(failed)
    }

    fn commit(&self, call: CommitCall) -> Result<CommitReply, PusherError> {
        let digest = digest_of(&call.manifest)?;
        if self.mode == Mode::Dir {
            if call.manifest.media_type == OCI_INDEX
                || call.manifest.media_type.contains("manifest.list")
            {
                return Err(failed(
                    "dir: of a manifest list is not supported: push an image",
                ));
            }
            let mut state = self.state();
            state.manifests += 1;
            if state.manifests > 1 {
                return Err(failed("dir: holds one manifest"));
            }
            drop(state);
            if !self.put_file("manifest.json", &call.body)? {
                return Err(failed("manifest.json is there already"));
            }
        } else {
            self.place(&call.manifest, &digest, &call.body[..])?;
            let mut state = self.state();
            if call.names.is_empty() {
                state.entries.push(index_entry(&call.manifest, None));
            }
            for name in &call.names {
                state.entries.push(index_entry(&call.manifest, Some(name)));
            }
        }
        // (it takes the manifest by each name and by its digest)
        let accepted = |name: Option<String>| Placed {
            name,
            accepted: true,
            reason: None,
        };
        let placed = call
            .names
            .iter()
            .cloned()
            .map(Some)
            .chain(std::iter::once(None))
            .map(accepted)
            .collect();
        Ok(CommitReply {
            digest: call.manifest.digest,
            placed,
        })
    }

    /// The layout's `index.json`: the entries it has that this push does not
    /// replace, then this push's.
    fn merged_index(&self, entries: &[Value]) -> Result<Vec<u8>, PusherError> {
        let previous = match rustix::fs::openat(
            self.dest.as_fd(),
            "index.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            FileMode::empty(),
        ) {
            Ok(fd) => {
                let mut bytes = Vec::new();
                File::from(fd)
                    .take(MAX_INDEX + 1)
                    .read_to_end(&mut bytes)
                    .map_err(failed)?;
                if bytes.len() as u64 > MAX_INDEX {
                    return Err(failed("index.json is too large"));
                }
                Some(bytes)
            }
            Err(rustix::io::Errno::NOENT) => None,
            Err(e) => return Err(failed(format!("index.json: {e}"))),
        };
        let mut index = match previous {
            Some(bytes) => serde_json::from_slice::<Value>(&bytes)
                .map_err(|e| failed(format!("invalid index.json: {e}")))?,
            None => json!({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": []}),
        };
        let manifests = index
            .get_mut("manifests")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| failed("invalid index.json: no manifests"))?;
        // (an entry of the same name goes, and an unnamed one of the same
        // digest)
        manifests.retain(|old| {
            !entries.iter().any(|new| {
                let named = names_of(new);
                if named.is_empty() {
                    names_of(old).is_empty() && old["digest"] == new["digest"]
                } else {
                    names_of(old).iter().any(|n| named.contains(n))
                }
            })
        });
        manifests.extend(entries.iter().cloned());
        serde_json::to_vec(&index).map_err(failed)
    }

    fn finish(&self) -> Result<(), PusherError> {
        let mut state = self.state();
        if std::mem::replace(&mut state.finished, true) {
            return Ok(());
        }
        match self.mode {
            Mode::Dir => {
                if state.manifests != 1 {
                    return Err(failed("dir: needs its manifest"));
                }
                drop(state);
                self.put_file("version", DIR_VERSION.as_bytes())?;
            }
            Mode::Layout => {
                let entries = std::mem::take(&mut state.entries);
                drop(state);
                // (the blobs are in place before the index names them, and
                // the index is replaced whole)
                let index = self.merged_index(&entries)?;
                let _ = self.put_file("oci-layout", OCI_LAYOUT.as_bytes())?;
                let temporary = ".velarx-index.tmp";
                let _ = rustix::fs::unlinkat(self.dest.as_fd(), temporary, AtFlags::empty());
                let file = rustix::fs::openat(
                    self.dest.as_fd(),
                    temporary,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    FileMode::from_raw_mode(0o644),
                )
                .map_err(|e| failed(format!("index.json: {e}")))?;
                File::from(file).write_all(&index).map_err(failed)?;
                rustix::fs::renameat(
                    self.dest.as_fd(),
                    temporary,
                    self.dest.as_fd(),
                    "index.json",
                )
                .map_err(|e| failed(format!("index.json: {e}")))?;
            }
            Mode::Archive => {
                let index = serde_json::to_vec(&json!({
                    "schemaVersion": 2,
                    "mediaType": OCI_INDEX,
                    "manifests": state.entries,
                }))
                .map_err(failed)?;
                let mut tar = state
                    .tar
                    .take()
                    .ok_or_else(|| failed("the archive is finished"))?;
                tar.append_data(
                    &mut header(index.len() as u64, false),
                    "index.json",
                    &index[..],
                )
                .map_err(failed)?;
                tar.into_inner()
                    .and_then(|mut f| f.flush())
                    .map_err(failed)?;
            }
        }
        Ok(())
    }
}

/// Run `work` on a thread that may block.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, PusherError> + Send + 'static,
) -> Result<T, PusherError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| failed(format!("the pusher stopped: {e}")))?
}

fn gone(_: crate::serve_fetch::Gone) -> PusherError {
    failed("the asker is gone")
}

#[async_trait]
impl Pushing for DirPush {
    fn described(&self) -> Described {
        Described {
            name: "dir".into(),
            capabilities: Vec::new(),
            max_objects: crate::pusher::push::MAX_OBJECTS as u32,
        }
    }

    async fn opened(&self, scope: &PushScope) -> Result<(), PusherError> {
        let mode =
            Mode::of_scheme(&scope.destination).ok_or_else(|| PusherError::NotSupported {
                feature: scope.destination.clone(),
            })?;
        let target = scope
            .target
            .as_ref()
            .ok_or_else(|| PusherError::InvalidArgument {
                reason: "the destination needs a target".into(),
            })?;
        let dest = rustix::io::dup(target).map_err(failed)?;
        // (the first member of an archive is written before the process is
        // confined)
        let inner = Self::make(mode, rustix::io::dup(&dest).map_err(failed)?).map_err(failed)?;
        (self.0.confine)(mode, &dest).map_err(|e| failed(format!("cannot confine: {e}")))?;
        self.0
            .inner
            .set(Arc::new(inner))
            .map_err(|_| PusherError::InvalidArgument {
                reason: "Open twice".into(),
            })
    }

    async fn probe(
        &self,
        _scope: &PushScope,
        objects: Vec<Object>,
        out: &Out<Probed>,
    ) -> Result<(), PusherError> {
        let inner = self.inner()?;
        let haves = blocking(move || {
            objects
                .iter()
                .map(|o| {
                    let digest = digest_of(o)?;
                    Ok(if inner.mode != Mode::Dir && inner.has_blob(o, &digest) {
                        Have::Present
                    } else {
                        Have::Needed
                    })
                })
                .collect::<Result<Vec<_>, PusherError>>()
        })
        .await?;
        for (index, have) in haves.into_iter().enumerate() {
            out.send(Probed {
                index: index as u32,
                have,
                failure: None,
            })
            .await
            .map_err(gone)?;
        }
        Ok(())
    }

    async fn put(
        &self,
        _scope: &PushScope,
        call: PutCall,
        out: &Out<PutEvent>,
    ) -> Result<(), PusherError> {
        for (index, (object, data)) in call.objects.into_iter().zip(call.data).enumerate() {
            let inner = self.inner()?;
            let placed = blocking(move || {
                let digest = digest_of(&object)?;
                inner.place(&object, &digest, data)
            })
            .await;
            let event = match placed {
                Ok(made) => PutEvent {
                    objects: vec![index as u32],
                    ..PutEvent::of(if made {
                        EventKind::Placed
                    } else {
                        EventKind::Present
                    })
                },
                Err(e) => PutEvent::failed(
                    vec![index as u32],
                    velarx_proto::transfer::Failure {
                        class: velarx_proto::transfer::FailureClass::Failed,
                        reason: e.to_string(),
                    },
                ),
            };
            out.send(event).await.map_err(gone)?;
        }
        Ok(())
    }

    async fn commit(
        &self,
        _scope: &PushScope,
        call: CommitCall,
    ) -> Result<CommitReply, PusherError> {
        let inner = self.inner()?;
        blocking(move || inner.commit(call)).await
    }

    async fn finish(&self, _scope: &PushScope) -> Result<(), PusherError> {
        let inner = self.inner()?;
        blocking(move || inner.finish()).await
    }
}

impl StagingFetcher for DirPush {
    fn described(&self) -> Described {
        Pushing::described(self)
    }

    fn pusher(&self) -> Option<Arc<dyn Pushing>> {
        Some(Arc::new(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(digest: &str) -> Object {
        Object {
            digest: digest.into(),
            size: 1,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            role: crate::pusher::push::Role::Manifest,
            known_at: None,
        }
    }

    fn digests(index: &[u8]) -> Vec<String> {
        let v: Value = serde_json::from_slice(index).unwrap();
        v["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["digest"].as_str().unwrap().to_string())
            .collect()
    }

    fn layout() -> (tempfile::TempDir, Inner) {
        let dir = tempfile::tempdir().unwrap();
        let dest: OwnedFd = File::open(dir.path()).unwrap().into();
        let inner = Inner {
            mode: Mode::Layout,
            dest,
            state: Mutex::new(State {
                entries: Vec::new(),
                manifests: 0,
                tar: None,
                written: HashSet::new(),
                finished: false,
            }),
        };
        (dir, inner)
    }

    /// An image pushed under the name of one the layout has replaces it; the
    /// others stay.
    #[test]
    fn merging_replaces_the_entry_of_the_same_name() {
        let (dir, inner) = layout();
        let (a, b, c) = ("sha256:a", "sha256:b", "sha256:c");
        std::fs::write(
            dir.path().join("index.json"),
            serde_json::to_vec(&json!({"schemaVersion": 2, "manifests": [
                index_entry(&object(a), Some("v1")),
                index_entry(&object(b), Some("v2")),
            ]}))
            .unwrap(),
        )
        .unwrap();
        let merged = inner
            .merged_index(&[index_entry(&object(c), Some("v1"))])
            .unwrap();
        assert_eq!(digests(&merged), [b, c]);
    }

    /// A name with a registry and a tag is the name of the image and its
    /// reference name is the tag; a bare tag is only the reference name.
    #[test]
    fn a_full_name_is_the_image_name_and_a_tag_the_reference() {
        let full = index_entry(&object("sha256:a"), Some("localhost/x:v1"));
        assert_eq!(full["annotations"][IMAGE_NAME], "localhost/x:v1");
        assert_eq!(full["annotations"][REF_NAME], "v1");
        let bare = index_entry(&object("sha256:a"), Some("v1"));
        assert!(bare["annotations"].get(IMAGE_NAME).is_none());
        assert_eq!(bare["annotations"][REF_NAME], "v1");
        assert!(index_entry(&object("sha256:a"), None)
            .get("annotations")
            .is_none());
    }
}
