// SPDX-License-Identifier: Apache-2.0
//! `CheckpointContainer`: the kubelet names the file of the archive
//! (`location`, in its checkpoint directory); the frontend makes it, as a
//! file without a name, passes it to the engine with the call
//! (`org.velarx.Engine.ContainerCheckpoint`, a descriptor in the message) and
//! links it under its name when the engine says it is written.  A checkpoint
//! that fails leaves nothing in the directory, and the engine opens no path
//! of a client.
//!
//! The process confines itself with the right to make and write files in that
//! directory only ([`velarx_proto::confine::Reach::create`]); `location` has
//! to be a file of it.

use super::varlink::{check_args, refused};
use super::{EngineError, Result};
use rustix::fs::{linkat, openat, unlinkat, AtFlags, Mode, OFlags, CWD};
use std::ffi::OsStr;
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;
use velarx_proto::connect::{connect_checked_via, Dial};
use velarx_proto::engine::{CheckpointFlags, EngineProxy};
use velarx_sys::fs::{open_beneath, Beneath, BeneathError};

/// Where the kubelet puts the archives of its checkpoints.
pub const DEFAULT_DIR: &str = "/var/lib/kubelet/checkpoints";

/// How long the containers of a pod may stay paused for a checkpoint.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// How long after the end of the cut the engine waits for the frontend to
/// resume the containers before it does it itself (the lease of the pause).
const RESUME_GRACE: Duration = Duration::from_secs(60);

/// The longest an attempt to resume a container takes.
const RESUME_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Checkpoints {
    /// How the engine (`org.velarx.Engine`) is reached: the process's own
    /// way, which for a confined one is its connector
    dial: Dial,
    path: PathBuf,
    dir: OwnedFd,
    /// The longest the containers of a pod stay paused
    timeout: Duration,
}

impl Checkpoints {
    /// The directory of the archives, opened now (the process cannot open a
    /// path once it is confined) and made if `create` and it is not there.
    pub fn open(dial: Dial, dir: &Path, create: bool) -> std::io::Result<Self> {
        if create {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        let fd = rustix::fs::open(
            dir,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self {
            dial,
            path: dir.to_path_buf(),
            dir: fd,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// The directory of the process: the one it was asked for (an error when
    /// it cannot be had), else [`DEFAULT_DIR`], made here when it is not
    /// there (the process cannot make it later); a user who may not make
    /// that one leaves it to be the answer of the first checkpoint (`None`).
    pub fn configured(dial: Dial, asked: Option<&Path>) -> std::io::Result<Option<Self>> {
        Self::configured_with(dial, asked, Path::new(DEFAULT_DIR))
    }

    fn configured_with(
        dial: Dial,
        asked: Option<&Path>,
        default: &Path,
    ) -> std::io::Result<Option<Self>> {
        match asked {
            Some(dir) => Self::open(dial, dir, true)
                .map(Some)
                .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", dir.display()))),
            None => match Self::open(dial, default, true) {
                Ok(c) => Ok(Some(c)),
                Err(e) => {
                    tracing::debug!("no checkpoints: {}: {e}", default.display());
                    Ok(None)
                }
            },
        }
    }

    /// The longest the containers of a pod are paused by a checkpoint: past
    /// it the dump is abandoned and they are resumed.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn dir(&self) -> &Path {
        &self.path
    }

    /// What the confined process needs of the directory: make, write and
    /// link the archives, remove the ones it linked when a later link fails,
    /// and read the checkpoints it restores.
    pub fn grant(&self, reach: &mut velarx_proto::confine::Reach) {
        reach.create.push(self.path.clone());
        reach.remove.push(self.path.clone());
        reach.read.push(self.path.clone());
    }

    /// The name of the file `location` is in the directory: an absolute path
    /// of a file of it, not of a directory below.
    fn name_of(&self, location: &str) -> Result<std::ffi::OsString> {
        let path = Path::new(location);
        match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) if path.is_absolute() && parent == self.path => {
                Ok(name.to_os_string())
            }
            _ => Err(EngineError::Invalid(format!(
                "the checkpoint {location} is not a file of {}",
                self.path.display()
            ))),
        }
    }

    fn made(&self, e: rustix::io::Errno) -> EngineError {
        EngineError::Other(format!("a file in {}: {e}", self.path.display()))
    }

    /// A file without a name in `dir`, to be linked when it is whole.
    fn unnamed(&self, dir: &impl AsFd) -> Result<OwnedFd> {
        openat(
            dir,
            ".",
            OFlags::TMPFILE | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| self.made(e))
    }

    /// Give the file `file` the name `name` in `dir`, which has to be new.
    fn link(&self, dir: &impl AsFd, file: &OwnedFd, name: &OsStr) -> Result<()> {
        linkat(
            CWD,
            velarx_sys::fd::proc_str(&file).as_str(),
            dir,
            name,
            AtFlags::SYMLINK_FOLLOW,
        )
        .map_err(|e| match e {
            rustix::io::Errno::EXIST => EngineError::Conflict(format!(
                "the checkpoint file {} exists",
                Path::new(name).display()
            )),
            e => EngineError::Other(format!("the checkpoint {}: {e}", Path::new(name).display())),
        })
    }

    async fn connect(&self) -> Result<velarx_proto::connect::Conn> {
        connect_checked_via(&self.dial)
            .await
            .map_err(|e| EngineError::Other(format!("the checkpoint needs the engine: {e}")))
    }

    /// The engine writes the archive of the checkpoint of `container`, which
    /// goes on running (or stays paused), in a file without a name, which is
    /// returned.
    async fn dump(&self, dir: &impl AsFd, container: &str) -> Result<OwnedFd> {
        let file = self.unnamed(dir)?;
        // (the engine writes in a descriptor of the same file)
        let given = rustix::io::fcntl_dupfd_cloexec(&file, 3).map_err(|e| self.made(e))?;
        let mut conn = self.connect().await?;
        let flags = CheckpointFlags {
            leave_running: true,
            ..Default::default()
        };
        check_args("container_checkpoint", &(container, &flags))?;
        conn.container_checkpoint(container, flags, Some(0), vec![given])
            .await
            .map_err(|e| EngineError::Other(format!("the engine: {e}")))?
            .map_err(refused)?;
        Ok(file)
    }

    /// Checkpoint `container` into the file `location`, which has to be new.
    pub async fn checkpoint(&self, container: &str, location: &str) -> Result<()> {
        let name = self.name_of(location)?;
        let file = self.dump(&self.dir, container).await?;
        self.link(&self.dir, &file, &name).map_err(|e| match e {
            EngineError::Conflict(_) => {
                EngineError::Conflict(format!("the checkpoint {location} exists"))
            }
            e => e,
        })
    }

    /// The directory `path` of the checkpoint directory (or it), open to
    /// read: a pod checkpoint is written in one, and restored from one.
    pub fn open_dir(&self, path: &str) -> Result<OwnedFd> {
        let path = Path::new(path);
        let relative = path
            .strip_prefix(&self.path)
            .ok()
            .filter(|_| path.is_absolute())
            .ok_or_else(|| {
                EngineError::Invalid(format!(
                    "{} is not the checkpoint directory {} or a directory of it",
                    path.display(),
                    self.path.display()
                ))
            })?;
        let relative = if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative
        };
        open_beneath(self.dir.as_fd(), relative, Beneath::Directory).map_err(|e| match e {
            BeneathError::Errno(rustix::io::Errno::NOENT) => {
                EngineError::NotFound(format!("the directory {}", path.display()))
            }
            BeneathError::Errno(rustix::io::Errno::NOTDIR) => {
                EngineError::Invalid(format!("{} is not a directory", path.display()))
            }
            BeneathError::Errno(rustix::io::Errno::XDEV | rustix::io::Errno::LOOP) => {
                EngineError::Invalid(format!(
                    "{} leads out of the checkpoint directory, or through a link",
                    path.display()
                ))
            }
            e => EngineError::Other(format!("{}: {e}", path.display())),
        })
    }

    /// Pause the containers, then dump each: the files without a name, in
    /// the order of `containers`.  `paused` is what is paused, whatever
    /// happens to this future.
    async fn cut<'a>(
        &self,
        dir: &impl AsFd,
        containers: &'a [String],
        paused: &mut Vec<&'a String>,
    ) -> Result<Vec<OwnedFd>> {
        let mut conn = self.connect().await?;
        // (the engine resumes them itself if this process is gone by then,
        // or the call that paused one did not answer)
        let lease = (self.timeout + RESUME_GRACE).as_secs();
        for c in containers {
            conn.container_pause(c, true, Some(lease))
                .await
                .map_err(|e| EngineError::Other(format!("the engine: {e}")))?
                .map_err(refused)?;
            paused.push(c);
        }
        let mut files = Vec::new();
        for c in containers {
            files.push(self.dump(dir, c).await?);
        }
        Ok(files)
    }

    /// Resume the containers, the last paused first, each on a connection
    /// that was made for it when the one before broke: the connection of
    /// the cut may be what broke.  A container the engine refuses to resume
    /// is not asked again.  What could not be resumed.
    async fn resume(&self, paused: &[&String]) -> Vec<String> {
        /// What an attempt to resume ended with.
        enum Failed {
            /// The connection broke, or the engine did not answer: a new one
            /// may do
            Connection(String),
            /// The engine answered no
            Refused(String),
        }
        let mut stuck = Vec::new();
        let mut conn: Option<velarx_proto::connect::Conn> = None;
        for c in paused.iter().rev() {
            let mut why = None;
            for _ in 0..2 {
                let attempt = tokio::time::timeout(RESUME_TIMEOUT, async {
                    if conn.is_none() {
                        conn = Some(
                            self.connect()
                                .await
                                .map_err(|e| Failed::Connection(e.to_string()))?,
                        );
                    }
                    let Some(conn) = conn.as_mut() else {
                        return Ok(());
                    };
                    conn.container_pause(c, false, None)
                        .await
                        .map_err(|e| Failed::Connection(format!("the engine: {e}")))?
                        .map_err(|e| Failed::Refused(refused(e).to_string()))
                        .map(|_| ())
                })
                .await;
                match attempt {
                    Ok(Ok(())) => {
                        why = None;
                        break;
                    }
                    Ok(Err(Failed::Refused(e))) => {
                        why = Some(e);
                        break;
                    }
                    Ok(Err(Failed::Connection(e))) => why = Some(e),
                    Err(_) => {
                        why = Some(format!("no answer in {}s", RESUME_TIMEOUT.as_secs()));
                    }
                }
                conn = None;
            }
            if let Some(why) = why {
                stuck.push(format!("{c}: {why}"));
            }
        }
        stuck
    }

    /// Checkpoint the containers of a pod at one instant: all of them are
    /// paused before the first is read and stay paused until the last is,
    /// and they are all resumed whatever happens, at the latest after the
    /// timeout of the checkpoints (and by the engine itself when this
    /// process is gone).  The archives are `0.tar`, `1.tar`... of the
    /// directory `output` (empty), in the order of `containers`, then
    /// `manifest` is `pod.json`.  Nothing is linked until every archive is
    /// whole; a link that fails removes the files linked before it.
    pub async fn checkpoint_pod(
        &self,
        containers: &[String],
        output: &str,
        manifest: &[u8],
    ) -> Result<()> {
        let dir = self.open_dir(output)?;
        let mut entries = rustix::fs::Dir::read_from(&dir).map_err(|e| self.made(e))?;
        if entries.any(|e| e.is_ok_and(|e| !matches!(e.file_name().to_bytes(), b"." | b".."))) {
            return Err(EngineError::Invalid(format!("{output} is not empty")));
        }
        let mut paused = Vec::new();
        let dumped =
            tokio::time::timeout(self.timeout, self.cut(&dir, containers, &mut paused)).await;
        let stuck = self.resume(&paused).await;
        let files = match dumped {
            Ok(Ok(files)) => files,
            Ok(Err(e)) if stuck.is_empty() => return Err(e),
            Ok(Err(e)) => {
                return Err(EngineError::Other(format!(
                    "{e}, and the containers could not be resumed: {}",
                    stuck.join("; ")
                )))
            }
            Err(_) => {
                return Err(EngineError::Other(format!(
                    "the checkpoint took longer than {:?}{}",
                    self.timeout,
                    if stuck.is_empty() {
                        ": the containers were resumed".to_string()
                    } else {
                        format!(
                            ", and the containers could not be resumed: {}",
                            stuck.join("; ")
                        )
                    }
                )))
            }
        };
        if !stuck.is_empty() {
            return Err(EngineError::Other(format!(
                "the containers could not be resumed: {}",
                stuck.join("; ")
            )));
        }
        // the manifest is written before anything is linked: only a link
        // that fails leaves files behind, and they are removed
        let file = self.unnamed(&dir)?;
        let mut written = 0;
        while written < manifest.len() {
            written += rustix::io::write(&file, &manifest[written..]).map_err(|e| self.made(e))?;
        }
        let mut linked = Vec::new();
        let named = files
            .iter()
            .enumerate()
            .map(|(i, f)| (f, format!("{i}.tar")))
            .chain([(&file, MANIFEST.to_string())]);
        for (f, name) in named {
            if let Err(e) = self.link(&dir, f, OsStr::new(&name)) {
                for done in linked {
                    if let Err(r) = unlinkat(&dir, &done, AtFlags::empty()) {
                        tracing::warn!("{output}/{done} was not removed: {r}");
                    }
                }
                return Err(e);
            }
            linked.push(name);
        }
        Ok(())
    }

    /// The manifest of the pod checkpoint in the directory `path`.
    pub fn read_pod_manifest(&self, path: &str) -> Result<Vec<u8>> {
        let dir = self.open_dir(path)?;
        let file = self.open_in(&dir, MANIFEST)?;
        let mut out = Vec::new();
        std::io::Read::take(std::fs::File::from(file), MAX_MANIFEST + 1)
            .read_to_end(&mut out)
            .map_err(|e| EngineError::Other(format!("{path}/{MANIFEST}: {e}")))?;
        if out.len() as u64 > MAX_MANIFEST {
            return Err(EngineError::Invalid(format!(
                "{path}/{MANIFEST} is bigger than {MAX_MANIFEST} bytes"
            )));
        }
        Ok(out)
    }

    /// A regular file of `dir` open to read.
    fn open_in(&self, dir: &impl AsFd, name: &str) -> Result<OwnedFd> {
        open_beneath(dir.as_fd(), Path::new(name), Beneath::File).map_err(|e| match e {
            BeneathError::Errno(rustix::io::Errno::NOENT) => {
                EngineError::NotFound(format!("the file {name}"))
            }
            BeneathError::NotRegular => {
                EngineError::Invalid(format!("{name} is not a regular file"))
            }
            e => EngineError::Other(format!("{name}: {e}")),
        })
    }

    /// Stage the archive `archive` of the directory `path` in the container
    /// `container`, which was never started: its start restores it.
    pub async fn restore_staged(&self, container: &str, path: &str, archive: &str) -> Result<()> {
        let dir = self.open_dir(path)?;
        let file = self.open_in(&dir, archive)?;
        let flags = velarx_proto::engine::RestoreFlags::default();
        check_args("container_restore", &(container, &flags))?;
        let mut conn = self.connect().await?;
        conn.container_restore(Some(container), flags, Some(0), None, true, vec![file])
            .await
            .map_err(|e| EngineError::Other(format!("the engine: {e}")))?
            .map_err(refused)?;
        Ok(())
    }
}

/// The file of a pod checkpoint that says what is in it.
pub const MANIFEST: &str = "pod.json";
const MAX_MANIFEST: u64 = 1 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    fn in_dir(dir: &Path) -> Checkpoints {
        Checkpoints::open(Dial::Path(dir.join("engine.sock")), dir, false).unwrap()
    }

    /// A directory that was asked for is an error when it cannot be had,
    /// whether or not it is the one that is the default; the default one is
    /// left to the first checkpoint.
    #[test]
    fn a_directory_asked_for_is_an_error_the_default_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let unusable = file.join("checkpoints");
        let socket = || dir.path().join("engine.sock");
        assert!(
            Checkpoints::configured_with(Dial::Path(socket()), Some(&unusable), &unusable).is_err()
        );
        assert!(
            Checkpoints::configured_with(Dial::Path(socket()), Some(&unusable), dir.path())
                .is_err()
        );
        assert!(
            Checkpoints::configured_with(Dial::Path(socket()), None, &unusable)
                .unwrap()
                .is_none()
        );
        let made = dir.path().join("made");
        assert!(
            Checkpoints::configured_with(Dial::Path(socket()), None, &made)
                .unwrap()
                .is_some()
        );
        assert!(made.is_dir());
    }

    #[test]
    fn only_a_file_of_the_directory_is_a_location() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let at = |name: &str| c.name_of(&format!("{}/{name}", dir.path().display()));
        assert_eq!(at("a b.tar").unwrap(), "a b.tar");
        for bad in ["../a.tar", "sub/a.tar", "", ".."] {
            assert!(at(bad).is_err(), "{bad}");
        }
        for bad in [
            "a.tar",
            "/etc/a.tar",
            "/",
            "/var/lib/kubelet/checkpoints/x/../a.tar",
        ] {
            assert!(c.name_of(bad).is_err(), "{bad}");
        }
        assert!(c.name_of(&format!("{}/", dir.path().display())).is_err());
    }

    /// A stand-in for the engine service: it answers `GetInfo`, and the
    /// checkpoint with `reply` after it wrote `archive` in the descriptor of
    /// the call.  Returns what the call named.
    fn engine(
        socket: &Path,
        archive: &'static [u8],
        reply: &'static str,
    ) -> std::thread::JoinHandle<serde_json::Value> {
        use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
        use std::io::{IoSliceMut, Write};
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut pending = Vec::new();
            loop {
                let mut buf = [0u8; 4096];
                let mut space =
                    [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
                let mut control = RecvAncillaryBuffer::new(&mut space);
                let got = recvmsg(
                    &stream,
                    &mut [IoSliceMut::new(&mut buf)],
                    &mut control,
                    RecvFlags::empty(),
                )
                .unwrap();
                assert!(got.bytes > 0, "the client went away");
                pending.extend_from_slice(&buf[..got.bytes]);
                let mut fds = Vec::new();
                for m in control.drain() {
                    if let RecvAncillaryMessage::ScmRights(r) = m {
                        fds.extend(r);
                    }
                }
                while let Some(end) = pending.iter().position(|b| *b == 0) {
                    let call: serde_json::Value = serde_json::from_slice(&pending[..end]).unwrap();
                    pending.drain(..=end);
                    let method = call["method"].as_str().unwrap().to_string();
                    let answer = if method.ends_with(".GetInfo") {
                        serde_json::json!({"parameters": {
                            "name": "velarx", "version": env!("CARGO_PKG_VERSION"),
                            "interface": velarx_proto::PROTO,
                            "digest": velarx_proto::DIGEST, "rootful": false}})
                        .to_string()
                    } else {
                        assert!(method.ends_with(".ContainerCheckpoint"), "{method}");
                        let [archive_fd]: [std::os::fd::OwnedFd; 1] =
                            std::mem::take(&mut fds).try_into().unwrap();
                        let mut file = std::fs::File::from(archive_fd);
                        file.write_all(archive).unwrap();
                        stream.write_all(reply.as_bytes()).unwrap();
                        stream.write_all(&[0]).unwrap();
                        return call;
                    };
                    stream.write_all(answer.as_bytes()).unwrap();
                    stream.write_all(&[0]).unwrap();
                }
            }
        })
    }

    #[tokio::test]
    async fn the_archive_is_written_by_the_engine_in_a_file_the_frontend_made() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let server = engine(
            &dir.path().join("engine.sock"),
            b"the archive",
            r#"{"parameters": {"id": "c1", "runtime_checkpoint_duration": 1}}"#,
        );
        let location = format!("{}/c.tar", dir.path().display());
        c.checkpoint("c1", &location).await.unwrap();
        let call = server.join().unwrap();
        assert_eq!(call["parameters"]["name"], "c1");
        assert_eq!(call["parameters"]["flags"]["leave_running"], true);
        assert_eq!(std::fs::read(&location).unwrap(), b"the archive");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&location).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // (a name that is taken is not replaced)
        let server = engine(
            &dir.path().join("engine2.sock"),
            b"other",
            r#"{"parameters": {"id": "c1", "runtime_checkpoint_duration": 1}}"#,
        );
        let again = Checkpoints::open(
            Dial::Path(dir.path().join("engine2.sock")),
            dir.path(),
            false,
        )
        .unwrap();
        let e = again.checkpoint("c1", &location).await.unwrap_err();
        server.join().unwrap();
        assert!(matches!(e, EngineError::Conflict(_)), "{e}");
        assert_eq!(std::fs::read(&location).unwrap(), b"the archive");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            3,
            "c.tar and the two sockets"
        );
    }

    #[tokio::test]
    async fn a_checkpoint_the_engine_refuses_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let server = engine(
            &dir.path().join("engine.sock"),
            b"half",
            r#"{"error": "org.velarx.Engine.NoSuchContainer", "parameters": {"cause": "x", "message": "no such container"}}"#,
        );
        let location = format!("{}/c.tar", dir.path().display());
        let e = c.checkpoint("c1", &location).await.unwrap_err();
        server.join().unwrap();
        assert!(
            matches!(&e, EngineError::NotFound(m) if m.contains("no such container")),
            "{e}"
        );
        assert!(!Path::new(&location).exists());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "the socket"
        );
    }

    #[tokio::test]
    async fn no_engine_service_is_an_error_and_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let location = format!("{}/c.tar", dir.path().display());
        assert!(c.checkpoint("c1", &location).await.is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// A stand-in for the engine service that answers any number of
    /// connections and calls, and logs them: `pause NAME`, `resume NAME`,
    /// `dump NAME` (the archive it writes is `archive of NAME`; `bad` fails),
    /// `stage NAME` (with what the descriptor holds).
    fn fake_engine(socket: &Path) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        fake_engine_in(socket, None)
    }

    /// [`fake_engine`], and the dump of the container named by `clash` makes
    /// the file `1.tar` in the directory too (a link of the frontend then
    /// fails).  The dump of `hang` never answers and the dump of `cut` breaks
    /// the connection.
    fn fake_engine_in(
        socket: &Path,
        clash: Option<(&'static str, PathBuf)>,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
        use std::io::{IoSliceMut, Read, Write};
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        let seen = log.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let log = seen.clone();
                let clash = clash.clone();
                std::thread::spawn(move || {
                    let mut pending = Vec::new();
                    let mut fds: Vec<std::os::fd::OwnedFd> = Vec::new();
                    loop {
                        let mut buf = [0u8; 4096];
                        let mut space = [std::mem::MaybeUninit::<u8>::uninit();
                            rustix::cmsg_space!(ScmRights(4))];
                        let mut control = RecvAncillaryBuffer::new(&mut space);
                        let got = recvmsg(
                            &stream,
                            &mut [IoSliceMut::new(&mut buf)],
                            &mut control,
                            RecvFlags::empty(),
                        )
                        .unwrap();
                        if got.bytes == 0 {
                            return;
                        }
                        pending.extend_from_slice(&buf[..got.bytes]);
                        for m in control.drain() {
                            if let RecvAncillaryMessage::ScmRights(r) = m {
                                fds.extend(r);
                            }
                        }
                        while let Some(end) = pending.iter().position(|b| *b == 0) {
                            let call: serde_json::Value =
                                serde_json::from_slice(&pending[..end]).unwrap();
                            pending.drain(..=end);
                            let method = call["method"].as_str().unwrap().to_string();
                            let name = call["parameters"]["name"]
                                .as_str()
                                .unwrap_or("")
                                .to_string();
                            let ok = r#"{"parameters": {}}"#.to_string();
                            let answer = if method.ends_with(".GetInfo") {
                                serde_json::json!({"parameters": {
                                    "name": "velarx", "version": env!("CARGO_PKG_VERSION"),
                                    "interface": velarx_proto::PROTO,
                                    "digest": velarx_proto::DIGEST, "rootful": false}})
                                .to_string()
                            } else if method.ends_with(".ContainerPause") {
                                let verb = if call["parameters"]["pause"] == true {
                                    format!("pause lease={}", call["parameters"]["lease"])
                                } else {
                                    "resume".to_string()
                                };
                                log.lock().unwrap().push(format!("{verb} {name}"));
                                if name == "stuck" && verb == "resume" {
                                    r#"{"error": "org.velarx.Engine.InvalidState", "parameters": {"cause": "x", "message": "not paused"}}"#.to_string()
                                } else {
                                    ok
                                }
                            } else if method.ends_with(".ContainerCheckpoint") {
                                let [fd]: [std::os::fd::OwnedFd; 1] =
                                    std::mem::take(&mut fds).try_into().unwrap();
                                log.lock().unwrap().push(format!("dump {name}"));
                                if name == "cut" {
                                    return;
                                }
                                if name == "hang" {
                                    // (until the client goes away)
                                    continue;
                                }
                                if let Some((on, dir)) = &clash {
                                    if *on == name {
                                        std::fs::write(dir.join("1.tar"), "theirs").unwrap();
                                    }
                                }
                                if name == "bad" {
                                    r#"{"error": "org.velarx.Engine.Failed", "parameters": {"cause": "x", "message": "CRIU failed"}}"#.to_string()
                                } else {
                                    std::fs::File::from(fd)
                                        .write_all(format!("archive of {name}").as_bytes())
                                        .unwrap();
                                    r#"{"parameters": {"id": "x", "runtime_checkpoint_duration": 1}}"#.to_string()
                                }
                            } else {
                                assert!(method.ends_with(".ContainerRestore"), "{method}");
                                let [fd]: [std::os::fd::OwnedFd; 1] =
                                    std::mem::take(&mut fds).try_into().unwrap();
                                let mut held = String::new();
                                std::fs::File::from(fd).read_to_string(&mut held).unwrap();
                                log.lock().unwrap().push(format!("stage {name}: {held}"));
                                r#"{"parameters": {"id": "x"}}"#.to_string()
                            };
                            stream.write_all(answer.as_bytes()).unwrap();
                            stream.write_all(&[0]).unwrap();
                        }
                    }
                });
            }
        });
        log
    }

    /// The seconds the engine gets to resume by itself.
    const LEASE: u64 = DEFAULT_TIMEOUT.as_secs() + RESUME_GRACE.as_secs();

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[tokio::test]
    async fn a_pod_is_checkpointed_with_its_containers_paused_all_the_time() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let log = fake_engine(&dir.path().join("engine.sock"));
        let out = dir.path().join("pod");
        std::fs::create_dir(&out).unwrap();
        c.checkpoint_pod(
            &names(&["a", "b"]),
            out.to_str().unwrap(),
            b"{\"manifest\": 1}",
        )
        .await
        .unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            [
                format!("pause lease={LEASE} a"),
                format!("pause lease={LEASE} b"),
                "dump a".into(),
                "dump b".into(),
                "resume b".into(),
                "resume a".into()
            ]
        );
        assert_eq!(std::fs::read(out.join("0.tar")).unwrap(), b"archive of a");
        assert_eq!(std::fs::read(out.join("1.tar")).unwrap(), b"archive of b");
        assert_eq!(
            std::fs::read(out.join(MANIFEST)).unwrap(),
            b"{\"manifest\": 1}"
        );
        // the manifest is what the restore reads, and it reads nothing else
        assert_eq!(
            c.read_pod_manifest(out.to_str().unwrap()).unwrap(),
            b"{\"manifest\": 1}"
        );
    }

    #[tokio::test]
    async fn a_pod_whose_container_fails_is_resumed_and_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let log = fake_engine(&dir.path().join("engine.sock"));
        let out = dir.path().join("pod");
        std::fs::create_dir(&out).unwrap();
        let e = c
            .checkpoint_pod(&names(&["a", "bad", "c"]), out.to_str().unwrap(), b"m")
            .await
            .unwrap_err();
        assert!(e.to_string().contains("CRIU failed"), "{e}");
        assert_eq!(
            *log.lock().unwrap(),
            [
                format!("pause lease={LEASE} a"),
                format!("pause lease={LEASE} bad"),
                format!("pause lease={LEASE} c"),
                "dump a".into(),
                "dump bad".into(),
                "resume c".into(),
                "resume bad".into(),
                "resume a".into()
            ]
        );
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }

    /// A resume the engine refuses is told, not asked again: only a
    /// connection that broke is made anew.
    #[tokio::test]
    async fn a_resume_the_engine_refuses_is_asked_once() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let log = fake_engine(&dir.path().join("engine.sock"));
        let out = dir.path().join("pod");
        std::fs::create_dir(&out).unwrap();
        let e = c
            .checkpoint_pod(&names(&["a", "stuck", "bad"]), out.to_str().unwrap(), b"m")
            .await
            .unwrap_err();
        assert!(e.to_string().contains("could not be resumed"), "{e}");
        assert!(e.to_string().contains("not paused"), "{e}");
        let log = log.lock().unwrap();
        let resumes = |name: &str| {
            log.iter()
                .filter(|l| **l == format!("resume {name}"))
                .count()
        };
        assert_eq!(resumes("stuck"), 1, "{log:?}");
        assert_eq!(resumes("a"), 1, "{log:?}");
    }

    #[tokio::test]
    async fn a_pod_is_checkpointed_in_an_empty_directory_of_the_checkpoint_directory() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let log = fake_engine(&dir.path().join("engine.sock"));
        let taken = dir.path().join("taken");
        std::fs::create_dir(&taken).unwrap();
        std::fs::write(taken.join("x"), "x").unwrap();
        let e = c
            .checkpoint_pod(&names(&["a"]), taken.to_str().unwrap(), b"m")
            .await
            .unwrap_err();
        assert!(matches!(e, EngineError::Invalid(_)), "{e}");
        let elsewhere = tempfile::tempdir().unwrap();
        for bad in [
            elsewhere.path().to_str().unwrap().to_string(),
            format!("{}/../{}", dir.path().display(), elsewhere.path().display()),
            "taken".to_string(),
            format!("{}/nothere", dir.path().display()),
        ] {
            let e = c
                .checkpoint_pod(&names(&["a"]), &bad, b"m")
                .await
                .unwrap_err();
            assert!(
                matches!(e, EngineError::Invalid(_) | EngineError::NotFound(_)),
                "{bad}: {e}"
            );
        }
        // a link in the directory does not lead out of it
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let e = c
            .checkpoint_pod(
                &names(&["a"]),
                &format!("{}/link", dir.path().display()),
                b"m",
            )
            .await
            .unwrap_err();
        assert!(!matches!(e, EngineError::Unsupported(_)), "{e}");
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
        assert!(log.lock().unwrap().is_empty(), "nothing was paused");
    }

    #[tokio::test]
    async fn an_archive_of_a_pod_checkpoint_is_given_to_the_engine_by_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let log = fake_engine(&dir.path().join("engine.sock"));
        let pod = dir.path().join("pod");
        std::fs::create_dir(&pod).unwrap();
        std::fs::write(pod.join("0.tar"), "the archive").unwrap();
        c.restore_staged("ctr", pod.to_str().unwrap(), "0.tar")
            .await
            .unwrap();
        assert_eq!(*log.lock().unwrap(), ["stage ctr: the archive"]);
        for bad in ["../x", "nothere.tar", "sub/0.tar"] {
            assert!(
                c.restore_staged("ctr", pod.to_str().unwrap(), bad)
                    .await
                    .is_err(),
                "{bad}"
            );
        }
        std::fs::create_dir(pod.join("dir.tar")).unwrap();
        assert!(c
            .restore_staged("ctr", pod.to_str().unwrap(), "dir.tar")
            .await
            .is_err());
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_dump_that_does_not_return_is_given_up_and_the_pod_resumed() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path()).with_timeout(Duration::from_millis(300));
        let log = fake_engine(&dir.path().join("engine.sock"));
        let out = dir.path().join("pod");
        std::fs::create_dir(&out).unwrap();
        let e = c
            .checkpoint_pod(&names(&["a", "hang", "c"]), out.to_str().unwrap(), b"m")
            .await
            .unwrap_err();
        assert!(e.to_string().contains("took longer than 300ms"), "{e}");
        assert!(e.to_string().contains("were resumed"), "{e}");
        let lease = RESUME_GRACE.as_secs();
        assert_eq!(
            *log.lock().unwrap(),
            [
                format!("pause lease={lease} a"),
                format!("pause lease={lease} hang"),
                format!("pause lease={lease} c"),
                "dump a".to_string(),
                "dump hang".to_string(),
                "resume c".to_string(),
                "resume hang".to_string(),
                "resume a".to_string()
            ]
        );
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_pod_is_resumed_on_a_new_connection_when_the_one_of_the_cut_broke() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let log = fake_engine(&dir.path().join("engine.sock"));
        let out = dir.path().join("pod");
        std::fs::create_dir(&out).unwrap();
        let e = c
            .checkpoint_pod(&names(&["a", "cut", "c"]), out.to_str().unwrap(), b"m")
            .await
            .unwrap_err();
        assert!(!e.to_string().contains("could not be resumed"), "{e}");
        let log = log.lock().unwrap();
        for resumed in ["resume c", "resume cut", "resume a"] {
            assert!(log.iter().any(|l| l == resumed), "{resumed}: {log:?}");
        }
    }

    #[tokio::test]
    async fn a_link_that_fails_removes_the_files_linked_before() {
        let dir = tempfile::tempdir().unwrap();
        let c = in_dir(dir.path());
        let out = dir.path().join("pod");
        std::fs::create_dir(&out).unwrap();
        let _log = fake_engine_in(&dir.path().join("engine.sock"), Some(("b", out.clone())));
        let e = c
            .checkpoint_pod(&names(&["a", "b", "c"]), out.to_str().unwrap(), b"m")
            .await
            .unwrap_err();
        assert!(matches!(e, EngineError::Conflict(_)), "{e}");
        let mut left: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["1.tar"], "only the file the engine made");
    }

    const CONFINED: &str =
        "engine::checkpoint::tests::a_confined_frontend_checkpoints_and_restores_a_pod";

    /// The calls of a checkpoint and of a restore under the confinement of
    /// the frontend (`velarx_proto::confine`: Landlock with what
    /// [`Checkpoints::grant`] gives, and its seccomp allow-list): none is
    /// refused, and a directory that is not there is not found.  The
    /// confinement cannot be undone, so the test runs itself again, in a
    /// process of its own.
    #[test]
    fn a_confined_frontend_checkpoints_and_restores_a_pod() {
        // (the test process makes the directory and removes it: the confined
        // one cannot)
        let Some(given) = std::env::var_os("VELARX_CONFINE_CHILD") else {
            let tmp = tempfile::tempdir().unwrap();
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CONFINED, "--nocapture", "--test-threads=1"])
                .env("VELARX_CONFINE_CHILD", tmp.path())
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "the confined test failed:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        };
        let tmp = std::path::PathBuf::from(given);
        let socket = tmp.join("engine/engine.sock");
        std::fs::create_dir(socket.parent().unwrap()).unwrap();
        let dir = tmp.join("checkpoints");
        let pod = dir.join("pod");
        std::fs::create_dir_all(&pod).unwrap();
        let pod = pod.to_str().unwrap();
        // (the engine of the test is not confined: its thread is older)
        let log = fake_engine(&socket);
        let c = Checkpoints::open(Dial::Path(socket.clone()), &dir, false).unwrap();
        let mut reach = velarx_proto::confine::Reach {
            connect: vec![velarx_proto::confine::dir_of(&socket)],
            ..Default::default()
        };
        c.grant(&mut reach);
        velarx_proto::confine::enter_thread(&reach).expect("the process confines itself");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                c.checkpoint_pod(&names(&["a"]), pod, b"m").await.unwrap();
                assert_eq!(c.read_pod_manifest(pod).unwrap(), b"m");
                c.restore_staged("ctr", pod, "0.tar").await.unwrap();
                let missing = format!("{}/nothere", dir.display());
                match c.open_dir(&missing) {
                    Err(EngineError::NotFound(_)) => {}
                    other => panic!("{missing}: {:?}", other.map(|_| ())),
                }
            });
        assert_eq!(
            log.lock().unwrap().last().map(String::as_str),
            Some("stage ctr: archive of a")
        );
    }
}
