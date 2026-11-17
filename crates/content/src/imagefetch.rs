// SPDX-License-Identifier: Apache-2.0
//! The interface between the image server of an image that is being pulled
//! lazily and the engine service of its store: `org.velarx.ImageFetch`.
//!
//! The image server (the FUSE side, `velarx-monitor --image-server`) has
//! exactly one kind of connection for the files its image lacks: to this
//! interface, served by the engine service of the store (`velarx varlink`),
//! which owns every lazy pull.  It knows no fetcher.  On the lookup of a file that is in
//! neither the store nor the staging of the pull, it asks `Miss` and holds
//! the lookup until the engine answers; the engine fetches the file through
//! its own list of fetchers into the staging, and says `staged`; the image
//! server then opens the file and takes the kernel's fs-verity measure
//! before it answers the kernel.  Nothing the engine says is believed
//! beyond that measure.  A miss is always on demand (a process of the
//! container waits); what to read ahead of it is the engine's choice.
//!
//! The socket is `<services>/image-fetch/engine`: ONE for the store, in a
//! directory a confined image server may connect beneath, the same path for
//! the next engine service (one started after a crash binds it again, and
//! the image servers reconnect to it).  A call names the image and carries
//! the token of its pull (`token` in its directory of the staging area,
//! handed to the image server at its start): a connection that does not
//! have it asks for nothing.  The server checks that its client runs as its
//! own user; the client checks the same of the server.
//!
//! Crashes: no engine service answers: the miss is `EIO` for the container
//! until the next command starts the service; the files that are there
//! already are served as before.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;
pub use velarx_proto::transfer::{Failure, FailureClass};
use velarx_wire::varlink::{CallError, Conn, Method};
use zlink::introspect;

/// The varlink interface.
pub const INTERFACE: &str = "org.velarx.ImageFetch";

/// The number `GetInfo` reports.
pub const PROTO: u32 = 1;

/// The directory of the socket, in the services directory.
pub const DIR: &str = "image-fetch";

/// The name of the socket in [`DIR`].
pub const SOCKET: &str = "engine";

/// The socket of the store whose services directory is `services`.
pub fn socket(services: &Path) -> PathBuf {
    services.join(DIR).join(SOCKET)
}

/// A connection to the socket at `path`, whatever its length: one longer
/// than a socket address holds is reached through a descriptor of its
/// directory (`/proc/self/fd/N/NAME`), as the engine binds it.
pub fn connect(path: &Path) -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    if path.as_os_str().as_bytes().len() < 108 {
        return std::os::unix::net::UnixStream::connect(path);
    }
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a socket path without a directory",
        ));
    };
    let dir = rustix::fs::open(
        dir,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    std::os::unix::net::UnixStream::connect(velarx_sys::fd::proc_path(&dir).join(name))
}

/// What a call that returns nothing answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Ack {}

/// What `GetProfile` answers: the profile is in the sealed memory file
/// `file` of the reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct ProfileReply {
    pub file: u32,
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.ImageFetch")]
pub enum ImageFetchError {
    /// A call before `Open`, an `Open` twice
    NotScoped {
        reason: String,
    },
    /// Not the token of the pull; a layer that is not of the pull
    Refused {
        reason: String,
    },
    InvalidArgument {
        reason: String,
    },
    /// `party`: the fetcher that failed or gave invalid content (`invalid`)
    Failed {
        failure: Failure,
        party: Option<String>,
    },
}

impl std::fmt::Display for ImageFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotScoped { reason } => write!(f, "not scoped: {reason}"),
            Self::Refused { reason } => write!(f, "refused: {reason}"),
            Self::InvalidArgument { reason } => write!(f, "invalid argument: {reason}"),
            Self::Failed { failure, party } => {
                write!(f, "{}: {}", failure.class.word(), failure.reason)?;
                match party {
                    Some(party) => write!(f, " (party {party})"),
                    None => Ok(()),
                }
            }
        }
    }
}

impl std::error::Error for ImageFetchError {}

/// `GetInfo`: who serves the interface and what it can do.
#[derive(Serialize)]
pub struct GetInfo {}

impl Method for GetInfo {
    const INTERFACE: &'static str = INTERFACE;
    const NAME: &'static str = "GetInfo";
    type Reply = velarx_proto::info::Info;
}

/// `Open`: give the connection its image, once.
#[derive(Serialize)]
pub struct Open<'a> {
    pub image: &'a str,
    pub token: &'a str,
}

impl Method for Open<'_> {
    const INTERFACE: &'static str = INTERFACE;
    const NAME: &'static str = "Open";
    type Reply = Ack;
}

/// `Miss`: the file `digest` of the layer `layer` is in neither the store
/// nor the staging of the pull: bring it.
#[derive(Serialize)]
pub struct Miss<'a> {
    pub layer: &'a str,
    pub digest: &'a str,
}

impl Method for Miss<'_> {
    const INTERFACE: &'static str = INTERFACE;
    const NAME: &'static str = "Miss";
    type Reply = Ack;
}

/// `GetProfile`: the startup profile of the image, at most `max` bytes.
#[derive(Serialize)]
pub struct GetProfile {
    pub max: u64,
}

impl Method for GetProfile {
    const INTERFACE: &'static str = INTERFACE;
    const NAME: &'static str = "GetProfile";
    type Reply = ProfileReply;
}

/// The blocking client of the image server: one connection per call at a
/// time, kept for the next; a connection that broke (the engine went, a new
/// one bound the socket again) is replaced once, at once, by a new one.  A
/// connection is `Open`ed for its image when it is made.
pub struct Client {
    via: Via,
    /// The id of the image
    image: String,
    token: String,
    idle: Mutex<Vec<Conn>>,
}

/// How the connections to the socket are made.
enum Via {
    /// By its path
    Path(PathBuf),
    /// Through the connector of a process that looks up no path (confined)
    Connector(std::sync::Arc<velarx_sys::connector::Connector>, PathBuf),
}

/// The connections kept idle: one, the proxy of the engine serves every
/// image server of the store, and a miss that finds none connects anew.
const KEEP: usize = 1;

impl Client {
    /// The client of the image `image`, whose pull has the token `token`.
    pub fn new(socket: PathBuf, image: String, token: String) -> Self {
        Self {
            via: Via::Path(socket),
            image,
            token,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// [`Client::new`] whose connections come through `connector` (to the
    /// socket it was started for, `socket`): the process looks up no socket
    /// by name.
    pub fn through(
        connector: std::sync::Arc<velarx_sys::connector::Connector>,
        socket: PathBuf,
        image: String,
        token: String,
    ) -> Self {
        Self {
            via: Via::Connector(connector, socket),
            image,
            token,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// A connection to the engine, checked and opened for the image.
    fn connect(&self) -> Result<Conn, CallError> {
        let (stream, socket) = match &self.via {
            Via::Path(socket) => (connect(socket), socket),
            Via::Connector(connector, socket) => (connector.connect(), socket),
        };
        let stream = stream.map_err(|e| {
            CallError::Io(io::Error::new(
                e.kind(),
                format!(
                    "no engine service serves the pulls of the store ({}): {e}",
                    socket.display()
                ),
            ))
        })?;
        velarx_base::ipc::check_client(&stream, velarx_base::ipc::trusted_uid)?;
        let mut conn = Conn::from_stream(stream);
        let (info, _) = conn.call_method(&GetInfo {}, &[])?;
        velarx_proto::info::check(INTERFACE, &info, PROTO)
            .map_err(|e| CallError::Protocol(e.to_string()))?;
        conn.call_method(
            &Open {
                image: &self.image,
                token: &self.token,
            },
            &[],
        )?;
        Ok(conn)
    }

    /// One call, on a kept connection or a new one; a kept one that broke
    /// is replaced by a new one once.
    fn call<M: Method>(
        &self,
        m: &M,
        deadline: Option<Instant>,
    ) -> Result<(M::Reply, Vec<std::os::fd::OwnedFd>), CallError> {
        let kept = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
        let fresh = kept.is_none();
        let mut conn = match kept {
            Some(c) => c,
            None => self.connect()?,
        };
        match Self::once(&mut conn, m, deadline) {
            Ok(v) => {
                self.keep(conn);
                Ok(v)
            }
            Err(e) if !fresh && retried(&e) => {
                let mut conn = self.connect()?;
                let v = Self::once(&mut conn, m, deadline)?;
                self.keep(conn);
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    fn once<M: Method>(
        conn: &mut Conn,
        m: &M,
        deadline: Option<Instant>,
    ) -> Result<(M::Reply, Vec<std::os::fd::OwnedFd>), CallError> {
        match deadline {
            Some(deadline) => conn.set_deadline(deadline),
            None => conn.clear_deadline(),
        }
        conn.call_method(m, &[])
    }

    fn keep(&self, conn: Conn) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < KEEP {
            idle.push(conn);
        }
    }

    /// Ask the engine for the file `digest` of `layer`, until `deadline`
    /// (none: until it answers; the engine ends the call when this side
    /// hangs up).  A failure is the error `Failed`, which names the class
    /// and the party in its text.
    pub fn miss(
        &self,
        layer: &str,
        digest: &str,
        deadline: Option<Instant>,
    ) -> Result<(), CallError> {
        self.call(&Miss { layer, digest }, deadline).map(|_| ())
    }

    /// The startup profile the engine's fetchers have for the image: at
    /// most `max` bytes of digests, one a line.
    pub fn profile(&self, max: u64, deadline: Option<Instant>) -> Result<Vec<String>, CallError> {
        let (reply, fds) = self.call(&GetProfile { max }, deadline)?;
        let file = fds
            .into_iter()
            .nth(reply.file as usize)
            .map(std::fs::File::from)
            .ok_or_else(|| CallError::Protocol("a profile without its file".into()))?;
        let text = velarx_base::sealed::read_sealed_whole(&file, max)
            .map_err(|w| CallError::Protocol(format!("the profile {w}")))?;
        Ok(String::from_utf8_lossy(&text)
            .lines()
            .map(str::to_string)
            .collect())
    }
}

/// A failure on a kept connection that a new connection may not have: the
/// engine that served it went (its socket bound again since).
fn retried(e: &CallError) -> bool {
    match e {
        CallError::Io(e) => !matches!(e.kind(), io::ErrorKind::TimedOut),
        CallError::Remote { .. } | CallError::Protocol(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socket_of_the_store_is_one_in_its_directory() {
        let s = socket(Path::new("/run/user/1000/velarx/services"));
        assert_eq!(
            s,
            Path::new("/run/user/1000/velarx/services/image-fetch/engine")
        );
    }

    /// A socket in a directory longer than a socket address holds is
    /// reached all the same.
    #[test]
    fn a_long_socket_path_is_reached() {
        let tmp = tempfile::tempdir().unwrap();
        let mut dir = tmp.path().to_path_buf();
        while dir.as_os_str().len() < 120 {
            dir.push("a-long-directory");
        }
        let path = socket(&dir);
        let _listener = velarx_base::ipc::bind_private_long(&path).unwrap();
        assert!(connect(&path).is_ok());
        assert_eq!(
            connect(&dir.join("none")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn a_kept_connection_is_replaced_when_its_engine_went() {
        assert!(retried(&CallError::Io(io::ErrorKind::BrokenPipe.into())));
        assert!(retried(&CallError::Io(io::ErrorKind::UnexpectedEof.into())));
        assert!(!retried(&CallError::Io(io::ErrorKind::TimedOut.into())));
        assert!(!retried(&CallError::Remote {
            error: "org.velarx.ImageFetch.Refused".into(),
            reason: String::new()
        }));
    }
}
