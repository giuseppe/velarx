// SPDX-License-Identifier: Apache-2.0
//! The messages between the daemon and a pull worker.
//!
//! A frame is a 24 byte header (kind, JSON length, payload length, and the
//! `tag` and `offset` of a data frame), the JSON and the payload.  The daemon sends requests, one at a time; the worker
//! answers with data frames (bytes of a manifest, a piece of a blob, a
//! chunk) and ends with a reply or an error.  The daemon treats everything it
//! receives as hostile: lengths are checked before anything is allocated.
//!
//! The requests of a push (`Upload`, `PutManifest`) are followed by data
//! frames from the daemon: the bytes to send, in order, exactly as many as
//! the request announced.

use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use velarx_registry::hints::Notices;
use velarx_registry::target::EndpointSpec;
use velarx_types::digest::{Algorithm, Digest};

/// What a worker that has no credentials for an endpoint asks the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthRequest {
    /// The index of the endpoint in the hello.
    pub endpoint: usize,
    pub actions: String,
    pub refresh: bool,
}

/// The `Authorization` header value (none: the endpoint needs none), or
/// why there is none.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuthReply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Notices::is_empty")]
    pub notices: Notices,
}

impl std::fmt::Debug for AuthReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthReply")
            .field("header", &self.header.as_ref().map(|_| "<redacted>"))
            .field("error", &self.error)
            .field("notices", &self.notices)
            .finish()
    }
}

/// Largest JSON of a frame.
pub const MAX_JSON: usize = 4 * 1024 * 1024;

const HEADER: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Daemon to worker.
    Request = 1,
    /// Worker to daemon: bytes, with a JSON that says what they are.
    Data = 2,
    /// Worker to daemon: the request is done.
    Reply = 3,
    /// Worker to daemon: the request failed.
    Error = 4,
    /// Worker to daemon, during a request: the `Authorization` of an
    /// endpoint whose credentials it does not have ([`AuthRequest`]).
    AuthRequest = 5,
    /// Daemon to worker: the answer to an [`AuthRequest`] ([`AuthReply`]).
    AuthReply = 6,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Kind::Request,
            2 => Kind::Data,
            3 => Kind::Reply,
            4 => Kind::Error,
            5 => Kind::AuthRequest,
            6 => Kind::AuthReply,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub kind: Kind,
    pub json_len: usize,
    pub payload_len: usize,
    /// What a data frame is: the range or the chunk it belongs to.
    pub tag: usize,
    /// Where it is in the blob, or whatever the request makes of it.
    pub offset: u64,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn header_bytes(h: &Header) -> io::Result<[u8; HEADER]> {
    let field = |n: usize| u32::try_from(n).map_err(|_| invalid("frame too long"));
    let mut b = [0u8; HEADER];
    b[0] = h.kind as u8;
    b[4..8].copy_from_slice(&field(h.json_len)?.to_le_bytes());
    b[8..12].copy_from_slice(&field(h.payload_len)?.to_le_bytes());
    b[12..16].copy_from_slice(&field(h.tag)?.to_le_bytes());
    b[16..24].copy_from_slice(&h.offset.to_le_bytes());
    Ok(b)
}

/// Write `parts` in as few calls as the socket takes.
async fn write_all_parts<W: AsyncWrite + Unpin>(w: &mut W, parts: &[&[u8]]) -> io::Result<()> {
    let mut slices: Vec<io::IoSlice<'_>> = parts
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| io::IoSlice::new(p))
        .collect();
    let mut rest = &mut slices[..];
    while !rest.is_empty() {
        let n = w.write_vectored(rest).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        io::IoSlice::advance_slices(&mut rest, n);
    }
    Ok(())
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: Kind,
    json: &[u8],
    payload: &[u8],
) -> io::Result<()> {
    write_data(w, kind, json, 0, 0, payload).await
}

/// Write a frame with a payload and the tag and offset of its header.
pub async fn write_data<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: Kind,
    json: &[u8],
    tag: usize,
    offset: u64,
    payload: &[u8],
) -> io::Result<()> {
    let header = header_bytes(&Header {
        kind,
        json_len: json.len(),
        payload_len: payload.len(),
        tag,
        offset,
    })?;
    write_all_parts(w, &[&header, json, payload]).await?;
    w.flush().await
}

/// Read a header; the payload may be at most `max_payload`.
pub async fn read_header<R: AsyncRead + Unpin>(
    r: &mut R,
    max_payload: usize,
) -> io::Result<Header> {
    let mut b = [0u8; HEADER];
    r.read_exact(&mut b).await?;
    parse_header(&b, max_payload)
}

fn parse_header(b: &[u8; HEADER], max_payload: usize) -> io::Result<Header> {
    let kind = Kind::from_u8(b[0]).ok_or_else(|| invalid("unknown frame kind"))?;
    if b[1..4] != [0, 0, 0] {
        return Err(invalid("invalid frame header"));
    }
    let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize;
    let (json_len, payload_len) = (word(4), word(8));
    if json_len > MAX_JSON || payload_len > max_payload {
        return Err(invalid("frame too large"));
    }
    let mut offset = [0u8; 8];
    offset.copy_from_slice(&b[16..24]);
    Ok(Header {
        kind,
        json_len,
        payload_len,
        tag: word(12),
        offset: u64::from_le_bytes(offset),
    })
}

/// Write a frame whose header carries the descriptor `fd` (`SCM_RIGHTS`):
/// the header goes in one message of its own, the rest after it.
pub async fn write_frame_with_fd(
    socket: &mut tokio::net::UnixStream,
    fd: std::os::fd::BorrowedFd<'_>,
    kind: Kind,
    json: &[u8],
) -> io::Result<()> {
    let header = header_bytes(&Header {
        kind,
        json_len: json.len(),
        payload_len: 0,
        tag: 0,
        offset: 0,
    })?;
    let sock = &*socket;
    sock.async_io(tokio::io::Interest::WRITABLE, || {
        velarx_sys::scm::send(sock, &header, &[fd])
    })
    .await?;
    write_all_parts(socket, &[json]).await?;
    socket.flush().await
}

/// Read a header and the descriptor that came with it, if one did.  The
/// peer sends the header in one message ([`write_frame_with_fd`]); a header
/// that came in pieces keeps the descriptor of the piece it came with.
pub async fn read_header_with_fd(
    socket: &tokio::net::UnixStream,
    max_payload: usize,
) -> io::Result<(Header, Option<std::os::fd::OwnedFd>)> {
    let mut b = [0u8; HEADER];
    let (mut at, mut fd) = (0, None);
    while at < HEADER {
        let got = socket
            .async_io(tokio::io::Interest::READABLE, || {
                velarx_sys::scm::recv(socket, &mut b[at..], 1, rustix::net::RecvFlags::empty())
            })
            .await?;
        if got.bytes == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        at += got.bytes;
        fd = fd.or(got.fds.into_iter().next());
    }
    Ok((parse_header(&b, max_payload)?, fd))
}

/// Read exactly `len` bytes.
pub async fn read_bytes<R: AsyncRead + Unpin>(r: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(len);
    while buf.len() < len {
        let want = len - buf.len();
        let n = r.take(want as u64).read_buf(&mut buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
    Ok(buf)
}

pub fn json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| invalid(e.to_string()))
}

pub fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(|e| invalid(format!("invalid message: {e}")))
}

/// What a chunk of a blob is: its index in the plan of the daemon, how many
/// compressed bytes it takes and its size once decompressed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkSpec {
    pub idx: usize,
    pub compressed: u64,
    pub size: u64,
    /// The bytes of the range before it that are not asked (a gap of
    /// merged ranges)
    #[serde(default)]
    pub skip: u64,
}

/// The largest manifest a push sends.
pub const MAX_PUT_MANIFEST: u64 = 4 * 1024 * 1024;

/// The largest piece of an upload (one PATCH) a worker gathers.
pub const MAX_UPLOAD_CHUNK: u64 = 64 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// The first message: the endpoints every other request is about.
    Hello { endpoints: Vec<EndpointSpec> },
    /// The body of an http(s) URL, at most `limit` bytes, in data frames
    /// (`offset` is the position); the reply is a [`UrlTrailer`](velarx_content::pull::net::origin::UrlTrailer).  It
    /// needs no hello: a worker for URLs talks to no registry.
    Url {
        url: String,
        limit: u64,
        /// The least the download must bring (`[pull] min_speed_kib`)
        #[serde(default)]
        min_speed: velarx_registry::speed::Speed,
    },
    /// The `tags/list` answer of the repository of the hello, in one data
    /// frame.
    Tags,
    /// A search of the registry of the hello (`podman search`): its v1
    /// answer or its catalog in one data frame, of at most `limit` bytes;
    /// the reply is a [`SearchReply`].
    Search {
        needle: String,
        n: usize,
        docker: bool,
        limit: u64,
    },
    /// Whether a registry accepts credentials (`login`); the reply is a
    /// [`LoginReply`].  No hello either.
    Login {
        host: String,
        /// Whether the certificate of the registry is checked (else it is
        /// tried over http too)
        tls_verify: bool,
        /// The credentials to check, and the certificates for the registry
        access: velarx_registry::auth::RegistryAccess,
    },
    /// The `Authorization` of the endpoint of the hello for `actions` (a
    /// worker that has the credentials of that endpoint only); the reply is
    /// an [`AuthReply`].
    Authorize { actions: String, refresh: bool },
    /// Where the registry sent a blob (a signed URL of its CDN), as another
    /// worker found out: the requests for it that follow go there.  No
    /// reply.
    Redirect { digest: Digest, url: String },
    /// Get ready for the requests that follow (connect to the registry,
    /// take the token for pulling); the reply is a `Done`.
    Warm,
    /// A manifest by tag or digest; its bytes come in one data frame.
    Manifest { reference: String },
    /// A layer, decompressed, in data frames; the reply tells what the
    /// compressed bytes were.
    Layer {
        digest: Digest,
        size: i64,
        max_uncompressed: u64,
    },
    /// Ranges of a blob as they arrive (`tag` is the range, `offset` the
    /// position in the blob).
    Ranges {
        digest: Digest,
        ranges: Vec<(u64, u64)>,
        /// The blob is the file whose descriptor came with the request:
        /// the ranges are read from it, nothing is asked of the registry
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        file: bool,
    },
    /// Ranges of a blob made of chunks: for each range the chunks it holds
    /// in order.  The data frames are the chunks, decompressed (`tag` is
    /// their index).
    Chunks {
        digest: Digest,
        ranges: Vec<(u64, u64)>,
        chunks: Vec<Vec<ChunkSpec>>,
        /// As for `Ranges`
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        file: bool,
    },
    /// A blob as the registry has it, of `size` bytes, in data frames
    /// (`offset` is the position); the reply is a `Done`.
    Blob { digest: Digest, size: u64 },
    /// Whether the registry has a blob; the reply is an [`ExistsReply`].
    BlobExists { digest: Digest },
    /// Mount a blob from another repository of the registry; the reply is
    /// a [`MountReply`].
    Mount { digest: Digest, from: String },
    /// Upload a blob of `size` bytes, which the daemon sends next in data
    /// frames, in pieces of `chunk` bytes; the reply is a `Done`.
    Upload {
        digest: Digest,
        size: u64,
        chunk: u64,
    },
    /// Put a manifest of `size` bytes, which the daemon sends next in one
    /// data frame; the reply is a [`ManifestReply`].
    PutManifest {
        reference: String,
        media_type: String,
        size: u64,
        /// The algorithm of the digest the reply tells.
        alg: Algorithm,
    },
}

/// What a request is, without its credentials (they never go to a log).
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Hello { endpoints } => f
                .debug_struct("Hello")
                .field(
                    "hosts",
                    &endpoints
                        .iter()
                        .map(|e| e.host.as_str())
                        .collect::<Vec<_>>(),
                )
                .finish_non_exhaustive(),
            Request::Login { host, .. } => f
                .debug_struct("Login")
                .field("host", host)
                .finish_non_exhaustive(),
            other => match serde_json::to_string(other) {
                Ok(s) => f.write_str(&s),
                Err(_) => f.write_str("Request"),
            },
        }
    }
}

/// The reply to a BlobExists request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExistsReply {
    pub exists: bool,
}

/// The reply to a Mount request: false when the registry opened an upload
/// instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MountReply {
    pub mounted: bool,
}

/// The reply to a PutManifest request: the digest of what was put.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestReply {
    pub digest: Digest,
}

/// The reply to a search: whether the data is the v1 answer (else the
/// catalog).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchReply {
    pub v1: bool,
}

/// The reply to a login request: why the login failed, if it did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginReply {
    pub failure: Option<String>,
    /// The failure is the registry's refusal of the credentials
    pub unauthorized: bool,
}

/// The reply to a layer request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerTrailer {
    pub blob_digest: Digest,
    pub blob_size: u64,
    pub uncompressed: u64,
}

/// The reply to a hello: whether the worker has a user namespace of its
/// own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloReply {
    pub userns: bool,
}

impl Default for HelloReply {
    fn default() -> Self {
        Self { userns: true }
    }
}

/// The reply to a request that has nothing to add to the data it sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Done {
    /// Where the registry sent the blob of the request, if it did
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    /// The endpoint (its place in the list of the hello) that sent it
    #[serde(default, skip_serializing_if = "is_zero")]
    pub redirect_endpoint: usize,
    /// What the requests found out about the registry
    #[serde(default, skip_serializing_if = "Notices::is_empty")]
    pub notices: Notices,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The server refuses the ranges asked for (400, 416).
    Rejected,
    /// The server cannot give the ranges (the whole blob, or a refusal of
    /// a single range): the blob is asked whole.
    WholeBlob,
    Failed,
    /// The registry refused the credentials (401, 403).
    Unauthorized,
    /// The registry refused what the credentials allow (403).
    Forbidden,
    /// The registry does not have what was asked (404 of a request that
    /// is not the lookup of an optional item).
    RegistryNotFound,
    /// What was asked is not there (404): a manifest or a URL a caller
    /// may look for without needing it (signatures).
    Missing,
    /// The body is longer than the limit of the request.
    TooLarge,
    /// The chunks of a blob are not what the TOC that placed them says
    /// (`ImageError::Contradicted`).
    Contradicted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMsg {
    pub kind: ErrorKind,
    pub status: Option<u16>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Notices::is_empty")]
    pub notices: Notices,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_frames_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_data(&mut a, Kind::Data, b"{}", 7, 1 << 40, b"payload")
            .await
            .unwrap();
        let h = read_header(&mut b, 100).await.unwrap();
        assert_eq!(
            (h.kind, h.json_len, h.payload_len, h.tag, h.offset),
            (Kind::Data, 2, 7, 7, 1 << 40)
        );
        assert_eq!(read_bytes(&mut b, h.json_len).await.unwrap(), b"{}");
        assert_eq!(read_bytes(&mut b, h.payload_len).await.unwrap(), b"payload");
    }

    /// A descriptor goes with the header of a frame, whose rest follows; a
    /// frame without one has none, and a second descriptor is refused.
    #[tokio::test]
    async fn test_a_descriptor_comes_with_the_header_of_its_frame() {
        use std::io::{Read, Seek, Write};
        use std::os::fd::AsFd;
        let (mut a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"the blob").unwrap();
        write_frame_with_fd(&mut a, file.as_fd(), Kind::Request, b"{}")
            .await
            .unwrap();
        write_frame(&mut a, Kind::Request, b"[]", &[])
            .await
            .unwrap();
        let (h, fd) = read_header_with_fd(&b, 0).await.unwrap();
        assert_eq!((h.kind, h.json_len), (Kind::Request, 2));
        let mut got = std::fs::File::from(fd.expect("the descriptor"));
        got.rewind().unwrap();
        let mut text = String::new();
        got.read_to_string(&mut text).unwrap();
        assert_eq!(text, "the blob");
        let mut json = [0u8; 2];
        b.readable().await.unwrap();
        assert_eq!(b.try_read(&mut json).unwrap(), 2);
        assert_eq!(&json, b"{}");
        let (h, fd) = read_header_with_fd(&b, 0).await.unwrap();
        assert_eq!((h.kind, h.json_len), (Kind::Request, 2));
        assert!(fd.is_none());
        let mut json = [0u8; 2];
        b.readable().await.unwrap();
        assert_eq!(b.try_read(&mut json).unwrap(), 2);
        // (two are refused, and neither is left open)
        let named = tempfile::NamedTempFile::new().unwrap();
        let path = std::fs::canonicalize(named.path()).unwrap();
        let open = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .flatten()
                .filter(|fd| std::fs::read_link(fd.path()).is_ok_and(|t| t == path))
                .count()
        };
        let header = header_bytes(&Header {
            kind: Kind::Request,
            json_len: 0,
            payload_len: 0,
            tag: 0,
            offset: 0,
        })
        .unwrap();
        let fd = named.as_file().as_fd();
        velarx_sys::scm::send(&a, &header, &[fd, fd]).unwrap();
        assert!(read_header_with_fd(&b, 0).await.is_err());
        assert_eq!(open(), 1);
    }

    #[tokio::test]
    async fn test_hostile_headers_are_refused() {
        for header in [
            // Unknown kind, junk in the reserved bytes, too long.
            [
                9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                2, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                2, 0, 0, 0, 0, 0, 0, 0, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ] {
            let mut r = &header[..];
            assert!(read_header(&mut r, 100).await.is_err(), "{header:?}");
        }
        let mut short = &[2u8, 0, 0][..];
        assert!(read_header(&mut short, 100).await.is_err());
    }

    #[test]
    fn test_requests_are_tagged() {
        let r = Request::Manifest {
            reference: "latest".into(),
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"op":"manifest","reference":"latest"}"#
        );
        assert!(parse::<Request>(b"{\"op\":\"exec\"}").is_err());
    }
}
