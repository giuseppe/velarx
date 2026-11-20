// SPDX-License-Identifier: Apache-2.0
//! The pull worker: the process that talks to the registries.
//!
//! `velarx pull-worker` runs this.  It confines itself
//! ([`super::sandbox`]), then answers the requests of the daemon on the
//! socket it was started with: the daemon says which endpoints to use in the
//! first message and what it wants in the next ones.  What it fetches and
//! decompresses goes back as frames, never to a file.

use super::proto::{
    json, parse, read_bytes, read_header, read_header_with_fd, write_data, write_frame, AuthReply,
    AuthRequest, ChunkSpec, Done, ErrorKind, ErrorMsg, Kind, LayerTrailer, Request,
};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, Mutex};
use velarx_content::pull::net::origin::UrlTrailer;
use velarx_content::pull::ranges::{Piece, RangesError};
use velarx_content::pull::stream::{self, Frame, CHANNEL_DEPTH, FRAME_SIZE};
use velarx_registry::client::RegistryClient;
use velarx_registry::target::Target;
use velarx_sandbox as sandbox;
use velarx_types::digest::{Algorithm, Digest, DigestWriter};
use velarx_types::{ImageError, ImageResult, OciDescriptor};

/// The writing side of the socket, shared by the tasks of a request.
#[derive(Clone)]
struct Out {
    socket: Arc<Mutex<OwnedWriteHalf>>,
}

impl Out {
    async fn frame(&self, kind: Kind, json_bytes: &[u8], payload: &[u8]) -> io::Result<()> {
        let mut socket = self.socket.lock().await;
        write_frame(&mut *socket, kind, json_bytes, payload).await
    }

    /// A piece of data, cut in frames of at most [`FRAME_SIZE`] bytes.
    async fn data(&self, tag: usize, offset: u64, payload: &[u8]) -> io::Result<()> {
        let mut at = 0usize;
        loop {
            let end = payload.len().min(at + FRAME_SIZE);
            self.whole(tag, offset + at as u64, &payload[at..end])
                .await?;
            at = end;
            if at >= payload.len() {
                return Ok(());
            }
        }
    }

    /// Data that is one frame, whatever its size.  `offset` is whatever the
    /// request makes of it.
    async fn whole(&self, tag: usize, offset: u64, payload: &[u8]) -> io::Result<()> {
        let mut socket = self.socket.lock().await;
        write_data(&mut *socket, Kind::Data, &[], tag, offset, payload).await
    }

    async fn reply<T: serde::Serialize>(&self, value: &T) -> io::Result<()> {
        self.frame(Kind::Reply, &json(value)?, &[]).await
    }

    async fn error(&self, e: ErrorMsg) -> io::Result<()> {
        self.frame(Kind::Error, &json(&e)?, &[]).await
    }
}

/// The `Authorization` of the endpoints whose credentials the daemon kept:
/// asked for on the socket, one question at a time, while a request is
/// being answered (the daemon reads the frames of the worker then).
struct SocketBroker {
    out: Out,
    reader: Arc<Mutex<OwnedReadHalf>>,
}

impl velarx_registry::client::AuthBroker for SocketBroker {
    fn authorization<'a>(
        &'a self,
        endpoint: usize,
        actions: &'a str,
        refresh: bool,
    ) -> futures::future::BoxFuture<'a, ImageResult<Option<String>>> {
        Box::pin(async move {
            // the reader is the question's until its answer is read
            let mut reader = self.reader.lock().await;
            let ask = AuthRequest {
                endpoint,
                actions: actions.to_string(),
                refresh,
            };
            self.out
                .frame(Kind::AuthRequest, &json(&ask).map_err(io_error)?, &[])
                .await
                .map_err(io_error)?;
            let header = read_header(&mut *reader, 0).await.map_err(io_error)?;
            if header.kind != Kind::AuthReply {
                return Err(ImageError::Registry(
                    "the daemon did not answer the authorization".into(),
                ));
            }
            let reply: AuthReply = parse(
                &read_bytes(&mut *reader, header.json_len)
                    .await
                    .map_err(io_error)?,
            )
            .map_err(io_error)?;
            match reply.error {
                Some(e) => Err(ImageError::Registry(e)),
                None => Ok(reply.header),
            }
        })
    }
}

fn failed(e: impl std::fmt::Display) -> ErrorMsg {
    ErrorMsg {
        kind: ErrorKind::Failed,
        status: None,
        message: e.to_string(),
        notices: Default::default(),
    }
}

/// A failure of the registry client: `Unauthorized` when the registry
/// refused the credentials.
fn image_failed(e: ImageError) -> ErrorMsg {
    let kind = match &e {
        ImageError::Transfer { failure, .. } => {
            use velarx_proto::transfer::FailureClass as C;
            match failure.class {
                C::Unauthorized => ErrorKind::Unauthorized,
                C::Forbidden => ErrorKind::Forbidden,
                C::NotFound => ErrorKind::RegistryNotFound,
                C::Invalid => ErrorKind::Contradicted,
                _ => ErrorKind::Failed,
            }
        }
        ImageError::Unauthorized(_) => ErrorKind::Unauthorized,
        ImageError::Forbidden(_) => ErrorKind::Forbidden,
        ImageError::RegistryNotFound(_) => ErrorKind::RegistryNotFound,
        ImageError::Contradicted(_) => ErrorKind::Contradicted,
        _ => ErrorKind::Failed,
    };
    match e {
        // (the kind says what it is)
        ImageError::Contradicted(reason) => ErrorMsg {
            kind,
            ..failed(reason)
        },
        e => ErrorMsg { kind, ..failed(e) },
    }
}

/// What was asked is not there (404).
fn missing(e: impl std::fmt::Display) -> ErrorMsg {
    ErrorMsg {
        kind: ErrorKind::Missing,
        status: Some(404),
        message: e.to_string(),
        notices: Default::default(),
    }
}

/// The body is longer than LIMIT bytes.
fn too_large(limit: u64) -> ErrorMsg {
    ErrorMsg {
        kind: ErrorKind::TooLarge,
        status: None,
        message: velarx_content::pull::net::origin::UrlError::TooLarge(limit).to_string(),
        notices: Default::default(),
    }
}

fn io_error(e: io::Error) -> ImageError {
    ImageError::Io(e)
}

struct State {
    client: RegistryClient,
    target: Target,
    out: Out,
}

impl State {
    async fn manifest(&self, reference: &str) -> Result<(), ErrorMsg> {
        let (body, _) = self
            .client
            .fetch_manifest_or_missing(&self.target, reference)
            .await
            .map_err(image_failed)?
            .map_err(missing)?;
        self.out.whole(0, 0, &body).await.map_err(failed)?;
        self.done(Done::default()).await
    }

    /// A blob as the registry has it, in data frames, exactly SIZE bytes.
    async fn blob(&self, digest: &Digest, size: u64) -> Result<(), ErrorMsg> {
        let resp = self
            .client
            .get_blob(&self.target, digest, None)
            .await
            .map_err(image_failed)?;
        if !resp.status().is_success() {
            return Err(image_failed(velarx_registry::client::answered(
                resp.status(),
                format!("blob {digest}: {}", resp.status()),
            )));
        }
        let mut at = 0u64;
        let mut body = self.client.body(resp);
        while let Some(chunk) = body.chunk().await.map_err(failed)? {
            if at + chunk.len() as u64 > size {
                return Err(failed(format!(
                    "the blob {digest} is larger than {size} bytes"
                )));
            }
            self.out.data(0, at, &chunk).await.map_err(failed)?;
            at += chunk.len() as u64;
        }
        if at != size {
            return Err(failed(format!(
                "the blob {digest} has {at} bytes, not {size}"
            )));
        }
        self.done(Done::default()).await
    }

    /// The reply to a request about the blob `digest`: where the registry
    /// sent it is told to the pool, for the other workers.
    async fn done_for(&self, digest: &Digest) -> Result<(), ErrorMsg> {
        let (redirect_endpoint, redirect) = match self.client.redirect_of(&self.target, digest) {
            Some((i, url)) => (i, Some(url)),
            None => (0, None),
        };
        self.done(Done {
            redirect,
            redirect_endpoint,
            ..Done::default()
        })
        .await
    }

    async fn warm(&self) -> Result<(), ErrorMsg> {
        self.client.warm(&self.target).await.map_err(image_failed)?;
        self.done(Done::default()).await
    }

    async fn blob_exists(&self, digest: &Digest) -> Result<(), ErrorMsg> {
        let exists = self
            .client
            .blob_exists(&self.target, digest)
            .await
            .map_err(image_failed)?;
        self.out
            .reply(&super::proto::ExistsReply { exists })
            .await
            .map_err(failed)
    }

    async fn mount(&self, digest: &Digest, from: &str) -> Result<(), ErrorMsg> {
        let mounting = self.target.mounting_from(from);
        let mounted = matches!(
            self.client
                .start_upload(&mounting, Some((digest, from)))
                .await
                .map_err(image_failed)?,
            velarx_registry::client::UploadStart::Mounted
        );
        self.out
            .reply(&super::proto::MountReply { mounted })
            .await
            .map_err(failed)
    }

    /// The bytes of an upload or a manifest from the daemon: data frames
    /// in order until SIZE bytes came, given to SINK; never more than
    /// announced, frames of at most MAX_FRAME.
    async fn receive(
        reader: &mut OwnedReadHalf,
        size: u64,
        max_frame: usize,
        sink: &mut (dyn FnMut(Bytes) -> futures::future::BoxFuture<'static, Result<(), ErrorMsg>>
                  + Send),
    ) -> Result<(), ErrorMsg> {
        let mut at = 0u64;
        while at < size {
            let h = read_header(reader, max_frame).await.map_err(failed)?;
            if h.kind != Kind::Data || h.json_len != 0 || h.tag != 0 || h.offset != at {
                return Err(failed("unexpected frame in the data of a push"));
            }
            if at + h.payload_len as u64 > size {
                return Err(failed(format!("more than the {size} bytes announced")));
            }
            let data = read_bytes(reader, h.payload_len).await.map_err(failed)?;
            at += data.len() as u64;
            sink(Bytes::from(data)).await?;
        }
        Ok(())
    }

    /// Upload a blob the daemon sends, a PATCH per CHUNK bytes, the last
    /// piece with the PUT that has the registry check the digest.
    async fn upload(
        &self,
        reader: &mut OwnedReadHalf,
        digest: &Digest,
        size: u64,
        chunk: u64,
    ) -> Result<(), ErrorMsg> {
        if chunk == 0 || chunk > super::proto::MAX_UPLOAD_CHUNK {
            return Err(failed(format!("invalid upload chunk of {chunk} bytes")));
        }
        let session = match self
            .client
            .start_upload(&self.target, None)
            .await
            .map_err(image_failed)?
        {
            velarx_registry::client::UploadStart::Session(url) => url,
            velarx_registry::client::UploadStart::Mounted => {
                return Err(failed("the registry mounted a blob that was not asked"))
            }
        };
        let state = Arc::new(Mutex::new((session, BytesMut::new(), 0u64)));
        let (client, target) = (self.client.clone(), self.target.clone());
        let pieces = state.clone();
        let mut sink = move |data: Bytes| {
            let (state, client, target) = (pieces.clone(), client.clone(), target.clone());
            Box::pin(async move {
                let mut s = state.lock().await;
                s.1.extend_from_slice(&data);
                while s.1.len() as u64 > chunk {
                    let piece = s.1.split_to(chunk as usize).freeze();
                    let start = s.2;
                    let next = client
                        .upload_chunk(&target, &s.0, start, piece)
                        .await
                        .map_err(image_failed)?;
                    s.0 = next;
                    s.2 += chunk;
                }
                Ok(())
            }) as futures::future::BoxFuture<'static, Result<(), ErrorMsg>>
        };
        Self::receive(reader, size, FRAME_SIZE, &mut sink).await?;
        let mut s = state.lock().await;
        let last = std::mem::take(&mut s.1).freeze();
        self.client
            .finish_upload(&self.target, &s.0, s.2, digest, last)
            .await
            .map_err(image_failed)?;
        self.done(Done::default()).await
    }

    /// Put the manifest the daemon sends, of SIZE bytes in one frame.
    async fn put_manifest(
        &self,
        reader: &mut OwnedReadHalf,
        reference: &str,
        media_type: &str,
        size: u64,
        alg: Algorithm,
    ) -> Result<(), ErrorMsg> {
        if size > super::proto::MAX_PUT_MANIFEST {
            return Err(failed(format!("a manifest of {size} bytes is too large")));
        }
        let body = Arc::new(Mutex::new(BytesMut::new()));
        let into = body.clone();
        let mut sink = move |data: Bytes| {
            let into = into.clone();
            Box::pin(async move {
                into.lock().await.extend_from_slice(&data);
                Ok(())
            }) as futures::future::BoxFuture<'static, Result<(), ErrorMsg>>
        };
        Self::receive(reader, size, size as usize, &mut sink).await?;
        let body = std::mem::take(&mut *body.lock().await).freeze();
        let digest = self
            .client
            .push_manifest_bytes(&self.target, reference, media_type, body, alg)
            .await
            .map_err(image_failed)?;
        self.out
            .reply(&super::proto::ManifestReply { digest })
            .await
            .map_err(failed)
    }

    async fn tags(&self) -> Result<(), ErrorMsg> {
        let body = self
            .client
            .list_tags_raw(&self.target)
            .await
            .map_err(image_failed)?;
        self.out.whole(0, 0, &body).await.map_err(failed)?;
        self.done(Done::default()).await
    }

    async fn search(
        &self,
        needle: &str,
        n: usize,
        docker: bool,
        limit: u64,
    ) -> Result<(), ErrorMsg> {
        let (v1, body) = self
            .client
            .search_raw(&self.target, needle, n, docker, limit)
            .await
            .map_err(image_failed)?;
        self.out.whole(0, 0, &body).await.map_err(failed)?;
        self.out
            .reply(&super::proto::SearchReply { v1 })
            .await
            .map_err(failed)
    }

    async fn done(&self, mut done: Done) -> Result<(), ErrorMsg> {
        done.notices = self.client.take_notices();
        self.out.reply(&done).await.map_err(failed)
    }

    async fn small_blob(&self, digest: Digest, size: i64, limit: u64) -> Result<(), ErrorMsg> {
        let desc = OciDescriptor {
            media_type: String::new(),
            digest,
            size,
            annotations: HashMap::new(),
        };
        let body = self
            .client
            .get_small_blob(&self.target, &desc, limit)
            .await
            .map_err(image_failed)?;
        self.out.whole(0, 0, &body).await.map_err(failed)?;
        self.done_for(&desc.digest).await
    }

    /// A layer, decompressed.  The compressed bytes are hashed here; the
    /// daemon hashes the tar stream and checks both.
    async fn layer(&self, digest: Digest, size: i64, max: u64) -> Result<(), ErrorMsg> {
        let resp = self
            .client
            .get_blob(&self.target, &digest, None)
            .await
            .map_err(image_failed)?;
        if !resp.status().is_success() {
            return Err(image_failed(velarx_registry::client::answered(
                resp.status(),
                format!("Failed to download layer: {}", resp.status()),
            )));
        }
        let (compressed_tx, compressed_rx) = mpsc::channel::<Frame>(CHANNEL_DEPTH * 2);
        let (frames_tx, mut frames_rx) = mpsc::channel::<Frame>(CHANNEL_DEPTH);
        let inflate = tokio::task::spawn_blocking(move || {
            stream::decompress(compressed_rx, frames_tx, max, None, None)
        });

        let read = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reading = read.clone();
        let client = self.client.clone();
        let network = async move {
            use futures::StreamExt;
            let mut hasher = DigestWriter::for_digest(&digest);
            let mut total = 0u64;
            let mut body = client.body(resp);
            let mut failure = None;
            while let Some(chunk) = body.next().await {
                match chunk {
                    Ok(chunk) => {
                        total += chunk.len() as u64;
                        if size >= 0 && total > size as u64 {
                            failure = Some(ImageError::Registry(format!(
                                "layer {digest} is larger than the {size} bytes of its descriptor"
                            )));
                            break;
                        }
                        hasher.update(&chunk);
                        reading.store(total, std::sync::atomic::Ordering::Relaxed);
                        if compressed_tx.send(Ok(chunk)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = compressed_tx
                            .send(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                e.to_string(),
                            )))
                            .await;
                        failure = Some(e);
                        break;
                    }
                }
            }
            drop(compressed_tx);
            match failure {
                Some(e) => Err(e),
                None => Ok((hasher.finalize(), total)),
            }
        };
        let out = self.out.clone();
        let forward = async move {
            while let Some(frame) = frames_rx.recv().await {
                let frame = frame.map_err(io_error)?;
                let progress = read.load(std::sync::atomic::Ordering::Relaxed);
                out.whole(0, progress, &frame).await.map_err(io_error)?;
            }
            Ok::<(), ImageError>(())
        };
        let (network, forward) = tokio::join!(network, forward);
        let stream = inflate
            .await
            .map_err(|e| failed(format!("decompression task: {e}")))?;
        let (blob_digest, blob_size) = network.map_err(failed)?;
        forward.map_err(failed)?;
        let stream = stream.map_err(failed)?;
        self.out
            .reply(&LayerTrailer {
                blob_digest,
                blob_size,
                uncompressed: stream.size,
            })
            .await
            .map_err(failed)
    }

    async fn ranges(
        &self,
        digest: Digest,
        ranges: Vec<(u64, u64)>,
        file: Option<File>,
    ) -> Result<(), ErrorMsg> {
        let ranges: Vec<_> = ranges.into_iter().map(|(a, b)| a..b).collect();
        let out = self.out.clone();
        let mut sink = move |p: Piece| {
            let out = out.clone();
            Box::pin(async move { out.data(p.range, p.offset, &p.data).await.map_err(io_error) })
                as futures::future::BoxFuture<'static, ImageResult<()>>
        };
        match &file {
            Some(file) => crate::net::ranges::read_ranges(file, &ranges, &mut sink).await,
            None => {
                crate::net::ranges::fetch_ranges(
                    &self.client,
                    &self.target,
                    &digest,
                    &ranges,
                    &mut sink,
                )
                .await
            }
        }
        .map_err(ranges_error)?;
        self.done_for(&digest).await
    }

    /// Chunks of a blob: the compressed bytes of each are put together,
    /// decompressed and sent.  A worker does one at a time on its only
    /// thread: the parallelism is that of the workers, and a chunk never
    /// changes thread on its way.
    async fn chunks(
        &self,
        digest: Digest,
        ranges: Vec<(u64, u64)>,
        members: Vec<Vec<ChunkSpec>>,
        file: Option<File>,
    ) -> Result<(), ErrorMsg> {
        if ranges.len() != members.len() {
            return Err(failed("the ranges and the chunks do not match"));
        }
        let ranges: Vec<_> = ranges.into_iter().map(|(a, b)| a..b).collect();

        let mut assembler = velarx_content::pull::ranges::Assembler::new(
            members
                .iter()
                .map(|m| m.iter().map(|c| (c.skip, c.compressed as usize)).collect())
                .collect(),
        );
        let out = self.out.clone();
        let members = &members;
        let mut sink = |piece: Piece| {
            let specs = &members[piece.range];
            let assembled = assembler.push(piece.range, piece.data);
            let ready: Result<Vec<(ChunkSpec, Bytes)>, ImageError> = match assembled {
                Ok((ready, _)) => Ok(ready
                    .into_iter()
                    .map(|(k, b)| (specs[k].clone(), b))
                    .collect()),
                Err(velarx_content::pull::ranges::RangesError::Other(e)) => Err(e),
                Err(other) => Err(ImageError::Layer(format!("rejected: {other:?}"))),
            };
            let out = out.clone();
            Box::pin(async move {
                for (spec, comp) in ready? {
                    let data = zstd::bulk::decompress(&comp, spec.size as usize).map_err(|e| {
                        ImageError::Contradicted(format!("a chunk cannot be decompressed: {e}"))
                    })?;
                    if data.len() as u64 != spec.size {
                        return Err(ImageError::Contradicted(format!(
                            "a chunk has {} bytes, {} were expected",
                            data.len(),
                            spec.size
                        )));
                    }
                    out.whole(spec.idx, 0, &data).await.map_err(io_error)?;
                }
                Ok(())
            }) as futures::future::BoxFuture<'_, ImageResult<()>>
        };
        match &file {
            Some(file) => crate::net::ranges::read_ranges(file, &ranges, &mut sink).await,
            None => {
                crate::net::ranges::fetch_ranges(
                    &self.client,
                    &self.target,
                    &digest,
                    &ranges,
                    &mut sink,
                )
                .await
            }
        }
        .map_err(ranges_error)?;
        self.done_for(&digest).await
    }
}

/// The body of URL, at most LIMIT bytes, in data frames.
async fn fetch_url(
    out: &Out,
    url: &str,
    limit: u64,
    min_speed: velarx_registry::speed::Speed,
) -> Result<(), ErrorMsg> {
    let (resp, last_modified) = super::url::get(url).await.map_err(|e| match e {
        super::url::GetError::NotFound(m) => missing(m),
        super::url::GetError::Failed(m) => failed(m),
    })?;
    let mut size = 0u64;
    let mut body = velarx_registry::body::Body::new(resp, min_speed);
    while let Some(chunk) = body.chunk().await.map_err(failed)? {
        if size + chunk.len() as u64 > limit {
            return Err(too_large(limit));
        }
        out.data(0, size, &chunk).await.map_err(failed)?;
        size += chunk.len() as u64;
    }
    out.reply(&UrlTrailer {
        size,
        last_modified,
    })
    .await
    .map_err(failed)
}

fn ranges_error(e: RangesError) -> ErrorMsg {
    match e {
        RangesError::Rejected(status) => ErrorMsg {
            kind: ErrorKind::Rejected,
            status: Some(status),
            message: format!("the registry refuses the ranges: {status}"),
            notices: Default::default(),
        },
        RangesError::WholeBlob => ErrorMsg {
            kind: ErrorKind::WholeBlob,
            status: None,
            message: "the registry cannot give the ranges of the blob".into(),
            notices: Default::default(),
        },
        RangesError::Other(e @ ImageError::Contradicted(_)) => image_failed(e),
        RangesError::Other(e) => failed(e),
    }
}

/// Answer requests until the daemon closes the socket.
async fn serve(socket: tokio::net::UnixStream) -> io::Result<()> {
    for set in [
        rustix::net::sockopt::set_socket_send_buffer_size,
        rustix::net::sockopt::set_socket_recv_buffer_size,
    ] {
        let _ = set(&socket, 4 * 1024 * 1024);
    }
    let (reader, writer) = socket.into_split();
    let out = Out {
        socket: Arc::new(Mutex::new(writer)),
    };
    // shared with the broker, which reads its answers during a request
    let reader = Arc::new(Mutex::new(reader));

    let mut state: Option<State> = None;
    loop {
        let mut guard = reader.lock().await;
        let (header, mut fd) = match read_header_with_fd(guard.as_ref(), 0).await {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if header.kind != Kind::Request {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not a request"));
        }
        let request: Request = parse(&read_bytes(&mut *guard, header.json_len).await?)?;
        // a push reads its data with the request; the others let the
        // broker read its answers
        let mut guard = match request {
            Request::Upload { .. } | Request::PutManifest { .. } => Some(guard),
            _ => {
                drop(guard);
                None
            }
        };
        let result = match (request, &state) {
            (
                Request::Url {
                    url,
                    limit,
                    min_speed,
                },
                _,
            ) => fetch_url(&out, &url, limit, min_speed).await,
            (
                Request::Login {
                    host,
                    tls_verify,
                    access,
                },
                _,
            ) => {
                // (the worker reads no certs.d: the request brings them)
                let failure = super::login::check(&host, &access, tls_verify, Vec::new())
                    .await
                    .err();
                out.reply(&super::proto::LoginReply {
                    unauthorized: failure.as_ref().is_some_and(ImageError::is_refusal),
                    failure: failure
                        .as_ref()
                        .map(velarx_content::pull::net::origin::failure_text),
                })
                .await
                .map_err(failed)
            }
            (Request::Hello { endpoints }, None) => match RegistryClient::from_specs(&endpoints) {
                Ok((mut client, target)) => {
                    // the credentials the daemon kept come through it
                    let broker = SocketBroker {
                        out: out.clone(),
                        reader: reader.clone(),
                    };
                    client.set_broker(&endpoints, Arc::new(broker));
                    // the CDN of the registry (a hint, or where the pool saw a
                    // blob sent) is connected to while the first request
                    // goes to the registry
                    if let Some(cdn) = endpoints
                        .first()
                        .filter(|e| e.hints)
                        .and_then(|e| Some((e.hint.as_ref()?, e.hint.as_ref()?.cdn.as_ref()?)))
                        .map(|(hint, cdn)| format!("{}://{cdn}/", hint.transport))
                    {
                        let (client, target) = (client.clone(), target.clone());
                        tokio::spawn(async move { client.preconnect(&target, Some(&cdn)).await });
                    }
                    state = Some(State {
                        client,
                        target,
                        out: out.clone(),
                    });
                    let hello = super::proto::HelloReply {
                        userns: sandbox::has_userns(),
                    };
                    out.reply(&hello).await.map_err(failed)
                }
                Err(e) => Err(failed(e)),
            },
            (Request::Hello { .. }, Some(_)) => Err(failed("hello twice")),
            (Request::Authorize { actions, refresh }, Some(s)) => {
                let reply = match s
                    .client
                    .authorization_value(&s.target, &actions, refresh)
                    .await
                {
                    Ok(header) => AuthReply {
                        header,
                        error: None,
                        notices: s.client.take_notices(),
                    },
                    Err(e) => AuthReply {
                        header: None,
                        error: Some(e.to_string()),
                        notices: s.client.take_notices(),
                    },
                };
                out.reply(&reply).await.map_err(failed)
            }
            (_, None) => Err(failed("no hello")),
            (Request::Warm, Some(s)) => s.warm().await,
            (Request::Redirect { digest, url }, Some(s)) => {
                s.client.set_redirect(&s.target, &digest, &url).await;
                Ok(())
            }
            (Request::Manifest { reference }, Some(s)) => s.manifest(&reference).await,
            (Request::Tags, Some(s)) => s.tags().await,
            (Request::Blob { digest, size }, Some(s)) => s.blob(&digest, size).await,
            (Request::BlobExists { digest }, Some(s)) => s.blob_exists(&digest).await,
            (Request::Mount { digest, from }, Some(s)) => s.mount(&digest, &from).await,
            // A push whose data was not all read leaves the socket in the
            // middle of frames: the worker ends after its error.
            (
                Request::Upload {
                    digest,
                    size,
                    chunk,
                },
                Some(s),
            ) => {
                let r = match guard.as_deref_mut() {
                    Some(reader) => s.upload(reader, &digest, size, chunk).await,
                    None => Err(failed("no reader")),
                };
                if let Err(e) = r {
                    out.error(e).await?;
                    return Ok(());
                }
                Ok(())
            }
            (
                Request::PutManifest {
                    reference,
                    media_type,
                    size,
                    alg,
                },
                Some(s),
            ) => {
                let r = s
                    .put_manifest(
                        match guard.as_deref_mut() {
                            Some(reader) => reader,
                            None => return Err(io::Error::other("no reader")),
                        },
                        &reference,
                        &media_type,
                        size,
                        alg,
                    )
                    .await;
                if let Err(e) = r {
                    out.error(e).await?;
                    return Ok(());
                }
                Ok(())
            }
            (
                Request::Search {
                    needle,
                    n,
                    docker,
                    limit,
                },
                Some(s),
            ) => s.search(&needle, n, docker, limit).await,
            (
                Request::SmallBlob {
                    digest,
                    size,
                    limit,
                },
                Some(s),
            ) => s.small_blob(digest, size, limit).await,
            (
                Request::Layer {
                    digest,
                    size,
                    max_uncompressed,
                },
                Some(s),
            ) => s.layer(digest, size, max_uncompressed).await,
            (
                Request::Ranges {
                    digest,
                    ranges,
                    file,
                },
                Some(s),
            ) => match source(file, &mut fd) {
                Ok(file) => s.ranges(digest, ranges, file).await,
                Err(e) => Err(e),
            },
            (
                Request::Chunks {
                    digest,
                    ranges,
                    chunks,
                    file,
                },
                Some(s),
            ) => match source(file, &mut fd) {
                Ok(file) => s.chunks(digest, ranges, chunks, file).await,
                Err(e) => Err(e),
            },
        };
        if let Err(mut e) = result {
            if let Some(s) = &state {
                e.notices = s.client.take_notices();
            }
            out.error(e).await?;
        }
    }
}

/// The file that came with a request that says it has one.
fn source(file: bool, fd: &mut Option<OwnedFd>) -> Result<Option<File>, ErrorMsg> {
    match (file, fd.take()) {
        (true, Some(fd)) => Ok(Some(File::from(fd))),
        (true, None) => Err(failed("the file of the request did not come")),
        (false, _) => Ok(None),
    }
}

/// Entry point of `velarx pull-worker`.  The standard input is the
/// socket of the daemon.  With `--self-test` the worker confines itself,
/// tries what it is not allowed to do and reports what happened.
pub fn main(startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
    let self_test = args.iter().any(|a| a == "--self-test");
    let require_userns = args.iter().any(|a| a == "--require-userns");
    // (the TCP ports it may connect to: those of what it is for)
    let mut ports = Vec::new();
    let mut rest = args.iter();
    while let Some(a) = rest.next() {
        if a == "--connect-port" {
            let port = rest
                .next()
                .and_then(|p| p.to_str()?.parse::<u16>().ok())
                .filter(|p| *p != 0);
            match port {
                Some(p) => ports.push(p),
                None => {
                    report_start_failure("--connect-port needs a port");
                    std::process::exit(1);
                }
            }
        }
    }
    let socket = match sandbox::enter(startup, require_userns, &ports) {
        Ok(fd) => fd,
        Err(e) => {
            // Tell the daemon why, on the socket it gave (still the
            // standard input at this point if the sandbox failed early).
            report_start_failure(&e);
            std::process::exit(1);
        }
    };
    let std_socket = std::os::unix::net::UnixStream::from(socket);
    if self_test {
        use std::io::Write;
        let results = serde_json::to_vec(&sandbox::probes(&ports))?;
        let mut frame = vec![Kind::Reply as u8, 0, 0, 0];
        frame.extend((results.len() as u32).to_le_bytes());
        frame.extend([0u8; 16]);
        frame.extend(results);
        (&std_socket).write_all(&frame)?;
        return Ok(());
    }
    std_socket.set_nonblocking(true)?;
    // One thread for the network: a worker is one of several processes, the
    // decompression runs on the blocking threads.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let socket = tokio::net::UnixStream::from_std(std_socket)?;
            serve(socket).await
        })?;
    Ok(())
}

/// Send an error frame on the standard input, which is the socket of the
/// daemon when the sandbox could not be entered.
fn report_start_failure(message: &str) {
    let body = serde_json::to_vec(&ErrorMsg {
        kind: ErrorKind::Failed,
        status: None,
        message: format!("the pull worker cannot confine itself: {message}"),
        notices: Default::default(),
    })
    .unwrap_or_default();
    let mut frame = vec![Kind::Error as u8, 0, 0, 0];
    frame.extend((body.len() as u32).to_le_bytes());
    frame.extend([0u8; 16]);
    frame.extend(body);
    // (a daemon that is gone sees the end of the socket, and the worker
    // goes: there is nobody to tell and nowhere else to say it)
    let socket = rustix::stdio::stdin();
    let mut rest = &frame[..];
    while !rest.is_empty() {
        match rustix::io::write(socket, rest) {
            Ok(n) => rest = &rest[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::proto::write_data;

    async fn received(frames: Vec<(u64, Vec<u8>)>, size: u64) -> Result<Vec<u8>, ErrorMsg> {
        let (a, mut b) = tokio::net::UnixStream::pair().unwrap();
        let (mut reader, _w) = a.into_split();
        tokio::spawn(async move {
            for (offset, data) in frames {
                let _ = write_data(&mut b, Kind::Data, &[], 0, offset, &data).await;
            }
        });
        let got = Arc::new(Mutex::new(Vec::new()));
        let into = got.clone();
        let mut sink = move |d: Bytes| {
            let into = into.clone();
            Box::pin(async move {
                into.lock().await.extend_from_slice(&d);
                Ok(())
            }) as futures::future::BoxFuture<'static, Result<(), ErrorMsg>>
        };
        State::receive(&mut reader, size, 8, &mut sink).await?;
        let v = got.lock().await.clone();
        Ok(v)
    }

    /// The bytes of a push: in order, never more than announced, frames of
    /// at most the size given.
    #[tokio::test]
    async fn the_data_of_a_push_is_checked() {
        let ok = received(vec![(0, b"abcd".to_vec()), (4, b"ef".to_vec())], 6).await;
        assert_eq!(ok.unwrap(), b"abcdef");
        let more = received(vec![(0, b"abcd".to_vec()), (4, b"efgh".to_vec())], 6).await;
        assert!(more.unwrap_err().message.contains("more than the 6 bytes"));
        let gap = received(vec![(0, b"ab".to_vec()), (3, b"cd".to_vec())], 4).await;
        assert!(gap.is_err());
        let big = received(vec![(0, vec![0u8; 9])], 9).await;
        assert!(big.is_err());
    }
}
