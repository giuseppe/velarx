// SPDX-License-Identifier: Apache-2.0
//! The engine, as `velarx-kube` sees it: a typed varlink client of the
//! engine service (`org.velarx.Engine`), one connection for each call.  It
//! links the interface and nothing of the engine.

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use velarx_proto::connect::{self, filled_pipe, Conn};
use velarx_proto::engine::{EngineError, EngineProxy, PullSpec};
use velarx_proto::pod::PodAction;
use velarx_proto::wait::WaitCondition;
use velarx_proto::workload::{
    ContainerRecord, ImageRecord, PodRecord, SecretRecord, VolumeRecord, VolumeSpec,
};
use velarx_registry::auth::RegistryAccess;

/// Why a call of the engine failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
    /// The engine says the object is not there
    missing: bool,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            missing: false,
        }
    }

    /// The object the call named is not there.
    pub fn is_missing(&self) -> bool {
        self.missing
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<EngineError> for Error {
    fn from(e: EngineError) -> Self {
        Self {
            missing: matches!(
                e,
                EngineError::NoSuchContainer { .. }
                    | EngineError::NoSuchImage { .. }
                    | EngineError::NoSuchPod { .. }
                    | EngineError::NoSuchVolume { .. }
                    | EngineError::NoSuchSecret { .. }
            ),
            message: e.to_string(),
        }
    }
}

impl From<zlink::Error> for Error {
    fn from(e: zlink::Error) -> Self {
        Self::new(format!("the engine: {e}"))
    }
}

impl From<connect::ConnectError> for Error {
    fn from(e: connect::ConnectError) -> Self {
        Self::new(format!("cannot use the engine: {e:?}"))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The answer of a call that may name what is not there: none when it is
/// not.
fn found<T>(answer: Result<T>) -> Result<Option<T>> {
    match answer {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.is_missing() => Ok(None),
        Err(e) => Err(e),
    }
}

/// A call on a connection of its own.
macro_rules! call {
    ($engine:expr, $method:ident ( $($arg:expr),* $(,)? )) => {{
        let mut conn = $engine.conn().await?;
        conn.$method($($arg),*).await?.map_err(Error::from)
    }};
}

/// The engine service.
#[derive(Debug, Clone)]
pub struct Engine {
    dial: connect::Dial,
}

impl Engine {
    pub fn new(socket: PathBuf) -> Self {
        Self::dialed(connect::Dial::Path(socket))
    }

    /// The engine reached by `dial`.
    pub fn dialed(dial: connect::Dial) -> Self {
        Self { dial }
    }

    async fn conn(&self) -> Result<Conn> {
        Ok(connect::connect_checked_via(&self.dial).await?)
    }

    pub async fn pod(&self, name: &str) -> Result<Option<PodRecord>> {
        found(call!(self, pod_inspect(name)).map(|r| r.pod))
    }

    /// Create a pod from its spec (a JSON document): its id.
    pub async fn pod_create(&self, spec: Vec<u8>) -> Result<String> {
        let read = filled_pipe(spec)?;
        call!(self, pod_create(0, vec![read])).map(|r| r.id)
    }

    /// Start the pod, its containers held to `verify` (the digests typed in
    /// the YAML).
    pub async fn pod_start(&self, name: &str, verify: &[String]) -> Result<()> {
        let ran = call!(
            self,
            pod_run(
                name,
                PodAction::Start,
                None,
                None,
                verify.to_vec(),
                None::<bool>
            )
        )?;
        if ran.errors.is_empty() {
            Ok(())
        } else {
            Err(Error::new(ran.errors.join("; ")))
        }
    }

    pub async fn pod_stop(&self, name: &str, timeout: u64) -> Result<()> {
        call!(
            self,
            pod_run(
                name,
                PodAction::Stop,
                Some(timeout),
                None,
                Vec::new(),
                None::<bool>
            )
        )
        .map(|_| ())
    }

    /// Remove the pod and its containers: their ids.
    pub async fn pod_remove(&self, name: &str, timeout: u64) -> Result<Vec<String>> {
        call!(self, pod_remove(name, true, Some(timeout))).map(|r| r.removed)
    }

    /// Create a container from the document of a libpod SpecGenerator: its
    /// id.
    pub async fn container_create(&self, spec: &serde_json::Value) -> Result<String> {
        let body = serde_json::to_vec(spec).map_err(|e| Error::new(e.to_string()))?;
        let read = filled_pipe(body)?;
        call!(
            self,
            podman_container_create(false, None, None, 0, vec![read])
        )
        .map(|r| r.id)
    }

    pub async fn container(&self, name: &str) -> Result<Option<ContainerRecord>> {
        found(call!(self, container_inspect(name, false)).map(|r| r.container))
    }

    /// Wait for the container to exit: its exit code.
    pub async fn container_wait(&self, name: &str) -> Result<i64> {
        use zlink::futures_util::StreamExt;
        let mut conn = self.conn().await?;
        let replies = conn
            .container_wait(name, vec![WaitCondition::Exited], 250_000_000)
            .await?;
        let mut replies = std::pin::pin!(replies);
        while let Some(reply) = replies.next().await {
            if let Some(code) = reply?.map_err(Error::from)?.status_code {
                return Ok(code);
            }
        }
        Err(Error::new(format!(
            "the engine ended the wait for {name} with no exit code"
        )))
    }

    pub async fn container_remove(&self, name: &str) -> Result<()> {
        call!(
            self,
            container_remove(name, true, false, false, false, None)
        )
        .map(|_| ())
    }

    pub async fn image(&self, name: &str) -> Result<Option<ImageRecord>> {
        found(call!(self, image_inspect(name)).map(|r| r.image))
    }

    /// Pull the image; the progress is not printed.
    pub async fn image_pull(
        &self,
        reference: &str,
        tls_verify: bool,
        access: &RegistryAccess,
    ) -> Result<()> {
        use zlink::futures_util::StreamExt;
        let spec = PullSpec {
            source: reference.to_string(),
            tls_verify,
            ..Default::default()
        };
        let (access, fds) = access_memfd(access)?;
        let mut conn = self.conn().await?;
        let replies = conn.image_pull_progress(spec, access, fds).await?;
        let mut replies = std::pin::pin!(replies);
        while let Some(reply) = replies.next().await {
            reply?.map_err(Error::from)?;
        }
        Ok(())
    }

    /// The registries a pull of `reference` goes to, for the credentials.
    pub async fn credential_scopes(&self, reference: &str) -> Result<Vec<String>> {
        call!(self, registry_credential_scopes(reference, false)).map(|r| r.scopes)
    }

    /// Build the directory the descriptor `dir` is as an image named `tag`;
    /// the progress is not printed.  The engine is given the descriptor,
    /// never a path: it reads what the directory held when the call was
    /// made, whatever the path of it becomes.
    pub async fn image_build(
        &self,
        dir: std::os::fd::BorrowedFd<'_>,
        tag: &str,
        tls_verify: bool,
        access: &RegistryAccess,
    ) -> Result<()> {
        use tokio::io::AsyncBufReadExt;
        use velarx_proto::buildspec::{BuildEvent, BuildEventKind, BuildSpec};
        let spec = BuildSpec {
            tags: vec![tag.to_string()],
            layers: true,
            tls_verify,
            ..Default::default()
        };
        let body = serde_json::to_vec(&spec).map_err(|e| Error::new(e.to_string()))?;
        // (the spec is descriptor 0, the context 1, the credentials 2)
        let mut pipes = vec![filled_pipe(body)?, dir.try_clone_to_owned()?];
        let (access, credentials) = access_memfd(access)?;
        let access = access.map(|_| 2);
        pipes.extend(credentials);
        let mut conn = self.conn().await?;
        let (stream, fds) = conn.image_build(0, Some(1), false, access, pipes).await?;
        stream.map_err(Error::from)?;
        let fd = connect::take_fd(fds, 0)
            .ok_or_else(|| Error::new("the engine opened a build with no progress"))?;
        let reader = tokio::net::unix::pipe::Receiver::from_owned_fd(fd)?;
        let mut lines = tokio::io::BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            let event: BuildEvent = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if event.kind == BuildEventKind::Error {
                return Err(Error::new(event.text));
            }
        }
        Ok(())
    }

    pub async fn secret_data(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn().await?;
        let (reply, fds) = conn.secret_inspect(name, true).await?;
        let reply = match found(reply.map_err(Error::from))? {
            Some(r) => r,
            None => return Ok(None),
        };
        let Some(index) = reply.data else {
            return Ok(Some(Vec::new()));
        };
        let fd = connect::take_fd(fds, index)
            .ok_or_else(|| Error::new("the engine named a file it did not send"))?;
        let data = velarx_base::sealed::read_sealed_whole(&std::fs::File::from(fd), 1 << 20)
            .map_err(|why| Error::new(format!("the data of the secret {why}")))?;
        Ok(Some(data))
    }

    /// The secret as the engine knows it, without its data.
    pub async fn secret(&self, name: &str) -> Result<Option<SecretRecord>> {
        let mut conn = self.conn().await?;
        let (reply, _) = conn.secret_inspect(name, false).await?;
        found(reply.map_err(Error::from).map(|r| r.secret))
    }

    pub async fn secret_create(&self, name: &str, data: Vec<u8>, replace: bool) -> Result<String> {
        let data = velarx_base::sealed::sealed_memory(&data)?;
        call!(
            self,
            secret_create(
                name,
                None,
                Default::default(),
                Default::default(),
                replace,
                false,
                0,
                vec![data]
            )
        )
        .map(|r| r.id)
    }

    pub async fn secret_remove(&self, name: &str) -> Result<()> {
        call!(self, secret_remove(name, false)).map(|_| ())
    }

    pub async fn volume(&self, name: &str) -> Result<Option<VolumeRecord>> {
        found(call!(self, volume_inspect(name)).map(|r| r.volume))
    }

    pub async fn volume_create(&self, spec: &VolumeSpec) -> Result<()> {
        call!(self, volume_create(spec, false)).map(|_| ())
    }

    /// Extract the tar archive into the volume.
    pub async fn volume_import(&self, name: &str, archive: Vec<u8>) -> Result<()> {
        let upload = upload_pipe(archive)?;
        call!(self, volume_import(name, vec![upload])).map(|_| ())
    }

    pub async fn volume_remove(&self, name: &str) -> Result<()> {
        call!(self, volume_remove(name, true, None)).map(|_| ())
    }
}

/// The credentials of a call: [`RegistryAccess::sealed`].
fn access_memfd(access: &RegistryAccess) -> Result<(Option<u32>, Vec<OwnedFd>)> {
    Ok(access.sealed()?)
}

/// An upload (a tar archive) as the frames the engine reads: each a length
/// (four bytes, big endian) and that many bytes, the end an empty frame.
fn upload_pipe(archive: Vec<u8>) -> Result<OwnedFd> {
    let mut framed = Vec::with_capacity(archive.len() + 8);
    for chunk in archive.chunks(velarx_proto::build::MAX_CONTEXT_FRAME) {
        framed.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
        framed.extend_from_slice(chunk);
    }
    framed.extend_from_slice(&0u32.to_be_bytes());
    Ok(filled_pipe(framed)?)
}
