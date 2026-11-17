// SPDX-License-Identifier: Apache-2.0
//! The operations on images.

use super::{ByteStream, Error, Result};
use crate::api::status::StatusCode;
use crate::api::AppState;
use crate::client::BuildImageRequest;
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc;

use velarx_content::archive::guard::{Accept, Guard};

/// Write `input` to a file of the staging area; with `accept`, only while
/// it is that kind of archive: what is not one ends the stream with an
/// `InvalidData` error at its first block.
pub(crate) async fn spool(
    service: &velarx_core::services::ImageService,
    mut input: ByteStream,
    accept: Option<velarx_content::archive::guard::Accept>,
) -> std::io::Result<std::fs::File> {
    let file = service.spool()?;
    // (the zeros of the tar are holes of the file)
    let mut out = velarx_storage::SparseWriter::new(file.try_clone()?);
    let mut guard = accept.map(velarx_content::archive::guard::Guard::new);
    while let Some(piece) = input.next().await {
        let piece = piece?;
        if let Some(g) = &mut guard {
            g.feed(&piece)?;
        }
        out = tokio::task::spawn_blocking(move || out.write(&piece).map(|()| out))
            .await
            .map_err(std::io::Error::other)??;
    }
    if let Some(g) = &mut guard {
        g.end()?;
    }
    tokio::task::spawn_blocking(move || out.finish())
        .await
        .map_err(std::io::Error::other)??;
    Ok(file)
}

/// The message for what a load got and is no image archive (podman's words).
pub(crate) fn unknown_format_message(e: &std::io::Error) -> String {
    format!("payload does not match any of the supported image formats: (oci-archive, docker-archive): {e}")
}

/// The largest build context.
const MAX_BUILD_CONTEXT: u64 = 16 << 30;

/// A build made ready: its context on disk and its options.
pub struct Build {
    work: velarx_core::services::build::ContextDir,
    context: velarx_core::services::BuildContext,
    options: velarx_core::services::BuildOptions,
    /// The client answers questions for credentials.
    pub asks_credentials: bool,
    /// The ids of the ssh agents of the client (`--ssh`): the build needs
    /// [`Build::with_agents`].
    pub ssh: Vec<String>,
    /// The RUN steps read the standard input of the client (`--stdin`): the
    /// build needs [`Build::with_stdin`].
    pub stdin: bool,
}

/// The agents of a client of the same process: the sockets it named.
#[derive(Debug)]
pub struct PathAgents(pub Vec<(String, std::path::PathBuf)>);

#[async_trait::async_trait]
impl velarx_core::services::AgentSource for PathAgents {
    fn ids(&self) -> Vec<String> {
        self.0.iter().map(|(i, _)| i.clone()).collect()
    }

    async fn connect(&self, id: &str) -> std::io::Result<std::os::fd::OwnedFd> {
        let path = self
            .0
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, p)| p.clone())
            .ok_or_else(|| std::io::Error::other(format!("no ssh agent {id}")))?;
        let conn = tokio::net::UnixStream::connect(path).await?.into_std()?;
        Ok(conn.into())
    }
}

/// The agents of a client at the other end of a broker socket
/// (`velarx_wire::buildopts`): one ask at a time, the others wait without
/// a thread (a step that opens many connections holds no blocking thread
/// of the engine).
#[derive(Debug)]
pub struct BrokerAgents {
    pub ids: Vec<String>,
    pub broker: Arc<tokio::sync::Mutex<std::os::fd::OwnedFd>>,
}

#[async_trait::async_trait]
impl velarx_core::services::AgentSource for BrokerAgents {
    fn ids(&self) -> Vec<String> {
        self.ids.clone()
    }

    async fn connect(&self, id: &str) -> std::io::Result<std::os::fd::OwnedFd> {
        let index = self
            .ids
            .iter()
            .position(|i| i == id)
            .ok_or_else(|| std::io::Error::other(format!("no ssh agent {id}")))?;
        let broker = self.broker.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            velarx_wire::buildopts::broker_connect(&*broker, index as u32)
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

impl Build {
    /// Where the RUN steps reach the ssh agents of the client.
    pub fn with_agents(mut self, agents: Arc<dyn velarx_core::services::AgentSource>) -> Self {
        self.options.agents = Some(agents);
        self
    }

    /// The standard input of the client, which the RUN steps read.
    pub fn with_stdin(mut self, stdin: std::os::fd::OwnedFd) -> Self {
        self.options.stdin = Some(Arc::new(stdin));
        self
    }

    /// Where the build gets the credentials of the client.
    pub fn with_credentials(
        mut self,
        source: std::sync::Arc<dyn velarx_core::services::build::CredentialSource>,
    ) -> Self {
        self.options.credentials = Some(source);
        self
    }
}

/// The upload `input` written to disk as it comes and extracted into the
/// empty directory `dir` by a confined worker.
async fn unpack_upload(
    state: &AppState,
    mut input: ByteStream,
    work: &mut velarx_core::services::build::ContextDir,
    dir: &std::path::Path,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let bad = |m: String| Error::bad_request(m).with_code(2);
    let archive = work.path().join("context.tar");
    {
        let mut f = tokio::fs::File::create(&archive)
            .await
            .map_err(Error::internal)?;
        let mut total = 0u64;
        let mut guard = Guard::new(Accept::Compressed);
        while let Some(chunk) = input.next().await {
            let chunk = chunk.map_err(|e| bad(format!("read the build context: {e}")))?;
            guard
                .feed(&chunk)
                .map_err(|e| bad(format!("the build context: {e}")))?;
            total += chunk.len() as u64;
            if total > MAX_BUILD_CONTEXT {
                return Err(Error::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "the build context is too large",
                )
                .with_code(2));
            }
            work.reservation.grow(chunk.len() as u64).map_err(|e| {
                Error::new(StatusCode::INSUFFICIENT_STORAGE, e.to_string()).with_code(10)
            })?;
            f.write_all(&chunk).await.map_err(Error::internal)?;
        }
        guard
            .end()
            .map_err(|e| bad(format!("the build context: {e}")))?;
        f.flush().await.map_err(Error::internal)?;
    }
    let file = crate::api::off_thread(move || {
        let file = std::fs::File::open(&archive)?;
        std::fs::remove_file(&archive)?;
        Ok(file)
    })
    .await
    .map_err(Error::internal)?;
    state
        .build_service
        .unpack_context(file, work, dir)
        .await
        .map_err(|e| bad(e.to_string()))?;
    Ok(())
}

/// The context of a build (a tar, `input`) written to disk as it comes and
/// extracted by a confined worker, and the options of `req`.
pub(crate) async fn prepare_build(
    state: &AppState,
    req: BuildImageRequest,
    input: ByteStream,
) -> Result<Build> {
    let bad = |m: String| Error::bad_request(m).with_code(2);
    let containerfile = match req.dockerfile.as_deref().filter(|d| !d.is_empty()) {
        None => None,
        Some(d) => {
            let mut clean = std::path::PathBuf::new();
            for c in std::path::Path::new(d).components() {
                match c {
                    std::path::Component::Normal(n) => clean.push(n),
                    std::path::Component::CurDir => {}
                    _ => {
                        return Err(bad(format!(
                            "the Containerfile `{d}` is outside of the context"
                        )))
                    }
                }
            }
            Some(clean)
        }
    };
    let mut work = state
        .build_service
        .context_dir()
        .map_err(|e| Error::internal(format!("Failed to create the context directory: {e}")))?;
    let dir = work.path().join("context");
    let made = dir.clone();
    crate::api::off_thread(move || std::fs::create_dir(made))
        .await
        .map_err(Error::internal)?;
    let root = match &req.remote {
        Some(remote) => state
            .build_service
            .fetch_context(remote, &mut work, &dir)
            .await
            .map_err(|e| bad(e.to_string()))?,
        None => {
            unpack_upload(state, input, &mut work, &dir).await?;
            dir.clone()
        }
    };
    let containerfile_text = match &req.containerfile_url {
        Some(url) => Some(
            state
                .build_service
                .download_containerfile(url, &mut work)
                .await
                .map_err(|e| bad(e.to_string()))?,
        ),
        None => None,
    };
    let mut context = crate::api::blocking(|| {
        velarx_core::services::BuildContext::new(&root, containerfile.as_deref())
    })
    .map_err(|e| bad(format!("Invalid build context: {e}")))?;
    if req.containerfile_outside {
        context = context
            .take_containerfile()
            .map_err(|e| bad(format!("Invalid build context: {e}")))?;
    }
    if containerfile_text.is_some() {
        context.containerfile_text = containerfile_text;
    }
    let mut secrets = std::collections::HashMap::new();
    for s in req.secrets {
        if s.value.len() > velarx_core::services::MAX_BUILD_SECRET {
            return Err(bad(format!("the secret {} is too large", s.id)));
        }
        if secrets
            .insert(s.id.clone(), velarx_core::services::SecretValue(s.value))
            .is_some()
        {
            return Err(bad(format!("the secret {} is given twice", s.id)));
        }
    }
    let contexts = named_contexts(state, req.contexts, &dir, &mut work).await?;
    let options = velarx_core::services::BuildOptions {
        tags: req.tags,
        build_args: req.build_args,
        labels: req.labels,
        no_cache: req.no_cache,
        layers: req.layers,
        target: req.target,
        platform: req.platform,
        manifest: req.manifest,
        all_platforms: req.all_platforms,
        contexts,
        squash: req.squash,
        squash_all: req.squash_all,
        network: req.network,
        allow: velarx_core::services::build::entitlement::Allow::Listed(req.allow),
        digest: req.digest,
        tls_verify: req.tls_verify,
        run: req.run,
        env: req.env,
        unset_env: req.unset_env,
        unset_labels: req.unset_labels,
        pull: match req.pull.as_deref().filter(|p| !p.is_empty()) {
            None => velarx_core::services::build::PullPolicy::Missing,
            Some(p) => velarx_core::services::build::PullPolicy::parse(p)
                .ok_or_else(|| bad(format!("invalid pull policy `{p}`")))?,
        },
        access: req.access,
        credentials: None,
        secrets,
        agents: None,
        stdin: None,
        flags: req.flags,
    };
    Ok(Build {
        work,
        context,
        options,
        asks_credentials: req.ask_credentials,
        ssh: req.ssh,
        stdin: req.stdin,
    })
}

/// The named contexts of a request: the directories the client put at the
/// top of the upload `dir` (moved out of the context), the images, the
/// repositories and tars of URLs (fetched into `work`).
async fn named_contexts(
    state: &AppState,
    requested: Vec<velarx_wire::buildopts::NamedContextRequest>,
    dir: &std::path::Path,
    work: &mut velarx_core::services::build::ContextDir,
) -> Result<std::collections::HashMap<String, velarx_core::services::NamedContext>> {
    use velarx_core::services::NamedContext;
    use velarx_wire::buildopts::ContextSource;
    let bad = |m: String| Error::bad_request(m).with_code(2);
    let mut out = std::collections::HashMap::new();
    for (n, c) in requested.into_iter().enumerate() {
        let named = match c.source {
            ContextSource::Image(i) => NamedContext::Image(i),
            ContextSource::Upload(name) => {
                if !velarx_wire::buildopts::is_upload_name(&name) {
                    return Err(bad(format!(
                        "the build context {}: invalid name {name:?}",
                        c.name
                    )));
                }
                let moved = work.path().join(format!("named-{n}"));
                let (from, to) = (dir.join(&name), moved.clone());
                crate::api::off_thread(move || std::fs::rename(from, to))
                    .await
                    .map_err(|e| {
                        bad(format!(
                            "the build context {} is not in the upload: {e}",
                            c.name
                        ))
                    })?;
                NamedContext::Dir(moved)
            }
            ContextSource::Url(url) => {
                let into = work.path().join(format!("named-{n}"));
                let made = into.clone();
                crate::api::off_thread(move || std::fs::create_dir(made))
                    .await
                    .map_err(Error::internal)?;
                let root = state
                    .build_service
                    .fetch_context(&url, work, &into)
                    .await
                    .map_err(|e| bad(format!("the build context {}: {e}", c.name)))?;
                NamedContext::Dir(root)
            }
        };
        if out.insert(c.name.clone(), named).is_some() {
            return Err(bad(format!("the build context {} is given twice", c.name)));
        }
    }
    Ok(out)
}

/// Run a build, what it does told on `progress`: the ID of the image;
/// `cancel` stops it (its containers and layers cleaned up as for a step
/// that failed).
pub(crate) async fn build(
    state: &AppState,
    build: Build,
    progress: Option<mpsc::Sender<velarx_core::services::BuildProgress>>,
    cancel: velarx_core::services::Cancel,
) -> Result<String> {
    let Build {
        work: _work,
        context,
        options,
        asks_credentials: _,
        ssh: _,
        stdin,
    } = build;
    if stdin && options.stdin.is_none() {
        return Err(Error::bad_request(
            "--stdin: the build has no standard input to give",
        ));
    }
    state
        .build_service
        .build(&context, &options, progress, cancel)
        .await
        .map_err(Error::internal)
}
