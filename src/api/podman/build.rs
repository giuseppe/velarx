// SPDX-License-Identifier: Apache-2.0
//! Builds for the frontends: the spec of the build ([`BuildSpec`]) and its
//! context (a tar, plain, gzip or zstd, from a pipe), the named directories
//! as descriptors; the progress is podman's and Docker's JSON lines.

use super::error::{ApiError, ApiResult};
use super::images::{image_id, resolve_image};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use velarx_core::services::{BuildContext, BuildOptions, BuildProgress, NamedContext};
use velarx_proto::buildspec::{
    BuildClient, BuildContextKind, BuildEvent, BuildEventKind as K, BuildOutputKind, BuildPull,
    BuildSecretKind, BuildSpec,
};
use velarx_proto::workload::EventKind;
use velarx_wire::buildopts::BuildFlagsCheck;

/// Largest build context.
const MAX_CONTEXT: u64 = 4 * 1024 * 1024 * 1024;
/// The most named contexts an upload of sections has.
const MAX_SECTIONS: usize = 64;

/// What a build request asks, but its context.
struct Request {
    options: BuildOptions,
    tags: Vec<String>,
    manifest: Option<String>,
    /// `outputs`: where the files of the image go on this host
    output: Option<velarx_wire::buildopts::Output>,
}

fn request_of(
    state: &super::AppState,
    spec: BuildSpec,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<Request> {
    let compat = spec.client == BuildClient::Docker;
    let tags: Vec<String> = spec
        .tags
        .iter()
        .map(|t| super::images::qualify_name(state, !compat, t))
        .collect();
    let pull = match spec.pull {
        BuildPull::Missing => velarx_core::services::build::PullPolicy::Missing,
        BuildPull::Always => velarx_core::services::build::PullPolicy::Always,
        BuildPull::Newer => velarx_core::services::build::PullPolicy::Newer,
        BuildPull::Never => velarx_core::services::build::PullPolicy::Never,
    };
    let mut flags = spec.flags;
    if spec.http_proxy {
        // (the proxy of the engine, as podman's service passes its own)
        flags.proxy_env = crate::cli::run::host_env(false, true, std::env::vars(), &[])
            .iter()
            .map(|a| velarx_proto::buildspec::BuildPair::parse(a))
            .collect();
    }
    flags.check().map_err(ApiError::bad_request)?;
    let options = BuildOptions {
        // (as given on libpod: the engine qualifies them, and the build
        // says the first one as written)
        tags: if compat { tags.clone() } else { spec.tags },
        build_args: velarx_proto::buildspec::unpair(spec.build_args).collect(),
        no_cache: spec.no_cache,
        layers: spec.layers,
        target: spec.target,
        labels: velarx_proto::buildspec::unpair(spec.labels).collect(),
        platform: spec.platform,
        manifest: spec.manifest.clone(),
        all_platforms: spec.all_platforms,
        contexts: HashMap::new(),
        squash: spec.squash,
        squash_all: spec.squash_all,
        network: spec.network,
        // (the client cannot say `allow`: the configuration decides)
        allow: velarx_core::services::build::entitlement::Allow::ByConfig,
        digest: spec.digest,
        tls_verify: spec.tls_verify,
        run: spec.run,
        env: velarx_proto::buildspec::unpair(spec.env).collect(),
        unset_env: spec.unset_env,
        unset_labels: spec.unset_labels,
        pull,
        access,
        credentials: None,
        secrets: HashMap::new(),
        agents: None,
        stdin: None,
        flags,
    };
    let output = spec.output.map(|o| match o.kind {
        BuildOutputKind::Dir => velarx_wire::buildopts::Output::Dir(o.path.into()),
        BuildOutputKind::Tar => velarx_wire::buildopts::Output::Tar(Some(o.path.into())),
    });
    Ok(Request {
        options,
        tags,
        manifest: spec.manifest,
        output,
    })
}

/// The context from a pipe, in the frames the frontend writes
/// ([`velarx_proto::build::MAX_CONTEXT_FRAME`]): the upload as such has
/// no time limit (a client sends as it can), but nothing for
/// [`velarx_proto::build::CONTEXT_STALL`] gives it up (408), and a pipe
/// that ends before the end frame is an upload the client did not finish
/// (400): a tar cut between two entries would build from fewer files.
pub struct PipeSource(pub Option<tokio::net::unix::pipe::Receiver>);

impl PipeSource {
    /// The upload as the bytes an operation reads (`what` names it in the
    /// errors): an error ends it.
    pub fn into_stream(self, what: String) -> crate::api::ops::ByteStream {
        Box::pin(futures::stream::unfold(Some((self, what)), |state| async {
            let (mut source, what) = state?;
            match source
                .next_of(velarx_proto::build::CONTEXT_STALL, &what)
                .await
            {
                Ok(Some(chunk)) => Some((Ok(chunk), Some((source, what)))),
                Ok(None) => None,
                Err(e) => Some((Err(std::io::Error::other(e.message)), None)),
            }
        }))
    }

    async fn fill(
        pipe: &mut tokio::net::unix::pipe::Receiver,
        buf: &mut [u8],
        stall: std::time::Duration,
        what: &str,
    ) -> ApiResult<()> {
        use tokio::io::AsyncReadExt;
        let mut done = 0;
        while done < buf.len() {
            let n = tokio::time::timeout(stall, pipe.read(&mut buf[done..]))
                .await
                .map_err(|_| {
                    ApiError::new(
                        408,
                        format!("{what} stalled: nothing came for {} s", stall.as_secs()),
                    )
                })?
                .map_err(|e| ApiError::bad_request(format!("read {what}: {e}")))?;
            if n == 0 {
                return Err(ApiError::bad_request(format!(
                    "{what} ended early: the upload was not finished"
                )));
            }
            done += n;
        }
        Ok(())
    }

    async fn next_within(&mut self, stall: std::time::Duration) -> ApiResult<Option<bytes::Bytes>> {
        self.next_of(stall, "the build context").await
    }

    async fn next_of(
        &mut self,
        stall: std::time::Duration,
        what: &str,
    ) -> ApiResult<Option<bytes::Bytes>> {
        let chunk = self.frame(stall, what).await?;
        if chunk.is_none() {
            self.0 = None;
        }
        Ok(chunk)
    }

    /// The next frame, none at the empty one.  A frame of the length
    /// `u32::MAX` is the frontend giving the upload up, with its reason.
    async fn frame(
        &mut self,
        stall: std::time::Duration,
        what: &str,
    ) -> ApiResult<Option<bytes::Bytes>> {
        let Some(pipe) = self.0.as_mut() else {
            return Ok(None);
        };
        let mut head = [0u8; 4];
        Self::fill(pipe, &mut head, stall, what).await?;
        let n = u32::from_be_bytes(head);
        if n == velarx_proto::build::FRAME_ABORT {
            Self::fill(pipe, &mut head, stall, what).await?;
            let len =
                (u32::from_be_bytes(head) as usize).min(velarx_proto::build::MAX_ABORT_REASON);
            let mut reason = vec![0u8; len];
            Self::fill(pipe, &mut reason, stall, what).await?;
            self.0 = None;
            return Err(ApiError::bad_request(
                String::from_utf8_lossy(&reason).into_owned(),
            ));
        }
        let n = n as usize;
        if n == 0 {
            return Ok(None);
        }
        if n > velarx_proto::build::MAX_CONTEXT_FRAME {
            return Err(ApiError::bad_request(format!(
                "a frame of {what} is {n} bytes"
            )));
        }
        let mut buf = bytes::BytesMut::zeroed(n);
        Self::fill(pipe, &mut buf, stall, what).await?;
        Ok(Some(buf.freeze()))
    }

    /// The name of the next section of an upload of sections, none at its
    /// end; the content of the section is [`Self::next_in_section`].
    pub async fn next_section(&mut self) -> ApiResult<Option<String>> {
        let name = self
            .frame(velarx_proto::build::CONTEXT_STALL, "the build context")
            .await?;
        match name {
            Some(n) => Ok(Some(String::from_utf8_lossy(&n).into_owned())),
            None => {
                self.0 = None;
                Ok(None)
            }
        }
    }

    /// The next piece of the tar, none at its end.
    pub async fn next(&mut self) -> ApiResult<Option<bytes::Bytes>> {
        self.next_within(velarx_proto::build::CONTEXT_STALL).await
    }

    /// The next piece of the section, none at its end.
    pub async fn next_in_section(&mut self) -> ApiResult<Option<bytes::Bytes>> {
        self.frame(velarx_proto::build::CONTEXT_STALL, "the build context")
            .await
    }
}

/// A place for one more build, else the answer a client that builds too
/// much gets.
fn admitted(state: &super::AppState) -> ApiResult<velarx_core::services::build::Admission> {
    state.build_service.admit().ok_or_else(|| {
        ApiError::new(
            429,
            "too many builds are running or waiting: try again later",
        )
    })
}

/// A build ready to run: its progress is streamed as JSON lines.
pub struct BuildRun {
    state: std::sync::Arc<super::AppState>,
    ctx: BuildContext,
    req: Request,
    /// Lives until the build is done
    held: Held,
}

/// What a build holds until it is done.  The fields drop in this order: the
/// directory of its context goes first, the place it took last.
struct Held {
    _dir: velarx_core::services::build::ContextDir,
    _admission: velarx_core::services::build::Admission,
}

/// Check the spec and take the context: the errors before the progress.
/// `sectioned`: the upload is a sequence of sections, the main context and
/// named ones (see [`PipeSource::next_section`]).
pub async fn build_of(
    state: &std::sync::Arc<super::AppState>,
    spec: BuildSpec,
    access: velarx_registry::auth::RegistryAccess,
    mut source: PipeSource,
    sectioned: bool,
) -> ApiResult<BuildRun> {
    if spec.local_dir.is_some() || spec.containerfile_host.is_some() {
        return Err(ApiError::bad_request(
            "a directory or a Containerfile of the host is the local build's",
        ));
    }
    let remote = spec.remote.clone();
    let containerfile = spec.containerfile.clone().map(PathBuf::from);
    let containerfile_url = spec.containerfile_url.clone();
    let ignore_file = spec.ignore_file.clone().map(PathBuf::from);
    let (secrets, contexts) = (spec.secrets.clone(), spec.contexts.clone());
    let req = request_of(state, spec, access)?;
    let state = state.clone();
    let admission = admitted(&state)?;
    let mut dir = state.build_service.context_dir()?;
    let text = containerfile_of_url(&state, containerfile_url, &mut dir).await?;
    let context_dir = dir.path().join("context");
    let made = context_dir.clone();
    crate::api::off_thread(move || std::fs::create_dir(made)).await?;
    // A remote context (a git repository, or a tar to download): the body
    // is ignored.
    if let Some(remote) = remote {
        let root = state
            .build_service
            .fetch_context(&remote, &mut dir, &context_dir)
            .await
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        let mut ctx = BuildContext::new(&root, containerfile.as_deref())
            .map_err(|e| ApiError::bad_request(format!("invalid build context: {e}")))?;
        ctx.containerfile_text = text;
        let mut req = req;
        named_contexts_of(&state, &contexts, &mut req, &mut dir, false).await?;
        return Ok(BuildRun {
            state,
            ctx,
            req,
            held: Held {
                _dir: dir,
                _admission: admission,
            },
        });
    }

    // the context goes to a file first, a worker extracts it; the named
    // contexts of an upload of sections to files of their own
    let mut req = req;
    let mut total = 0u64;
    let base = dir.path().to_path_buf();
    let reservation = &mut dir.reservation;
    let mut take = |chunk: &[u8]| {
        total += chunk.len() as u64;
        if total > MAX_CONTEXT {
            return Err(ApiError::new(413, "the build context is too large"));
        }
        reservation
            .grow(chunk.len() as u64)
            .map_err(|e| ApiError::new(507, e.to_string()))
    };
    let archive = base.join("context.tar");
    let named = if sectioned {
        spool_sections(&mut source, &base, &mut take).await?
    } else {
        let mut f = tokio::fs::File::create(&archive).await?;
        while let Some(chunk) = source.next().await? {
            take(&chunk)?;
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
        Vec::new()
    };
    let file = crate::api::off_thread(move || {
        let file = std::fs::File::open(&archive)?;
        std::fs::remove_file(&archive)?;
        Ok(file)
    })
    .await?;
    state
        .build_service
        .unpack_context(file, &mut dir, &context_dir)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    // (the named parts first: those of the query override them)
    for (n, (name, path)) in named.into_iter().enumerate() {
        let into = dir.path().join(format!("part-{n}"));
        let made = into.clone();
        let file = crate::api::off_thread(move || {
            std::fs::create_dir(made)?;
            let file = std::fs::File::open(&path)?;
            std::fs::remove_file(&path)?;
            Ok(file)
        })
        .await?;
        state
            .build_service
            .unpack_context(file, &mut dir, &into)
            .await
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        req.options.contexts.insert(name, NamedContext::Dir(into));
    }
    crate::api::blocking(|| take_secrets(&secrets, &mut req, Some(&context_dir)))?;
    named_contexts_of(&state, &contexts, &mut req, &mut dir, false).await?;
    let mut ctx = crate::api::blocking(|| {
        let ctx = BuildContext::new(&context_dir, containerfile.as_deref())?;
        match &ignore_file {
            Some(f) => ctx.with_ignore_file(f),
            None => Ok(ctx),
        }
    })
    .map_err(|e| ApiError::bad_request(format!("invalid build context: {e}")))?;
    ctx.containerfile_text = text;
    Ok(BuildRun {
        state,
        ctx,
        req,
        held: Held {
            _dir: dir,
            _admission: admission,
        },
    })
}

/// Read a file of at most `max` bytes, no link followed on the way: one at
/// the top of `dir` (then removed, it is not in the context), or with
/// `dir` none a path of this host.
fn take_file(dir: Option<&Path>, name: &str, max: u64) -> ApiResult<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};
    let bad =
        |e: &dyn std::fmt::Display| ApiError::bad_request(format!("the secret file {name}: {e}"));
    let (fd, root) = match dir {
        Some(dir) => {
            if name.contains('/') || name == ".." || name == "." || name.is_empty() {
                return Err(bad(&"not a file at the top of the context"));
            }
            let root = rustix::fs::open(
                dir,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| bad(&e))?;
            let fd = rustix::fs::openat(
                &root,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|e| bad(&e))?;
            (fd, Some(root))
        }
        None => {
            let path = local_path("secrets", name)?;
            let fd = rustix::fs::open(
                &path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|e| bad(&e))?;
            (fd, None)
        }
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| bad(&e))?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(bad(&"not a regular file"));
    }
    let mut data = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::from(fd), max + 1),
        &mut data,
    )
    .map_err(|e| bad(&e))?;
    if data.len() as u64 > max {
        return Err(bad(&format!("larger than {max} bytes")));
    }
    if let Some(root) = root {
        rustix::fs::unlinkat(&root, name, rustix::fs::AtFlags::empty()).map_err(|e| bad(&e))?;
    }
    Ok(data)
}

/// The sections of an upload (see [`PipeSource::next_section`]) as files of
/// `dir`: the main context in `context.tar`, each named one in a file of its
/// own (the names and the files, in their order).  `take` has each piece
/// before it is written; the most named contexts are refused before the
/// content of one more is read.
async fn spool_sections(
    source: &mut PipeSource,
    dir: &Path,
    take: &mut impl FnMut(&[u8]) -> ApiResult<()>,
) -> ApiResult<Vec<(String, PathBuf)>> {
    let mut named: Vec<(String, PathBuf)> = Vec::new();
    let mut main = false;
    while let Some(header) = source.next_section().await? {
        let target = if header == velarx_proto::build::SECTION_MAIN {
            main = true;
            dir.join("context.tar")
        } else if let Some(name) = header.strip_prefix(velarx_proto::build::SECTION_CONTEXT) {
            if named.len() >= MAX_SECTIONS {
                return Err(ApiError::bad_request(
                    "invalid multipart body: too many parts in the multipart body",
                ));
            }
            let path = dir.join(format!("section-{}.tar", named.len()));
            named.push((name.to_string(), path.clone()));
            path
        } else {
            return Err(ApiError::bad_request(format!(
                "an unknown part {header:?} of the build body"
            )));
        };
        let mut f = tokio::fs::File::create(&target).await?;
        while let Some(chunk) = source.next_in_section().await? {
            take(&chunk)?;
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
    }
    if !main {
        return Err(ApiError::bad_request(
            "the multipart body has no MainContext",
        ));
    }
    Ok(named)
}

/// The secrets of the spec into the options: from the context `dir`
/// (taken out of it), or with none from this host (the local route).
fn take_secrets(
    secrets: &[velarx_proto::buildspec::BuildSecretSpec],
    req: &mut Request,
    dir: Option<&Path>,
) -> ApiResult<()> {
    for s in secrets {
        // (a file of the context is one of the upload, a file of the host
        // one of the local route: never the one for the other)
        let (name, here) = match (s.kind, dir) {
            (BuildSecretKind::ContextFile, Some(dir)) => (&s.source, Some(dir)),
            (BuildSecretKind::HostFile, None) => (&s.source, None),
            (BuildSecretKind::ContextFile, None) => {
                return Err(ApiError::bad_request(format!(
                    "the secret {}: the local build has no upload to take it from",
                    s.id
                )))
            }
            (BuildSecretKind::HostFile, Some(_)) => {
                return Err(ApiError::bad_request(format!(
                    "the secret {}: a file of the host is the local build's",
                    s.id
                )))
            }
            (BuildSecretKind::Value, _) => {
                return Err(ApiError::bad_request(
                    "a secret of the command line is not one of the routes",
                ))
            }
        };
        let data = take_file(here, name, velarx_core::services::MAX_BUILD_SECRET as u64)?;
        req.options
            .secrets
            .insert(s.id.clone(), velarx_core::services::SecretValue(data));
    }
    Ok(())
}

/// The named contexts of the spec: a URL is cloned or downloaded into
/// `work`, a directory of the host is the host's (the local route).
async fn named_contexts_of(
    state: &std::sync::Arc<super::AppState>,
    contexts: &[velarx_proto::buildspec::BuildContextSpec],
    req: &mut Request,
    work: &mut velarx_core::services::build::ContextDir,
    local: bool,
) -> ApiResult<()> {
    for (n, c) in contexts.iter().enumerate() {
        let name = &c.name;
        let named = match c.kind {
            BuildContextKind::Image => NamedContext::Image(c.source.clone()),
            BuildContextKind::Url => {
                let url = &c.source;
                let into = work.path().join(format!("named-{n}"));
                let made = into.clone();
                crate::api::off_thread(move || std::fs::create_dir(made)).await?;
                let root = state
                    .build_service
                    .fetch_context(url, work, &into)
                    .await
                    .map_err(|e| ApiError::bad_request(format!("the build context {name}: {e}")))?;
                NamedContext::Dir(root)
            }
            BuildContextKind::Host => {
                let p = &c.source;
                if !local {
                    return Err(ApiError::bad_request(format!(
                        "the build context {name}: a path of the client goes in a multipart body"
                    )));
                }
                let path = local_path("additionalbuildcontexts", p)?;
                if !is_dir(&path).await {
                    return Err(ApiError::bad_request(format!("{p} is not a directory")));
                }
                NamedContext::Dir(path)
            }
            BuildContextKind::Upload => {
                return Err(ApiError::bad_request(format!(
                    "the build context {name}: a directory of the upload is the command line's"
                )))
            }
        };
        req.options.contexts.insert(name.clone(), named);
    }
    Ok(())
}

/// Whether `path` is a directory (one stat, off the async threads).
async fn is_dir(path: &Path) -> bool {
    let path = path.to_path_buf();
    crate::api::off_thread(move || Ok(path.is_dir()))
        .await
        .unwrap_or(false)
}

/// An absolute path of the daemon's host the local API names: 400 when it
/// is not absolute, 404 when it does not exist.
fn local_path(what: &str, p: &str) -> ApiResult<PathBuf> {
    if p.is_empty() {
        return Err(ApiError::bad_request(format!("{what} cannot be empty")));
    }
    let path = Path::new(p);
    if !path.is_absolute() {
        return Err(ApiError::bad_request(format!(
            "{what}: the path {p:?} is not absolute"
        )));
    }
    match std::fs::metadata(path) {
        Ok(_) => Ok(path.to_path_buf()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ApiError::not_found(format!(
            "{what}: {p}: no such file or directory"
        ))),
        Err(e) => Err(ApiError::bad_request(format!("{what}: {p}: {e}"))),
    }
}

/// The Containerfile of an http(s) URL (`-f URL`), fetched by the engine.
async fn containerfile_of_url(
    state: &super::AppState,
    url: Option<String>,
    work: &mut velarx_core::services::build::ContextDir,
) -> ApiResult<Option<String>> {
    let Some(url) = url else {
        return Ok(None);
    };
    state
        .build_service
        .download_containerfile(&url, work)
        .await
        .map(Some)
        .map_err(|e| ApiError::bad_request(e.to_string()))
}

pub async fn local_build_of(
    state: &std::sync::Arc<super::AppState>,
    spec: BuildSpec,
    access: velarx_registry::auth::RegistryAccess,
) -> ApiResult<BuildRun> {
    if spec.remote.is_some() {
        return Err(ApiError::bad_request(
            "the local build takes a directory of the host, not a remote context",
        ));
    }
    let local_dir = spec.local_dir.clone().unwrap_or_default();
    let containerfile = spec.containerfile.clone().map(PathBuf::from);
    let containerfile_host = spec.containerfile_host.clone();
    let containerfile_url = spec.containerfile_url.clone();
    let (secrets, contexts) = (spec.secrets.clone(), spec.contexts.clone());
    let req = request_of(state, spec, access)?;
    let admission = admitted(state)?;
    let dir = local_path("localcontextdir", &local_dir)?;
    if !is_dir(&dir).await {
        return Err(ApiError::bad_request(format!(
            "localcontextdir: {} is not a directory",
            dir.display()
        )));
    }
    let mut ctx = crate::api::blocking(|| BuildContext::new(&dir, None))
        .map_err(|e| ApiError::bad_request(format!("invalid build context: {e}")))?;
    if let Some(dockerfile) = containerfile_host {
        let path = local_path("dockerfile", &dockerfile)?;
        let text = crate::api::off_thread(move || {
            velarx_base::conf::read_config_file(&path, velarx_wire::parse::MAX_FILE)
        })
        .await
        .map_err(|e| ApiError::bad_request(format!("dockerfile: {e}")))?;
        ctx.containerfile_text = Some(text);
    } else {
        ctx.containerfile = containerfile;
    }
    let mut req = req;
    crate::api::blocking(|| take_secrets(&secrets, &mut req, None))?;
    let mut work = state.build_service.context_dir()?;
    if let Some(text) = containerfile_of_url(state, containerfile_url, &mut work).await? {
        ctx.containerfile_text = Some(text);
    }
    named_contexts_of(state, &contexts, &mut req, &mut work, true).await?;
    Ok(BuildRun {
        state: state.clone(),
        ctx,
        req,
        held: Held {
            _dir: work,
            _admission: admission,
        },
    })
}

/// Check the spec and take the context a client opened and sent as a
/// directory descriptor (`dir`): the build reads the directory through it, in
/// place, and nothing of it is copied, changed or removed.
pub async fn dir_build_of(
    state: &std::sync::Arc<super::AppState>,
    spec: BuildSpec,
    access: velarx_registry::auth::RegistryAccess,
    dir: std::os::fd::OwnedFd,
) -> ApiResult<BuildRun> {
    if spec.remote.is_some() || spec.local_dir.is_some() || spec.containerfile_host.is_some() {
        return Err(ApiError::bad_request(
            "a context that is a directory has no other place named",
        ));
    }
    if !spec.secrets.is_empty() {
        return Err(ApiError::bad_request(
            "a context that is a directory carries no secret files: it is the client's own tree, and the engine takes nothing out of it",
        ));
    }
    let containerfile = spec.containerfile.clone().map(PathBuf::from);
    let containerfile_url = spec.containerfile_url.clone();
    let contexts = spec.contexts.clone();
    let mut req = request_of(state, spec, access)?;
    let state = state.clone();
    let admission = admitted(&state)?;
    let mut work = state.build_service.context_dir()?;
    let text = containerfile_of_url(&state, containerfile_url, &mut work).await?;
    named_contexts_of(&state, &contexts, &mut req, &mut work, false).await?;
    let mut ctx = crate::api::blocking(|| BuildContext::from_fd(dir, containerfile.as_deref()))
        .map_err(|e| ApiError::bad_request(format!("invalid build context: {e}")))?;
    ctx.containerfile_text = text;
    Ok(BuildRun {
        state,
        ctx,
        req,
        held: Held {
            _dir: work,
            _admission: admission,
        },
    })
}

impl BuildRun {
    /// Run the build, its progress streamed as events: the steps and their
    /// output, then the end (`complete` with the id and the qualified tags,
    /// or `error`); the frontend lays them out.  The reader that goes stops
    /// the build, as podman's service does.
    pub async fn run<W: super::stream::Sink>(self, mut out: super::stream::JsonLines<W>) {
        let Self {
            state,
            ctx,
            req,
            held,
        } = self;
        let Request {
            options,
            tags,
            manifest,
            output,
        } = req;
        let _held = held;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BuildProgress>(100);
        let svc = state.build_service.clone();
        // As podman's (the context of the request): the reader that goes
        // stops the build, whether it waits for its turn or runs.
        let (stop, cancel) = velarx_core::services::Cancel::new();
        let build = tokio::spawn(async move { svc.build(&ctx, &options, Some(tx), cancel).await });
        let mut alive = true;
        loop {
            let ev = if alive {
                match out.while_there(rx.recv()).await {
                    Some(ev) => ev,
                    None => {
                        let _ = stop.send(true);
                        alive = false;
                        continue;
                    }
                }
            } else {
                rx.recv().await
            };
            let Some(ev) = ev else {
                break;
            };
            // (the frontends tell the steps and their output only)
            let Some(event) = event_of(ev).filter(|e| !matches!(e.kind, K::Started | K::Progress))
            else {
                continue;
            };
            if !alive {
                continue;
            }
            alive = out.send(&event).await;
            if !alive {
                let _ = stop.send(true);
            }
        }
        let built = build.await;
        let built = match (built, output) {
            (Ok(Ok(id)), Some(output)) => match write_output(&state, &id, output).await {
                Ok(()) => Ok(Ok(id)),
                Err(e) => Ok(Err(e)),
            },
            (built, _) => built,
        };
        let result = match built {
            // The id of the manifest list.
            Ok(Ok(id)) if manifest.is_some() => Ok(id),
            Ok(Ok(id)) => resolve_image(&state, &id)
                .await
                .map(|r| image_id(&r))
                .map_err(|e| e.message),
            Ok(Err(e)) => Err(e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        let last = match result {
            Ok(id) => {
                state.podman.events.emit(super::events::Event::new(
                    EventKind::Image,
                    "build",
                    &id,
                    "",
                ));
                BuildEvent {
                    kind: K::Complete,
                    text: id,
                    tags,
                    ..Default::default()
                }
            }
            Err(text) => BuildEvent {
                kind: K::Error,
                text,
                ..Default::default()
            },
        };
        out.send(&last).await;
    }
}

/// A line of the stream of events.
pub(crate) fn event_line(event: &BuildEvent) -> String {
    let mut line = serde_json::to_string(event).unwrap_or_default();
    line.push('\n');
    line
}

/// What a client is told of the progress of a build; nothing of the end,
/// which the build tells itself.
pub(crate) fn event_of(progress: BuildProgress) -> Option<BuildEvent> {
    use velarx_proto::buildspec::BuildStream as S;
    let output = |step, text, stream| BuildEvent {
        kind: K::Output,
        step,
        text,
        stream,
        ..Default::default()
    };
    Some(match progress {
        BuildProgress::Started { total_steps } => BuildEvent {
            kind: K::Started,
            step: total_steps as u64,
            ..Default::default()
        },
        BuildProgress::StepStarted { step, instruction } => BuildEvent {
            kind: K::Step,
            step: step as u64,
            text: instruction,
            ..Default::default()
        },
        BuildProgress::StepOutput { step, output: o } => output(step as u64, o, S::Step),
        BuildProgress::RunOutput {
            step,
            stderr,
            output: o,
        } => output(step as u64, o, if stderr { S::Stderr } else { S::Stdout }),
        BuildProgress::Report { output: o } => output(0, o, S::Report),
        BuildProgress::Blob(p) => BuildEvent {
            kind: K::Progress,
            progress: Some(super::images::pull::progress_record(p)),
            ..Default::default()
        },
        BuildProgress::Platform { platform } => BuildEvent {
            kind: K::Platform,
            text: platform,
            ..Default::default()
        },
        BuildProgress::StepCompleted { .. }
        | BuildProgress::Completed { .. }
        | BuildProgress::Error { .. } => return None,
    })
}

/// The progress of a build of the command line as lines of events; the build
/// goes on if the reader goes away (its images and containers are cleaned
/// up by the build, not dropped half way).
pub(crate) fn cli_events(
    state: std::sync::Arc<super::AppState>,
    mut build: crate::api::ops::image::Build,
) -> tokio::sync::mpsc::Receiver<String> {
    use crate::api::build_credentials::StreamAsker;
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<BuildProgress>(100);
    let (tx, rx) = tokio::sync::mpsc::channel(100);
    if build.asks_credentials {
        build = build.with_credentials(std::sync::Arc::new(StreamAsker::new(
            state.build_asks.clone(),
            tx.clone(),
        )));
    }
    let job = tokio::spawn(async move {
        crate::api::ops::image::build(&state, build, Some(progress_tx), Default::default()).await
    });
    tokio::spawn(async move {
        while let Some(progress) = progress_rx.recv().await {
            let Some(event) = event_of(progress) else {
                continue;
            };
            if tx.send(event_line(&event)).await.is_err() {
                break;
            }
        }
        // (the build must not wait for a reader that went away)
        drop(progress_rx);
        let last = match job.await {
            Ok(Ok(image_id)) => BuildEvent {
                kind: K::Complete,
                text: image_id,
                ..Default::default()
            },
            Ok(Err(e)) => BuildEvent {
                kind: K::Error,
                text: e.message,
                ..Default::default()
            },
            Err(e) => BuildEvent {
                kind: K::Error,
                text: e.to_string(),
                ..Default::default()
            },
        };
        let _ = tx.send(event_line(&last)).await;
    });
    rx
}

/// `outputs`: the files of the image `image` written where the output says,
/// from a container made of it (never started).
async fn write_output(
    state: &std::sync::Arc<super::AppState>,
    image: &str,
    output: velarx_wire::buildopts::Output,
) -> Result<(), velarx_core::services::build::BuildError> {
    use futures::StreamExt;
    use velarx_core::services::build::BuildError;
    let failed = |e: &dyn std::fmt::Display| BuildError::StepFailed(e.to_string());
    let cs = state.container_service.clone();
    let id = cs
        .create(velarx_core::services::CreateContainerRequest {
            image: image.to_string(),
            command: vec!["true".into()],
            labels: [(
                velarx_core::services::build::BUILD_LABEL.to_string(),
                std::process::id().to_string(),
            )]
            .into(),
            ..Default::default()
        })
        .await
        .map_err(|e| failed(&e))?;
    let written = async {
        let mut stream = super::archive::export_of(state, &id)
            .await
            .map_err(|e| failed(&e.message))?;
        let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(4);
        let task = tokio::task::spawn_blocking(move || {
            struct Chunks {
                rx: tokio::sync::mpsc::Receiver<std::io::Result<bytes::Bytes>>,
                rest: bytes::Bytes,
            }
            impl std::io::Read for Chunks {
                fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                    while self.rest.is_empty() {
                        match self.rx.blocking_recv() {
                            Some(chunk) => self.rest = chunk?,
                            None => return Ok(0),
                        }
                    }
                    let n = buf.len().min(self.rest.len());
                    buf[..n].copy_from_slice(&self.rest.split_to(n));
                    Ok(n)
                }
            }
            output.write(
                Chunks {
                    rx,
                    rest: bytes::Bytes::new(),
                },
                &mut |w| tracing::warn!("{w}"),
            )
        });
        while let Some(chunk) = stream.next().await {
            if tx.send(chunk).await.is_err() {
                break;
            }
        }
        drop(tx);
        task.await.map_err(|e| failed(&e))?.map_err(|e| failed(&e))
    }
    .await;
    if let Err(e) = cs.delete(&id, true).await {
        tracing::warn!("Cannot remove the build container {id}: {e}");
    }
    written
}

pub async fn build_prune_of(
    state: &std::sync::Arc<super::AppState>,
) -> ApiResult<velarx_proto::workload::BuildPruned> {
    let (deleted, mut space) = state.image_service.prune_build_cache().await?;
    // (and the directories of RUN --mount=type=cache nothing uses)
    let svc = state.build_service.clone();
    space += tokio::task::spawn_blocking(move || svc.prune_cache_mounts())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))??;
    for id in &deleted {
        state.podman.events.emit(super::events::Event::new(
            EventKind::Image,
            "remove",
            id,
            "",
        ));
    }
    Ok(velarx_proto::workload::BuildPruned {
        ids: deleted,
        space,
    })
}

#[cfg(test)]
mod pipe_source_tests {
    use super::PipeSource;
    use std::io::Write;
    use std::time::Duration;

    fn source(bytes: &[u8], keep_open: bool) -> (PipeSource, Option<std::fs::File>) {
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let mut w = std::fs::File::from(write);
        w.write_all(bytes).unwrap();
        let r = tokio::net::unix::pipe::Receiver::from_owned_fd(read).unwrap();
        (PipeSource(Some(r)), keep_open.then_some(w))
    }

    fn frame(data: &[u8]) -> Vec<u8> {
        let mut v = (data.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(data);
        v
    }

    const LONG: Duration = Duration::from_secs(30);

    #[tokio::test]
    async fn the_frames_are_the_context_up_to_the_end_frame() {
        let mut bytes = frame(b"abc");
        bytes.extend(frame(b"de"));
        bytes.extend(frame(b""));
        let (mut s, _) = source(&bytes, false);
        let mut got = Vec::new();
        while let Some(c) = s.next_within(LONG).await.unwrap() {
            got.extend_from_slice(&c);
        }
        assert_eq!(got, b"abcde");
        assert!(s.next_within(LONG).await.unwrap().is_none());
    }

    /// A tar cut between two entries is a valid tar: the missing end
    /// frame is what says the upload was not finished.
    #[tokio::test]
    async fn a_pipe_that_ends_before_the_end_frame_is_an_error() {
        for bytes in [frame(b"abc"), frame(b"abc")[..5].to_vec(), vec![0, 0]] {
            let (mut s, _) = source(&bytes, false);
            let mut r = s.next_within(LONG).await;
            while let Ok(Some(_)) = r {
                r = s.next_within(LONG).await;
            }
            let e = r.unwrap_err();
            assert_eq!(e.status.as_u16(), 400, "{bytes:?}");
        }
    }

    #[tokio::test]
    async fn a_stalled_upload_is_given_up_and_a_huge_frame_refused() {
        let (mut s, _w) = source(&frame(b"x")[..3], true);
        let e = s.next_within(Duration::from_millis(50)).await.unwrap_err();
        assert_eq!(e.status.as_u16(), 408);
        let huge = ((velarx_proto::build::MAX_CONTEXT_FRAME + 1) as u32).to_be_bytes();
        let (mut s, _w) = source(&huge, true);
        assert_eq!(s.next_within(LONG).await.unwrap_err().status.as_u16(), 400);
    }
}

#[cfg(test)]
mod spec_tests {
    use super::*;
    use velarx_proto::buildspec::BuildSecretSpec;

    fn request() -> Request {
        Request {
            options: BuildOptions::default(),
            tags: Vec::new(),
            manifest: None,
            output: None,
        }
    }

    /// A file of the host is a secret of the local route only, a file of
    /// the context one of the upload only: whatever the spec says, the
    /// build of an upload reads no file of the host.
    #[test]
    fn a_secret_is_read_from_where_its_route_takes_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s"), "context").unwrap();
        let host = dir.path().join("h");
        std::fs::write(&host, "host").unwrap();
        let secret = |kind, source: &str| {
            vec![BuildSecretSpec {
                id: "s".into(),
                kind,
                source: source.into(),
            }]
        };
        let host_file = secret(BuildSecretKind::HostFile, &host.display().to_string());
        let e = take_secrets(&host_file, &mut request(), Some(dir.path()))
            .err()
            .unwrap();
        assert!(e.to_string().contains("the local build's"), "{e}");
        let e = take_secrets(
            &secret(BuildSecretKind::ContextFile, "s"),
            &mut request(),
            None,
        )
        .err()
        .unwrap();
        assert!(e.to_string().contains("no upload"), "{e}");
        let mut req = request();
        take_secrets(&host_file, &mut req, None).unwrap();
        assert_eq!(req.options.secrets["s"].0, b"host");
        let mut req = request();
        take_secrets(
            &secret(BuildSecretKind::ContextFile, "s"),
            &mut req,
            Some(dir.path()),
        )
        .unwrap();
        assert_eq!(req.options.secrets["s"].0, b"context");
    }

    /// The frames of a section: its name, its content, the empty frame.
    fn section(name: &str, data: &[u8]) -> Vec<u8> {
        let frame = |data: &[u8]| {
            let mut f = (data.len() as u32).to_be_bytes().to_vec();
            f.extend_from_slice(data);
            f
        };
        let mut out = frame(name.as_bytes());
        if !data.is_empty() {
            out.extend(frame(data));
        }
        out.extend(frame(b""));
        out
    }

    /// Spool `upload` (its writer stays open when `open`) into `dir`.
    async fn spool(
        dir: &Path,
        upload: Vec<u8>,
        open: bool,
        take: &mut impl FnMut(&[u8]) -> ApiResult<()>,
    ) -> ApiResult<Vec<(String, PathBuf)>> {
        let (read, write) = rustix::pipe::pipe().unwrap();
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            let mut w = std::fs::File::from(write);
            let _ = w.write_all(&upload);
            open.then_some(w)
        });
        let mut source = PipeSource(Some(
            tokio::net::unix::pipe::Receiver::from_owned_fd(read).unwrap(),
        ));
        let spooled = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            spool_sections(&mut source, dir, take),
        )
        .await
        .expect("the sections are read without waiting for more");
        drop(source);
        drop(writer.join().unwrap());
        spooled
    }

    /// The sections of an upload are files of the build's directory; the
    /// named context one over the most is refused before its content, the
    /// frontend's reason is the error, the count of the bytes stops it.
    #[tokio::test]
    async fn the_sections_of_an_upload_are_files_of_the_build() {
        let dir = tempfile::tempdir().unwrap();
        let mut taken = 0;
        let mut count = |c: &[u8]| {
            taken += c.len();
            Ok(())
        };
        let upload = [
            section("context:../a", b"A"),
            section("main", b"MAIN"),
            section("context:b", b"BB"),
            0u32.to_be_bytes().to_vec(),
        ]
        .concat();
        let named = spool(dir.path(), upload, false, &mut count).await.unwrap();
        assert_eq!(taken, 7);
        assert_eq!(
            std::fs::read(dir.path().join("context.tar")).unwrap(),
            b"MAIN"
        );
        assert_eq!(named.len(), 2);
        assert_eq!(named[0].0, "../a");
        assert_eq!(named[0].1, dir.path().join("section-0.tar"));
        assert_eq!(std::fs::read(&named[1].1).unwrap(), b"BB");

        let refused = |upload: Vec<u8>, open: bool| {
            let dir = dir.path().to_path_buf();
            async move {
                spool(&dir, upload, open, &mut |_: &[u8]| Ok(()))
                    .await
                    .unwrap_err()
            }
        };
        // (the 65th named context: refused at its name, its content never
        // comes and the writer is still open)
        let mut many: Vec<u8> = (0..MAX_SECTIONS)
            .flat_map(|n| section(&format!("context:c{n}"), b"x"))
            .collect();
        let name = format!("context:c{MAX_SECTIONS}");
        many.extend((name.len() as u32).to_be_bytes());
        many.extend(name.as_bytes());
        let e = refused(many, true).await;
        assert!(e.to_string().contains("too many parts"), "{e}");
        let mut abort = section("main", b"M")[..8].to_vec();
        abort.extend(velarx_proto::build::FRAME_ABORT.to_be_bytes());
        abort.extend(3u32.to_be_bytes());
        abort.extend(b"why");
        let e = refused(abort, false).await;
        assert_eq!(e.status.as_u16(), 400);
        assert!(e.to_string().contains("why"), "{e}");
        let e = refused(
            [section("x", b""), 0u32.to_be_bytes().to_vec()].concat(),
            false,
        )
        .await;
        assert!(e.to_string().contains("an unknown part"), "{e}");
        let e = refused(
            [section("context:a", b""), 0u32.to_be_bytes().to_vec()].concat(),
            false,
        )
        .await;
        assert!(e.to_string().contains("no MainContext"), "{e}");
        let e = refused(section("main", b"M"), false).await;
        assert!(e.to_string().contains("ended early"), "{e}");
        let e = spool(
            dir.path(),
            section("main", b"too large"),
            false,
            &mut |_: &[u8]| Err(ApiError::new(413, "the build context is too large")),
        )
        .await
        .unwrap_err();
        assert_eq!(e.status.as_u16(), 413);
    }
}
