// SPDX-License-Identifier: Apache-2.0
//! The engine service of the store, for the engine of a command: every
//! pull that outlives the command (a lazy pull, its completion, the cancel
//! of one) is the service's (`velarx_core::services::PullHandOff`).  The
//! service is found on the engine's socket or started there, under the lock
//! of the socket (one per store), as `velarx varlink` with the engine's idle
//! time (`[engine] idle_exit`): it stays while it completes a pull or
//! follows a container, and leaves when it has nothing to do.  The call is
//! made on the connection made under the lock, so that a service that
//! leaves meanwhile serves it all the same.
//!
//! The calls are typed (`org.velarx.Engine`): an error of the service comes
//! back as the error it is.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use velarx_config::Config;
use velarx_core::services::{PullHandOff, PullOptions, PullResult};
use velarx_proto::engine::{EngineError, EngineProxy, PlatformSpec, PullSpec};
use velarx_proto::transfer::{Failure, FailureClass};
use velarx_proto::workload::TransferStats;
use velarx_registry::auth::RegistryAccess;
use velarx_types::{ImageError, ImageResult};

/// The engine service of the store of `config`, found or started.
pub struct PullService {
    config: Arc<Config>,
    config_path: PathBuf,
}

impl PullService {
    pub fn new(config: Arc<Config>, config_path: &Path) -> Self {
        Self {
            config,
            // (the service runs in `/`)
            config_path: std::path::absolute(config_path)
                .unwrap_or_else(|_| config_path.to_path_buf()),
        }
    }

    /// A connection to the service, made under the lock of its socket:
    /// the one that runs, or one started now.
    fn connect(&self) -> std::io::Result<std::os::unix::net::UnixStream> {
        let socket = self.config.engine_socket();
        let mut cmd = std::process::Command::new(velarx_base::spawn::sibling("velarx"));
        // (what it does after the command ended is in its log)
        cmd.arg("--config")
            .arg(&self.config_path)
            .args([
                "--log-level",
                "info",
                "varlink",
                "--listen-fd",
                "3",
                "--time",
            ])
            .arg(self.config.engine.idle_exit.to_string())
            .current_dir("/");
        let log = log_file(&socket)?;
        let (stream, child) =
            velarx_content::activation::start(&socket, cmd, std::process::Stdio::from(log))?;
        if let Some(mut child) = child {
            tracing::info!(
                "Started the engine service of the store (pid {}) on {}: it owns the lazy pulls",
                child.id(),
                socket.display()
            );
            // (reaped while this process lives; after, by whoever reaps the
            // orphans)
            std::thread::Builder::new()
                .name("engine-reap".into())
                .spawn(move || {
                    let _ = child.wait();
                })?;
        }
        Ok(stream)
    }

    /// A checked connection to the service, for one call.
    async fn conn(&self) -> ImageResult<velarx_proto::connect::Conn> {
        let this = Self {
            config: self.config.clone(),
            config_path: self.config_path.clone(),
        };
        let stream = tokio::task::spawn_blocking(move || this.connect())
            .await
            .map_err(|e| ImageError::Storage(e.to_string()))?
            .map_err(|e| unreachable(&self.config, e.to_string()))?;
        stream.set_nonblocking(true)?;
        let stream = tokio::net::UnixStream::from_std(stream)?;
        let mut conn = velarx_content::activation::checked(stream)?;
        velarx_proto::connect::check(&mut conn)
            .await
            .map_err(|e| unreachable(&self.config, e.to_string()))?;
        Ok(conn)
    }
}

/// The error of a service that cannot be had.
fn unreachable(config: &Config, e: String) -> ImageError {
    ImageError::Storage(format!(
        "the engine service of the store ({}), which owns the lazy pulls: {e}",
        config.engine_socket().display()
    ))
}

/// The log of a service started here: next to its socket.
fn log_file(socket: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = socket.parent().unwrap_or_else(|| Path::new("."));
    velarx_base::ipc::ensure_private_dir(dir)?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(dir.join("service.log"))
}

/// The credentials of a call: [`RegistryAccess::sealed`].
fn sealed_access(access: &RegistryAccess) -> ImageResult<(Option<u32>, Vec<OwnedFd>)> {
    access
        .sealed()
        .map_err(|e| ImageError::Pulling(format!("the credentials: {e}")))
}

/// What the service said, as the image service's error.
fn image_error(e: EngineError) -> ImageError {
    let message = e.message().to_string();
    match e {
        EngineError::ImageNotLazy { image, layers, .. } => ImageError::NotLazy {
            image,
            layers: layers
                .into_iter()
                .map(|l| velarx_types::NotLazyLayer {
                    index: l.index,
                    digest: l.digest,
                    media_type: l.media_type,
                    reason: l.reason,
                })
                .collect(),
        },
        EngineError::Contradicted { cause, .. } => ImageError::Contradicted(cause),
        EngineError::NoSuchImage { .. } => ImageError::NotFound(message),
        EngineError::Unauthorized { .. } => ImageError::Unauthorized(message),
        EngineError::PermissionDenied { .. } => ImageError::Forbidden(message),
        EngineError::InvalidArgument { .. }
        | EngineError::InvalidReference { .. }
        | EngineError::InvalidName { .. } => ImageError::Invalid(message),
        EngineError::InvalidContent { party, object, .. } => ImageError::Transfer {
            party,
            object: Some(object).filter(|o| !o.is_empty()),
            failure: Failure {
                class: FailureClass::Invalid,
                reason: message,
            },
        },
        EngineError::SourceUnavailable {
            party, transient, ..
        } => ImageError::transfer(
            party,
            if transient {
                FailureClass::Transient
            } else {
                FailureClass::Unavailable
            },
            message,
        ),
        EngineError::Unreachable { .. } => ImageError::Unreachable(message),
        EngineError::NoSpace { .. } => ImageError::Io(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            message,
        )),
        _ => ImageError::Pulling(message),
    }
}

fn call_error(e: zlink::Error) -> ImageError {
    ImageError::Storage(format!(
        "the engine service of the store, which owns the lazy pulls: {e}"
    ))
}

fn stats_of(s: Option<TransferStats>) -> velarx_core::services::TransferStats {
    let s = s.unwrap_or_default();
    velarx_core::services::TransferStats {
        by_source: s.by_source,
        layers_cached: s.layers_cached,
        duration_ms: s.duration_ms,
        ..Default::default()
    }
}

#[async_trait::async_trait]
impl PullHandOff for PullService {
    async fn pull_lazy(&self, reference: &str, options: &PullOptions) -> ImageResult<PullResult> {
        let mut conn = self.conn().await?;
        let spec = PullSpec {
            source: reference.to_string(),
            platform: PlatformSpec {
                platform: options.platform.clone(),
                ..Default::default()
            },
            tls_verify: options.tls_verify,
            lazy: true,
            sources: options.sources.clone(),
            inline_threshold: options.inline_threshold,
            ..Default::default()
        };
        let (access, fds) = sealed_access(&options.access)?;
        let pulled = conn
            .image_pull(spec, access, fds)
            .await
            .map_err(call_error)?
            .map_err(image_error)?;
        let id = pulled.id.ok_or_else(|| {
            ImageError::Pulling(format!(
                "the engine service pulled no image for {reference}"
            ))
        })?;
        Ok(PullResult {
            id,
            stats: stats_of(pulled.stats),
        })
    }

    async fn complete(
        &self,
        id: &str,
        access: &RegistryAccess,
    ) -> ImageResult<velarx_core::services::TransferStats> {
        let mut conn = self.conn().await?;
        let (access, fds) = sealed_access(access)?;
        let done = conn
            .image_complete(id, access, fds)
            .await
            .map_err(call_error)?
            .map_err(image_error)?;
        Ok(stats_of(Some(done.stats)))
    }

    async fn cancel(&self, id: &str, force: bool) -> ImageResult<()> {
        let mut conn = self.conn().await?;
        conn.image_remove(id, force, false, false, false, false)
            .await
            .map_err(call_error)?
            .map_err(image_error)?;
        Ok(())
    }

    fn ensure(&self) -> ImageResult<()> {
        self.connect()
            .map(drop)
            .map_err(|e| unreachable(&self.config, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::podman::error::ApiError;
    use crate::engine_service::api_error;

    /// A refused layer goes over the interface as its own condition and
    /// comes back as the same class, with the reason it was refused for.
    #[test]
    fn a_refused_layer_keeps_its_class_over_the_interface() {
        let sent = api_error(
            ApiError::from(ImageError::Contradicted("tar-split differs".into())),
            crate::api::podman::error::Kind::Image,
        );
        assert!(matches!(sent, EngineError::Contradicted { .. }), "{sent:?}");
        // (a client of the interface reads what the command would say)
        assert_eq!(
            sent.parts(),
            (
                "tar-split differs",
                "the layer is refused: tar-split differs"
            )
        );
        let back = image_error(sent);
        assert!(matches!(back, ImageError::Contradicted(_)), "{back:?}");
        assert_eq!(back.to_string(), "the layer is refused: tar-split differs");
        assert!(matches!(
            image_error(EngineError::Failed {
                cause: String::new(),
                message: "x".into()
            }),
            ImageError::Pulling(_)
        ));
    }
}
