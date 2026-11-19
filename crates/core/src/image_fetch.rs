// SPDX-License-Identifier: Apache-2.0
//! The engine's end of `org.velarx.ImageFetch`
//! (`velarx_content::imagefetch`): what the image servers of the containers
//! of lazily pulled images ask the engine service of the store for.
//!
//! The engine service of the store binds ONE socket for every pull of the
//! store, for as long as it runs; a call names its image and carries the
//! token of its pull (`staging/pulls/<id>/token`).  A miss goes through the
//! funnel of the engine (`ImageService::stage_lazy`): the misses of every
//! image server and the completion of the pull for the same file wait for
//! one fetch, which the engine's list of fetchers makes, on demand, into
//! the staging directory of the layer.  A call runs on the runtime of the
//! engine, never on the thread that reads the connections, so that no call
//! waits for another's fetch or commit.

use crate::services::ImageService;
use std::collections::HashSet;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use velarx_content::activation;
use velarx_content::imagefetch::{Ack, ImageFetchError, ProfileReply, PROTO};
use velarx_db::LayerKey;
use velarx_proto::info::Info;
use velarx_proto::transfer::{Failure, FailureClass};

/// What the image servers of the pulls of a store reach.  Each connection
/// has an endpoint of its own (a clone has no image yet): `Open` gives it
/// the image of its pull.
pub struct ProxyEndpoint {
    inner: Arc<Inner>,
    opened: Arc<Mutex<Option<Opened>>>,
}

impl Clone for ProxyEndpoint {
    /// The endpoint of another connection: it has no image until it is
    /// opened.
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            opened: Arc::default(),
        }
    }
}

struct Inner {
    service: ImageService,
    runtime: tokio::runtime::Handle,
}

/// What `Open` gave a connection: its image and the layers of its pull.
struct Opened {
    image: String,
    layers: HashSet<String>,
}

/// Equal, in a time that does not depend on where they differ.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// What an error of the engine's fetch is, as the error of the call: the
/// class and the party that failed.
fn failed(e: &velarx_types::ImageError) -> ImageFetchError {
    match e {
        velarx_types::ImageError::Transfer { party, failure, .. } => ImageFetchError::Failed {
            failure: failure.clone(),
            party: Some(party.clone()),
        },
        e => ImageFetchError::Failed {
            failure: Failure {
                class: if matches!(e, velarx_types::ImageError::RegistryNotFound(_)) {
                    FailureClass::NotFound
                } else {
                    FailureClass::Failed
                },
                reason: e.to_string(),
            },
            party: None,
        },
    }
}

impl ProxyEndpoint {
    /// The endpoint of the pulls of `service`; the calls run on `runtime`.
    pub fn new(service: ImageService, runtime: tokio::runtime::Handle) -> Self {
        Self {
            inner: Arc::new(Inner { service, runtime }),
            opened: Arc::default(),
        }
    }

    /// The keys of the layers of the pull of `image`, when `token` is its
    /// token.
    fn check(&self, image: &str, token: &str) -> Result<HashSet<String>, ImageFetchError> {
        let refused = || ImageFetchError::Refused {
            reason: format!("not the token of a pull of {image}"),
        };
        // (an id names a directory: nothing else is looked up)
        if !matches!(image.len(), 64 | 128)
            || !image
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ImageFetchError::InvalidArgument {
                reason: format!("{image:?} is not the id of an image"),
            });
        }
        let area = self.inner.service.staging_area();
        let theirs = area.token(image).map_err(|_| refused())?;
        if !same(token, &theirs) {
            return Err(refused());
        }
        let pull = area.pull(image).ok().flatten().ok_or_else(refused)?;
        Ok(pull.layers.into_iter().collect())
    }

    /// The image and the layers of the pull this connection was opened for.
    fn opened(&self) -> Result<(String, HashSet<String>), ImageFetchError> {
        self.opened
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|o| (o.image.clone(), o.layers.clone()))
            .ok_or_else(|| ImageFetchError::NotScoped {
                reason: "a call before Open".into(),
            })
    }

    /// The fetch of `digest` of `layer`, on demand, through the funnel of
    /// the engine (joined when one is in flight).
    async fn fetch(&self, digest: &str, layer: LayerKey) -> Result<(), velarx_types::ImageError> {
        let (service, file) = (self.inner.service.clone(), digest.to_string());
        self.inner
            .runtime
            .spawn(async move {
                // (and the files that follow it, in the background)
                service.fetch_lazy_file(&file, &layer).await.map(|_| ())
            })
            .await
            .unwrap_or_else(|e| {
                Err(velarx_types::ImageError::Io(std::io::Error::other(
                    format!("the fetch ended: {e}"),
                )))
            })
    }
}

mod service {
    #![allow(missing_docs)]
    use super::*;

    #[zlink::service(
        interface = "org.velarx.ImageFetch",
        vendor = "org.velarx",
        product = "velarx",
        version = env!("CARGO_PKG_VERSION"),
        url = env!("CARGO_PKG_REPOSITORY"),
        types = [FailureClass, Failure]
    )]
    impl ProxyEndpoint {
        /// Who serves the interface and what it can do.
        pub async fn get_info(&self) -> Info {
            Info {
                name: "engine".into(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                proto: PROTO,
                capabilities: Vec::new(),
                limits: Default::default(),
            }
        }

        /// Give the connection its image: `image` (its id) and `token`, the
        /// token of its pull the image server was handed at its start.
        /// Once, before any other call but GetInfo; `Refused` for a wrong
        /// token.
        pub async fn open(&self, image: String, token: String) -> Result<Ack, ImageFetchError> {
            let layers = self.check(&image, &token)?;
            let mut opened = self.opened.lock().unwrap_or_else(|e| e.into_inner());
            if opened.is_some() {
                return Err(ImageFetchError::NotScoped {
                    reason: "Open twice".into(),
                });
            }
            *opened = Some(Opened { image, layers });
            Ok(Ack {})
        }

        /// The file `digest` (its fs-verity digest) of the layer `layer`
        /// (the key of the layer as the pull names it) is in neither the
        /// store nor the staging of the pull: bring it.  The reply comes
        /// when it has its name; `Failed` when it cannot (the reader gets
        /// EIO).
        pub async fn miss(&self, layer: String, digest: String) -> Result<Ack, ImageFetchError> {
            let (image, layers) = self.opened()?;
            if !layers.contains(&layer) {
                return Err(ImageFetchError::Refused {
                    reason: format!("{layer} is not a layer of the pull"),
                });
            }
            let key = LayerKey::parse(&layer).ok_or_else(|| ImageFetchError::InvalidArgument {
                reason: format!("{layer:?} is not the key of a layer"),
            })?;
            if velarx_types::digest::Digest::parse_fsverity(&digest).is_err() {
                return Err(ImageFetchError::InvalidArgument {
                    reason: format!("{digest:?} is not the fs-verity digest of a file"),
                });
            }
            // (a file of the table of contents of the layer, not any digest)
            match self
                .inner
                .service
                .is_file_of_lazy_layer(&key, &digest)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Err(ImageFetchError::InvalidArgument {
                        reason: format!("{digest} is not a file of the layer {layer}"),
                    })
                }
                Err(e) => return Err(failed(&e)),
            }
            match self.fetch(&digest, key).await {
                Ok(()) => Ok(Ack {}),
                Err(e) => {
                    tracing::info!("pull {image}: {digest} of {layer}: {e}");
                    Err(failed(&e))
                }
            }
        }

        /// The startup profile of the image: digests of files, one a line,
        /// at most `max` bytes, in `file`, a sealed memory file in the
        /// reply.
        #[zlink(return_fds)]
        pub async fn get_profile(
            &self,
            max: u64,
        ) -> (Result<ProfileReply, ImageFetchError>, Vec<OwnedFd>) {
            let image = match self.opened() {
                Ok((image, _)) => image,
                Err(e) => return (Err(e), Vec::new()),
            };
            let (service, max) = (
                self.inner.service.clone(),
                max.min(velarx_content::fetcher::fetch::PROFILE_MAX_BYTES),
            );
            let files = self
                .inner
                .runtime
                .spawn(async move { service.peer_profile(&image, 65536).await })
                .await
                .unwrap_or_default();
            let mut text = String::new();
            for file in files {
                if (text.len() + file.len() + 1) as u64 > max {
                    break;
                }
                text.push_str(&file);
                text.push('\n');
            }
            match velarx_base::sealed::sealed_memory(text.as_bytes()) {
                Ok(fd) => (Ok(ProfileReply { file: 0 }), vec![fd]),
                Err(e) => (
                    Err(ImageFetchError::Failed {
                        failure: Failure {
                            class: FailureClass::Failed,
                            reason: format!("a memory file for the profile: {e}"),
                        },
                        party: None,
                    }),
                    Vec::new(),
                ),
            }
        }
    }

    /// The interface as the macro described it.
    #[cfg(test)]
    pub(super) fn description() -> String {
        format!("{}", __ProxyEndpoint_INTERFACE_0)
    }
}

/// The text of the interface definition
/// (`interfaces/org.velarx.ImageFetch.varlink`), made from the types and
/// the methods above, with the rules in its header.
#[cfg(test)]
pub fn definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # What the image server of a container of a lazily pulled image asks the\n\
         # engine that holds the pull for.  Generated from the Rust types\n\
         # (crates/content/src/imagefetch.rs and crates/core/src/image_fetch.rs) by the\n\
         # test `image_fetch::tests::the_interface_file_is_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-core --lib image_fetch writes it.\n\
         #\n\
         # ONE CONNECTION.  The image server knows no fetcher.  It gives the connection\n\
         # its image with Open (the id and the token of its pull), once.  For a file\n\
         # that is in neither the store nor the staging of the pull it asks Miss, and holds the\n\
         # lookup of the file until the reply.  The engine brings the file through\n\
         # its own list of fetchers; the reply means it has its name.  The image server\n\
         # then opens it and takes the kernel's fs-verity measure: nothing the engine\n\
         # says is believed beyond that measure.\n\
         #\n\
         # THE SOCKET.  <services>/image-fetch/engine, ONE for the store, bound by the\n\
         # engine service of the store (velarx varlink) while it runs, and bound again\n\
         # by the next one.  Client and server run as the same user.  The token of the\n\
         # pull is handed to the image server at its start.  A profile is a sealed\n\
         # memory file of digests, one a line, which carries no length.  A descriptor\n\
         # is a field of type `int` whose value is its position among the\n\
         # descriptors of its message.\n\
         #\n\
         # WHEN NO ENGINE ANSWERS.  A miss is EIO for the container until the next\n\
         # command starts the engine service; the files that are there are served as\n\
         # before.\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        service::description()
    )
}

/// The proxy of the store, served while this is held: the socket goes with
/// it (unless another engine bound it since).
pub struct Proxy {
    socket: PathBuf,
    bound: Option<(u64, u64)>,
    _stop: tokio::sync::oneshot::Sender<()>,
    /// The engine service that the connections of the image servers keep
    /// (given when it serves)
    service: Option<tokio::sync::oneshot::Sender<Arc<activation::Activity>>>,
}

/// What the proxy serves at once: an image server keeps one connection
/// idle, and one more for each miss it waits for, so a store with many
/// lazy containers needs more than the frontends of the engine do.
const LIMITS: activation::Limits = activation::Limits {
    connections: 1024,
    per_client: 64,
    first_call: std::time::Duration::from_secs(10),
};

impl Drop for Proxy {
    fn drop(&mut self) {
        activation::remove_own_socket(&self.socket, self.bound);
    }
}

impl Proxy {
    /// The connections of the image servers keep `service` from leaving:
    /// the containers of lazy pulls need the proxy while they run, whatever
    /// the engine does.
    pub fn keep(&mut self, service: Arc<activation::Activity>) {
        if let Some(tx) = self.service.take() {
            let _ = tx.send(service);
        }
    }

    /// Bind the socket of the store under `services` and serve it on a
    /// thread of its own (the servers of zlink are not `Send`); the calls
    /// run on the runtime of the endpoint.  An error when another engine
    /// serves it.
    pub fn start(services: &Path, endpoint: ProxyEndpoint) -> std::io::Result<Self> {
        let socket = velarx_content::imagefetch::socket(services);
        if let Some(dir) = socket.parent() {
            velarx_base::ipc::create_private_dirs(dir)?;
        }
        // (under the lock of the socket: a socket nobody listens on is
        // bound again; the path may be longer than a socket address holds)
        let listener = {
            let _lock = activation::take_lock(&socket)?;
            match velarx_content::imagefetch::connect(&socket) {
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        format!("another engine serves {}", socket.display()),
                    ))
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    velarx_base::ipc::bind_private_long(&socket)?
                }
                Err(e) => return Err(e),
            }
        };
        let bound = activation::socket_file_id(&socket);
        listener.set_nonblocking(true)?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (service, keeps) = tokio::sync::oneshot::channel::<Arc<activation::Activity>>();
        std::thread::Builder::new()
            .name("image-fetch".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("image-fetch: {e}");
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    let listener = match tokio::net::UnixListener::from_std(listener) {
                        Ok(l) => l,
                        Err(e) => {
                            tracing::warn!("image-fetch: {e}");
                            return;
                        }
                    };
                    let activity = activation::Activity::new(LIMITS);
                    let kept = async {
                        match keeps.await {
                            Ok(service) => activity.clone().keep_while_served(service).await,
                            Err(_) => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        () = activation::serve_varlink_on(
                            listener,
                            None,
                            velarx_base::ipc::trusted_uid,
                            activity.clone(),
                            "image-fetch",
                            endpoint,
                        ) => {}
                        () = kept => {}
                        _ = stopped => {}
                    }
                });
            })?;
        Ok(Self {
            socket,
            bound,
            _stop: stop,
            service: Some(service),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interface_file_is_current() {
        let text = definition();
        velarx_base::testing::assert_interface_file("org.velarx.ImageFetch.varlink", &text);
        for method in ["GetInfo", "Open", "Miss", "GetProfile"] {
            assert!(text.contains(&format!("method {method}(")), "{method}");
        }
        assert!(!text.contains("[`"), "a rustdoc link in the definition");
    }

    #[tokio::test]
    async fn a_call_needs_the_token_of_the_pull_of_its_image() {
        use velarx_types::digest::{Algorithm, Digest};
        let dir = tempfile::tempdir().unwrap();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let store = Arc::new(velarx_storage::FileStore::new(dir.path().join("objects")).unwrap());
        let service = ImageService::new(
            db,
            store,
            dir.path().join("staging"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap();
        let endpoint = ProxyEndpoint::new(service.clone(), tokio::runtime::Handle::current());
        let digest = |t: &str| Digest::of(Algorithm::Sha256, t.as_bytes());
        let id = digest("manifest").hex().to_string();
        let pull = velarx_content::pull::staged::StagedPull {
            id: id.clone(),
            manifest_digest: digest("manifest"),
            config_digest: digest("config"),
            manifest: "{}".into(),
            config: "{}".into(),
            layers: vec![format!("toc:{}", digest("toc"))],
            tags: Vec::new(),
            digest_names: Vec::new(),
            shareable: false,
            pulls: Vec::new(),
            registry_ref: None,
            started_at: "2026-01-01T00:00:00+00:00".into(),
        };
        let area = service.staging_area();
        area.publish_pull(&pull).unwrap();
        let token = area.token(&id).unwrap();
        assert_eq!(endpoint.check(&id, &token).unwrap().len(), 1);
        assert!(matches!(
            endpoint.check(&id, &"0".repeat(32)),
            Err(ImageFetchError::Refused { .. })
        ));
        // (another image, an id that is not one)
        assert!(matches!(
            endpoint.check(&"c".repeat(64), &token),
            Err(ImageFetchError::Refused { .. })
        ));
        assert!(matches!(
            endpoint.check("../x", &token),
            Err(ImageFetchError::InvalidArgument { .. })
        ));
    }

    #[test]
    fn tokens_are_compared_whole() {
        assert!(same("abcd", "abcd"));
        assert!(!same("abcd", "abce"));
        assert!(!same("abcd", "abc"));
        assert!(!same("", "a"));
    }
}
