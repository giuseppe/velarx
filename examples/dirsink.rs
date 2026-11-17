// SPDX-License-Identifier: Apache-2.0
//! A recording helper sink: a pusher that places nothing and writes down, in a
//! directory, what the destination was told: for each manifest the
//! destination's own pusher committed, a file with its digest, its names
//! and the destination.  It is what a referrers, signature or announce sink
//! starts from.
//!
//! ```sh
//! mkdir -p records
//! cargo run --example dirsink -- "$XDG_RUNTIME_DIR/velarx/services/dirsink.sock" records
//! ```
//!
//! and in `config.toml`:
//!
//! ```toml
//! [[sinks.external]]
//! name = "dirsink"
//! socket = "/run/user/1000/velarx/services/dirsink.sock"
//!
//! [push]
//! sinks = ["dirsink"]
//! ```
//!
//! The engine asks it (`Probe`, then `Put`) for each object the destination
//! lacks, before the destination's own pusher; it answers `unavailable` for
//! all of them (the objects are not its to place), so the engine asks the
//! next pusher, whatever the destination is.  When the destination's own
//! pusher has put the manifest, the engine tells it (`Commit`): it is no
//! origin and puts nothing, it records.  The interface (`org.velarx.Pusher`)
//! is `interfaces/org.velarx.Pusher.varlink`.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use velarx_content::pusher::push::PusherError;
use velarx_content::serve_fetch::{self, Described, FetchEndpoint, StagingFetcher};
use velarx_content::serve_push::{CommittedCall, PushScope, Pushing};

/// The helper: the defaults of a pusher answer `unavailable` to everything,
/// and the record of a commit is what it adds.
#[derive(Clone)]
struct Recorder {
    dir: Arc<PathBuf>,
}

#[async_trait]
impl Pushing for Recorder {
    fn described(&self) -> Described {
        Described {
            name: "dirsink".into(),
            capabilities: Vec::new(),
            max_objects: 8,
        }
    }

    async fn committed(&self, scope: &PushScope, call: CommittedCall) -> Result<(), PusherError> {
        // (the digest is checked by the endpoint: `alg:hex`)
        let file = self
            .dir
            .join(format!("{}.json", call.manifest.digest.replace(':', "-")));
        let record = serde_json::json!({
            "digest": call.manifest.digest,
            "size": call.manifest.size,
            "names": call.names,
            "destination": scope.destination,
        });
        std::fs::write(&file, record.to_string())
            .map_err(|e| PusherError::failed(format!("{}: {e}", file.display())))?;
        Ok(())
    }
}

impl StagingFetcher for Recorder {
    fn described(&self) -> Described {
        Pushing::described(self)
    }

    fn pusher(&self) -> Option<Arc<dyn Pushing>> {
        Some(Arc::new(self.clone()))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    velarx_wire::sdnotify::take_manager_env();
    let mut args = std::env::args_os().skip(1);
    let (Some(socket), Some(dir)) = (args.next(), args.next()) else {
        eprintln!("usage: dirsink <socket> <directory>");
        std::process::exit(2);
    };
    let (socket, dir) = (PathBuf::from(socket), PathBuf::from(dir));
    if !Path::new(&dir).is_dir() {
        eprintln!("{} is not a directory", dir.display());
        std::process::exit(2);
    }
    let sink = Recorder { dir: Arc::new(dir) };
    // The socket is created with mode 0600 in a directory of mode 0700, and
    // only this user (and root) can talk to it.
    let listener = velarx_base::ipc::bind_private(&socket)?;
    listener.set_nonblocking(true)?;
    velarx_wire::sdnotify::notify("READY=1");
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let endpoint = FetchEndpoint::new(Arc::new(sink));
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            tokio::select! {
                _ = serve_fetch::serve(listener, endpoint, None, velarx_base::ipc::trusted_uid, velarx_content::activation::Limits::default()) => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        })
        .await;
    let _ = std::fs::remove_file(&socket);
    Ok(())
}
