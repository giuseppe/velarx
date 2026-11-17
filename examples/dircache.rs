// SPDX-License-Identifier: Apache-2.0
//! A directory cache: a content source that serves the files of a directory,
//! named by the digest of their content, to velarx's pull engine.
//!
//! ```sh
//! mkdir -p cache && cp layer.tar.gz cache/$(sha256sum layer.tar.gz | cut -d' ' -f1)
//! cargo run --example dircache -- "$XDG_RUNTIME_DIR/velarx/services/dircache.sock" cache
//! ```
//!
//! and in `config.toml`:
//!
//! ```toml
//! [[sources.external]]
//! name = "dircache"
//! socket = "/run/user/1000/velarx/services/dircache.sock"
//!
//! [pull]
//! sources = ["dircache", "registry"]
//! ```
//!
//! A file of a layer is staged from the file of its content, or from the
//! files of its chunks (the uncompressed pieces of zstd:chunked layers),
//! each named by the hex of its sha256, with or without the `sha256:`
//! prefix.  The engine checks everything this stages; the interface
//! (`org.velarx.Fetcher`) is `interfaces/org.velarx.Fetcher.varlink`.

use std::path::{Path, PathBuf};
use velarx_content::dir_fetch::DirFetch;
use velarx_content::serve_fetch::{self, FetchEndpoint};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    velarx_wire::sdnotify::take_manager_env();
    let mut args = std::env::args_os().skip(1);
    let (Some(socket), Some(dir)) = (args.next(), args.next()) else {
        eprintln!("usage: dircache <socket> <directory>");
        std::process::exit(2);
    };
    let (socket, dir) = (PathBuf::from(socket), PathBuf::from(dir));
    if !Path::new(&dir).is_dir() {
        eprintln!("{} is not a directory", dir.display());
        std::process::exit(2);
    }
    // The socket is created with mode 0600 in a directory of mode 0700, and
    // only this user (and root) can talk to it.
    let listener = velarx_base::ipc::bind_private(&socket)?;
    listener.set_nonblocking(true)?;
    // (a service manager, or a test, learns that it serves)
    velarx_wire::sdnotify::notify("READY=1");
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let endpoint = FetchEndpoint::new(DirFetch::new("dircache", dir));
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
