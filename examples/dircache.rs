// SPDX-License-Identifier: Apache-2.0
//! A directory cache: a content source that serves the files of a directory,
//! named by the digest of their content, to velarx's pull engine.
//!
//! ```sh
//! mkdir -p cache && cp layer.tar.gz cache/$(sha256sum layer.tar.gz | cut -d' ' -f1)
//! ```
//!
//! It keeps nothing between pulls, so the engine can start it for each use:
//! the connection to it is its descriptor 3, and it leaves at its end.  In
//! `config.toml`:
//!
//! ```toml
//! [[sources.external]]
//! name = "dircache"
//! command = ["/usr/local/bin/dircache", "/var/cache/layers"]
//!
//! [pull]
//! sources = ["dircache", "registry"]
//! ```
//!
//! Or as a service that runs: a socket unit (`ListenStream=`, `Accept=no`)
//! starts it with the listening socket as descriptor 3, and the entry names
//! that socket:
//!
//! ```toml
//! [[sources.external]]
//! name = "dircache"
//! socket = "/run/user/1000/velarx/services/dircache.sock"
//! ```
//!
//! A file of a layer is staged from the file of its content, or from the
//! files of its chunks (the uncompressed pieces of zstd:chunked layers),
//! each named by the hex of its sha256, with or without the `sha256:`
//! prefix.  The engine checks everything this stages; the interface
//! (`org.velarx.Fetcher`) is `interfaces/org.velarx.Fetcher.varlink`.

use std::path::PathBuf;
use velarx_content::dir_fetch::DirFetch;

fn main() -> std::io::Result<()> {
    // (first thing: it notes the descriptors it was passed)
    let startup = velarx_sys::fd::Startup::take().expect("the first call");
    let mut args = std::env::args_os().skip(1);
    let (Some(dir), None) = (args.next().map(PathBuf::from), args.next()) else {
        eprintln!("usage: dircache <directory>");
        std::process::exit(2);
    };
    if !dir.is_dir() {
        eprintln!("{} is not a directory", dir.display());
        std::process::exit(2);
    }
    let api = DirFetch::new("dircache", dir);
    let limits = velarx_content::activation::Limits::default();
    velarx_content::serve_fetch::run_descriptor_3(&startup, api, limits)
}
