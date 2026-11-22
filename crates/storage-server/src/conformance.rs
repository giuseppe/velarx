// SPDX-License-Identifier: Apache-2.0
//! The subject of the conformance suite (`velarx_graph::conformance`) that is a
//! driver talking to this server over a unix socket: the cases of the tests of
//! this package, and those of the engine's wrappers of the driver (the lazy
//! phase of `velarx-core`), which differ only in what wraps the client.

use crate::{Config, Running, Server};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use velarx_db::Database;
use velarx_graph::conformance::{Factory, Subject};
use velarx_graph::{StorageDriver, StoreId};
use velarx_storage::FileStore;
use velarx_storage_client::{Link, Options, VarlinkDriver};

/// What makes the driver of a subject from the client of the server, the
/// database and the objects of the subject, and its staging area.
pub type Wrap = fn(Arc<VarlinkDriver>, &Database, &Arc<FileStore>, &Path) -> Arc<dyn StorageDriver>;

/// The client as it is.
pub fn plain(
    driver: Arc<VarlinkDriver>,
    _: &Database,
    _: &Arc<FileStore>,
    _: &Path,
) -> Arc<dyn StorageDriver> {
    driver
}

/// A server of a subject of its own, in the scratch directory of the case:
/// dropped with the subject, before the directory goes.  (Its runtime is not
/// dropped on the thread of an async case, which refuses: a thread of its
/// own does.)
struct Served {
    socket: PathBuf,
    root: PathBuf,
    running: Option<Running>,
    server: Option<Arc<Server>>,
}

impl Served {
    fn start(dir: &Path) -> Self {
        let root = dir.join("server");
        let socket = dir.join("storage.sock");
        let server = Server::new(Config {
            root: root.clone(),
            timeout: Duration::from_secs(30),
            decision: Duration::from_secs(120),
        })
        .unwrap();
        let running = server.listen(&socket).unwrap();
        Self {
            socket,
            root,
            running: Some(running),
            server: Some(server),
        }
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        let (running, server) = (self.running.take(), self.server.take());
        let _ = std::thread::spawn(move || drop((running, server))).join();
    }
}

/// The factory of subjects whose driver is `wrap` of a client of a server of
/// their own; `chunked_only`: the layers come as zstd:chunked blobs of a
/// registry, else as archives read whole.
pub fn factory(chunked_only: bool, wrap: Wrap) -> Factory {
    Box::new(move |dir| {
        Box::pin(async move {
            let shared = Served::start(&dir);
            let graph = dir.join("graph");
            std::fs::create_dir_all(&graph).unwrap();
            let store = Arc::new(FileStore::new(dir.join("objects")).unwrap());
            let staging = dir.join("staging");
            let client = {
                let graph = graph.clone();
                let socket = shared.socket.clone();
                tokio::task::spawn_blocking(move || {
                    VarlinkDriver::open(Options {
                        link: Link {
                            socket,
                            timeout: Duration::from_secs(30),
                        },
                        graph_root: graph,
                    })
                })
                .await
                .unwrap()
                .expect("open")
            };
            // (the files of the layers are the server's: the database reads
            // them from it)
            let client = Arc::new(client);
            let db = Database::open(dir.join("db"))
                .await
                .unwrap()
                .with_layer_files(client.clone());
            let id = StoreId::of_root(&graph).unwrap();
            let uid = rustix::process::geteuid().as_raw();
            // (where the server makes the roots: beneath the work directory
            // of the store, which the client made)
            let work = std::fs::canonicalize(graph.join("varlink").join("work")).unwrap();
            let tocs = shared
                .root
                .join(uid.to_string())
                .join(id.as_str())
                .join("vfs")
                .join("tocs");
            let driver = wrap(client, &db, &store, &staging);
            Subject {
                driver,
                kernel: None,
                db,
                store,
                staging,
                dir,
                overlay_upper: false,
                damage: Box::new(move |key| {
                    std::fs::remove_file(tocs.join(format!("{}.toc", key.file_stem()))).is_ok()
                }),
                proc_root: Box::new(|dir, _| {
                    let _ = std::fs::remove_file(dir.join("root"));
                }),
                image_state: Box::new(|_| false),
                chunked_only,
                remote: true,
                upper: Some(Box::new({
                    let work = work.clone();
                    move |w| work.join(w.id()).join("vfs").join("root")
                })),
                bundle: Some(Box::new(move |w| work.join(w.id()))),
                keep: Some(Box::new(shared)),
            }
        })
    })
}
