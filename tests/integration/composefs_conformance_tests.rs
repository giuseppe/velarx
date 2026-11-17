// SPDX-License-Identifier: Apache-2.0
//! The conformance suite (`velarx_graph::conformance`) for the composefs
//! driver.  Its mounts are made by the kernel (as root) or by the image
//! server, the monitor binary cargo built, so each case runs in a child of
//! the test binary in a user and mount namespace of its own, as the tests of
//! the image server do (`image_server_tests`); where the kernel gives the
//! user none the case says so and stops.

use crate::common::built_binary;
use crate::monitor_common::namespace;
use std::path::Path;
use std::sync::Arc;
use velarx_core::storage_driver::{ComposefsDriver, ComposefsOptions, ImageServer};
use velarx_db::Database;
use velarx_fuse::composefs as cfs;
use velarx_graph::conformance::{Factory, Subject};
use velarx_graph::{IdmapWay, Prefs};
use velarx_storage::{FileStore, VerityMode};

/// The tests of the cases of the suite: each in a namespace of its own.
macro_rules! in_namespace {
    ($factory:expr; $($case:ident,)*) => {
        $(
            #[test]
            fn $case() {
                velarx_base::testing::in_child(|| {
                    if !namespace() {
                        return;
                    }
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        let factory: Factory = $factory;
                        velarx_graph::conformance::$case(&factory).await;
                    });
                    std::mem::forget(rt);
                });
            }
        )*
    };
}

fn server(dir: &Path) -> ImageServer {
    ImageServer::new(
        built_binary("velarx-monitor")
            .expect("no velarx-monitor next to the tests: cargo build --bins"),
        dir.join("run"),
        Arc::new(velarx_config::Config::default()),
    )
}

fn factory() -> Factory {
    Box::new(|dir| {
        Box::pin(async move {
            let db = Database::open(dir.join("db")).await.unwrap();
            let store = Arc::new(FileStore::new(dir.join("objects")).unwrap());
            let staging = dir.join("staging");
            let make = |options: ComposefsOptions| {
                Arc::new(ComposefsDriver::new(
                    db.clone(),
                    store.clone(),
                    staging.clone(),
                    VerityMode::Off,
                    options,
                ))
            };
            let for_damage = store.clone();
            let for_state = store.clone();
            Subject {
                // the driver not configured: the image server makes every mount
                driver: make(ComposefsOptions::new(server(&dir))),
                // the driver as configured (`[storage] composefs = auto`):
                // the kernel mounts where this process may
                kernel: Some(make(ComposefsOptions::for_mode(
                    "auto",
                    server(&dir),
                    store.root(),
                ))),
                db,
                store,
                staging,
                dir,
                overlay_upper: true,
                damage: Box::new(move |key| {
                    std::fs::remove_file(cfs::layer_image_path(for_damage.root(), &key.file_stem()))
                        .is_ok()
                }),
                proc_root: Box::new(|dir, paths| {
                    let table = match paths {
                        Some(p) => format!(
                            "22 1 0:21 / /proc rw,nosuid - proc proc rw\n\
                             23 1 0:57 / / rw,relatime - overlay overlay \
                             rw,lowerdir+=/x/layers/1,upperdir={},workdir={},userxattr\n",
                            p.upper.display(),
                            p.work.as_ref().unwrap().display()
                        ),
                        None => "22 1 0:21 / /proc rw,nosuid - proc proc rw\n\
                                 23 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                            .to_string(),
                    };
                    std::fs::write(dir.join("mountinfo"), table).unwrap();
                }),
                // the startup profile the image server records for a
                // container of the image
                image_state: Box::new(move |id| {
                    let p = cfs::profile_path(for_state.root(), id);
                    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                    std::fs::write(p, b"[]").is_ok()
                }),
                chunked_only: false,
                remote: false,
                upper: None,
                bundle: None,
                keep: None,
            }
        })
    })
}

mod suite {
    use super::*;
    velarx_graph::conformance_suite_with!(in_namespace; factory());
}

/// The suite of the volume API on a driver that has volumes of its own (a
/// test-only wrapper): composefs does not, its mounts are made of the
/// layers.  The ids are mapped by the driver or by the monitor, and the root
/// is a descriptor too.
mod volumes_by_the_driver {
    use super::*;
    velarx_graph::volume_conformance_suite_with!(
        in_namespace;
        velarx_graph::conformance::with_volumes(factory(), Prefs::new(&[IdmapWay::AtCopy]), false)
    );
}

mod volumes_by_the_monitor {
    use super::*;
    velarx_graph::volume_conformance_suite_with!(
        in_namespace;
        velarx_graph::conformance::with_volumes(
            factory(),
            Prefs::new(&[IdmapWay::MonitorMount, IdmapWay::AtCopy]),
            true
        )
    );
}

mod volumes_without_a_way_to_map {
    use super::*;
    velarx_graph::volume_conformance_suite_with!(
        in_namespace;
        velarx_graph::conformance::with_volumes(factory(), Prefs::NONE, false)
    );
}
