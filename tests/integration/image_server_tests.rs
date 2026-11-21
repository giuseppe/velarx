// SPDX-License-Identifier: Apache-2.0
//! The image server of the composefs storage driver: a process of its own
//! (`velarx-monitor --image-server`) serves the EROFS images of the layers by
//! FUSE and hands the overlay over as a mount descriptor.  The tests run in a
//! user and mount namespace of a child of the test binary, as an unprivileged
//! engine does, with the monitor binary cargo built as the server.

use crate::check_tests::{composefs_env, pulled};
use crate::common::*;
use crate::monitor_common::namespace;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::Duration;
use velarx_core::services::ImageService;
use velarx_core::storage_driver::{
    DriverErrorKind, MountRequest, Mounts, MountsRequest, Purpose, Rootfs, StorageDriver,
    VerityAsk, Writable, WritableOptions,
};
use velarx_fuse::plan::RootfsPlan;
use velarx_fuse::view::{ImageTree, VIEW_ROOT};
use velarx_fuse::{IdTranslate, MountedImage};
use velarx_proto::pod::IdMapping;

/// How long a test waits for a server to end once nothing holds its file
/// system.
const ENDS: Duration = Duration::from_secs(30);

/// The ids the namespace of the test shows: the root of the namespace, alone.
fn own_ids() -> IdTranslate {
    let one = || {
        vec![IdMapping {
            container_id: 0,
            host_id: 0,
            size: 1,
        }]
    };
    IdTranslate {
        uid: one(),
        gid: one(),
        squash: false,
    }
}

/// The monitor binary, which is the server; its absence is a failure of the
/// run (`cargo build --bins`), never a skip.
fn server_binary() -> PathBuf {
    built_binary("velarx-monitor").expect("no velarx-monitor next to the tests: cargo build --bins")
}

/// A service whose driver serves the layers with the image server.
fn with_server(e: &Env, program: PathBuf) -> ImageService {
    let run_root = e._tmp.path().join("run");
    std::fs::create_dir_all(&run_root).unwrap();
    (*e.service).clone().with_image_server(
        program,
        run_root,
        std::sync::Arc::new(velarx_config::Config::default()),
    )
}

/// What a start asks of the driver for the root or an image mount of the
/// image `id` of the container `w`.
struct Ask {
    image: velarx_db::ImageRecord,
    layers: Vec<velarx_db::LayerRecord>,
    translate: IdTranslate,
    w: Writable,
    verity_accepted: Option<Vec<Vec<String>>>,
    _bundle: tempfile::TempDir,
}

impl Ask {
    async fn new(e: &Env, id: &str) -> Self {
        let bundle = tempfile::tempdir().unwrap();
        Self {
            image: e.db.get_image(id).await.unwrap(),
            layers: e.db.get_image_layers(id).await.unwrap(),
            translate: own_ids(),
            w: Writable::new("0123456789abcdef0123456789abcdef", bundle.path()),
            verity_accepted: None,
            _bundle: bundle,
        }
    }

    fn request(&self, purpose: Purpose) -> MountRequest<'_> {
        MountRequest {
            container: &self.w,
            purpose,
            image: &self.image,
            layers: &self.layers,
            mapping: None,
            translate: Some(&self.translate),
            idmap_mount: false,
            label: None,
            verity: VerityAsk::Off,
            volatile: false,
        }
    }
}

impl Ask {
    /// [`Self::request`] with the digests enforced (`verity_accepted`).
    fn request_enforced(&self, purpose: Purpose) -> MountRequest<'_> {
        MountRequest {
            verity: VerityAsk::Enforce {
                accepted: self.verity_accepted.as_deref().expect("lists"),
                chain: None,
            },
            ..self.request(purpose)
        }
    }
}

fn mounts(
    driver: &dyn StorageDriver,
    root: Option<MountRequest<'_>>,
    volumes: usize,
    a: &Ask,
) -> Mounts {
    driver
        .mounts(&MountsRequest {
            root,
            volumes: (0..volumes)
                .map(|n| a.request(Purpose::Volume { index: n as u32 }))
                .collect(),
        })
        .unwrap()
}

/// The regular files and directories of a tree, by path, with their size and
/// mode, in order.
fn listing(tree: &dyn ImageTree) -> Vec<(String, velarx_storage::TocEntryType, u64, u32)> {
    fn walk(
        tree: &dyn ImageTree,
        dir: usize,
        out: &mut Vec<(String, velarx_storage::TocEntryType, u64, u32)>,
    ) {
        for (name, id) in tree.children(dir).unwrap() {
            let node = tree.node(id).unwrap();
            let e = &node.entry;
            out.push((e.name.clone(), e.entry_type, e.size, e.mode));
            if e.entry_type == velarx_storage::TocEntryType::Dir {
                let _ = name;
                walk(tree, id, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(tree, VIEW_ROOT, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn read(tree: &dyn ImageTree, path: &str) -> Vec<u8> {
    use std::io::Read;
    let node = tree
        .node(tree.resolve(path).expect("a file of the image"))
        .unwrap();
    let mut data = Vec::new();
    tree.open_content(&node)
        .unwrap()
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// The server of an answer has not ended.
fn alive(r: &Rootfs) -> bool {
    !velarx_sys::pidfd::has_exited(r.server.as_ref().expect("a server").as_fd())
}

/// The mount of an answer, as the engine reads an image through a mount.
fn viewed(fd: OwnedFd) -> MountedImage {
    MountedImage::new(fd).unwrap()
}

/// A volume of an image served by the image server is the image: what the
/// engine's own view of the layers lists, the same files with the same
/// content; its server is a process whose pidfd the driver hands over, and it
/// ends by itself when the last reference to the mount goes.
#[test]
fn a_volume_is_served_by_a_process_that_ends_with_the_mount() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (e, id) = pulled().await;
            let service = with_server(&e, server_binary());
            let driver = service.storage().clone();
            let a = Ask::new(&e, &id).await;
            let answer = mounts(&*driver, None, 1, &a);
            let r = answer.volumes.into_iter().next().unwrap();
            assert!(matches!(r.plan, RootfsPlan::MountFd(_)), "{:?}", r.plan);
            assert!(r.fd.is_some() && r.server.is_some());
            assert!(alive(&r));
            let reference = driver.image_view(&id, &a.layers).unwrap();
            let Rootfs { fd, server, .. } = r;
            let view = viewed(fd.unwrap());
            assert_eq!(listing(&view), listing(&*reference));
            assert_eq!(read(&view, "etc/small"), b"hello\n");
            assert_eq!(read(&view, "usr/big").len(), 100_000);
            let server = server.unwrap();
            assert!(!velarx_sys::pidfd::has_exited(server.as_fd()));
            // nothing tells the server to stop: it ends with its mount
            drop(view);
            assert!(velarx_sys::pidfd::wait_exit(server.as_fd(), ENDS).unwrap());
        });
        std::mem::forget(rt);
    });
}

/// A mount cloned from the descriptor keeps the file system, and the server,
/// alive after the descriptor is gone; the server ends when the clone does.
/// The engine and the monitor close what they hold the same way: a copy that
/// stayed open would keep a server for every container that ever ran.
#[test]
fn a_clone_of_the_mount_keeps_the_server_until_it_goes() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (e, id) = pulled().await;
            let service = with_server(&e, server_binary());
            let a = Ask::new(&e, &id).await;
            let r = mounts(&**service.storage(), None, 1, &a).volumes.remove(0);
            let Rootfs { fd, server, .. } = r;
            let (fd, server) = (fd.unwrap(), server.unwrap());
            let clone = rustix::mount::open_tree(
                &fd,
                "",
                rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                    | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
                    | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH
                    | rustix::mount::OpenTreeFlags::AT_RECURSIVE,
            )
            .unwrap();
            drop(fd);
            // (the server answers: it is not gone)
            let view = viewed(clone);
            assert_eq!(read(&view, "etc/small"), b"hello\n");
            assert!(!velarx_sys::pidfd::has_exited(server.as_fd()));
            drop(view);
            assert!(velarx_sys::pidfd::wait_exit(server.as_fd(), ENDS).unwrap());
        });
        std::mem::forget(rt);
    });
}

/// The root file system: the overlay has the container's upper layer, takes
/// a write and keeps it there, and has the `/etc/mtab` the monitor's overlay
/// has.
#[test]
fn the_root_is_a_writable_overlay_of_the_served_layers() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (e, id) = pulled().await;
            let service = with_server(&e, server_binary());
            let driver = service.storage().clone();
            let a = Ask::new(&e, &id).await;
            driver
                .writable_create(&a.w, None, &WritableOptions::default(), None)
                .unwrap();
            let answer = mounts(&*driver, Some(a.request(Purpose::Root)), 0, &a);
            let r = answer.root.unwrap();
            assert!(r.server.is_some() && alive(&r));
            let Rootfs { fd, server, .. } = r;
            let fd = fd.unwrap();
            let at = format!("/proc/self/fd/{}", fd.as_raw_fd());
            assert_eq!(
                std::fs::read(format!("{at}/etc/small")).unwrap(),
                b"hello\n"
            );
            std::fs::write(format!("{at}/etc/written"), b"w\n").unwrap();
            std::fs::write(format!("{at}/etc/small"), b"changed\n").unwrap();
            assert_eq!(
                std::fs::read_link(format!("{at}/etc/mtab")).unwrap(),
                PathBuf::from("/proc/mounts")
            );
            let upper = driver.writable_paths(&a.w).upper;
            assert_eq!(std::fs::read(upper.join("etc/written")).unwrap(), b"w\n");
            assert_eq!(
                std::fs::read(upper.join("etc/small")).unwrap(),
                b"changed\n"
            );
            let reference = driver.image_view(&id, &a.layers).unwrap();
            let small = reference
                .node(reference.resolve("etc/small").unwrap())
                .unwrap();
            assert_eq!(small.entry.size, 6);
            drop(fd);
            assert!(velarx_sys::pidfd::wait_exit(server.unwrap().as_fd(), ENDS).unwrap());
        });
        std::mem::forget(rt);
    });
}

/// A server that cannot be started or does not answer is a start that fails,
/// with the reason: the monitor needs the same FUSE and Landlock, so the plan
/// is not left to it.  Nothing is left running.
#[test]
fn a_server_that_cannot_start_is_a_start_error_with_the_reason() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (e, id) = pulled().await;
            let a = Ask::new(&e, &id).await;
            let missing = e._tmp.path().join("no-such-program");
            let ends_at_once = PathBuf::from("/bin/true");
            // (a server that ends at once is seen as the end of its stream or
            // as a request nobody reads)
            for (program, reason) in [(missing, "cannot run"), (ends_at_once, "image server:")] {
                let service = with_server(&e, program.clone());
                let err = service
                    .storage()
                    .mounts(&MountsRequest {
                        root: None,
                        volumes: vec![a.request(Purpose::Volume { index: 0 })],
                    })
                    .err()
                    .unwrap_or_else(|| panic!("{}: a start without a server", program.display()));
                let text = err.to_string();
                assert!(
                    text.contains("the image server cannot serve the image mount 0")
                        && text.contains(reason),
                    "{}: {text}",
                    program.display()
                );
                assert!(matches!(err.kind, DriverErrorKind::Storage));
            }
        });
        std::mem::forget(rt);
    });
}

/// An image that is being pulled (a lazy one) is served by the image server
/// too, with the loader of the files it lacks in the server (the facts, the
/// fetchers and the startup profile come with the request): the answer is
/// a mount with a server, the files are read through it, and the server ends
/// with the mount.  The digests being enforced, the driver refuses it itself.
#[test]
fn an_image_being_pulled_is_served_by_the_image_server() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (e, id) = pulled().await;
            let service = with_server(&e, server_binary());
            let driver = service.storage().clone();
            let mut a = Ask::new(&e, &id).await;
            a.image.is_lazy = true;
            // (an image being pulled has its pull, whose token the image
            // server is handed)
            let digest =
                velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, b"{}");
            e.area()
                .publish_pull(&velarx_content::pull::staged::StagedPull {
                    id: id.clone(),
                    manifest_digest: digest,
                    config_digest: digest,
                    manifest: "{}".into(),
                    config: "{}".into(),
                    layers: a.layers.iter().map(|l| l.key.to_string()).collect(),
                    tags: vec![],
                    digest_names: vec![],
                    pulls: vec![],
                    registry_ref: None,
                    started_at: String::new(),
                })
                .unwrap();
            // the plan says a mount at the create, as for any image
            let planned = driver
                .image_volume_create(&a.request(Purpose::Volume { index: 0 }))
                .unwrap();
            assert!(
                matches!(planned.plan, RootfsPlan::MountFd(_)),
                "{:?}",
                planned.plan
            );
            let r = mounts(&*driver, None, 1, &a).volumes.remove(0);
            assert!(matches!(r.plan, RootfsPlan::MountFd(_)), "{:?}", r.plan);
            assert!(r.fd.is_some() && r.server.is_some() && alive(&r));
            let Rootfs { fd, server, .. } = r;
            let view = viewed(fd.unwrap());
            assert_eq!(read(&view, "etc/small"), b"hello\n");
            // (the profile of the image is kept next to the records)
            drop(view);
            assert!(velarx_sys::pidfd::wait_exit(server.unwrap().as_fd(), ENDS).unwrap());
            // enforced digests and files the store lacks: refused by the driver
            let accepted = vec![vec!["sha256:".to_string() + &"0".repeat(64)]; a.layers.len()];
            a.verity_accepted = Some(accepted);
            let enforce = a.request_enforced(Purpose::Volume { index: 0 });
            let err = driver
                .mounts(&MountsRequest {
                    root: None,
                    volumes: vec![enforce],
                })
                .expect_err("an enforced lazy image");
            assert!(matches!(err.kind, DriverErrorKind::DigestEnforced), "{err}");
            assert!(err.to_string().contains("a lazy pull"), "{err}");
        });
        std::mem::forget(rt);
    });
}

/// Owners the mapping does not cover are the driver's refusal, whoever would
/// mount the image and at the create as at each start, with the words the
/// monitor used to give; squashed, they are served.
#[test]
fn owners_outside_the_mapping_are_refused_by_the_driver() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (e, id) = pulled().await;
            let service = with_server(&e, server_binary());
            let mut a = Ask::new(&e, &id).await;
            // (the files of the image are owned by 0)
            let elsewhere = || {
                vec![IdMapping {
                    container_id: 1000,
                    host_id: 0,
                    size: 1,
                }]
            };
            a.translate = IdTranslate {
                uid: elsewhere(),
                gid: elsewhere(),
                squash: false,
            };
            let driver = &**service.storage();
            let refused = |text: String| {
                assert!(
                    text.contains("the image has files owned by uid 0, which is not mapped in the user namespace")
                        && text.contains("/etc/subuid"),
                    "{text}"
                );
            };
            // at the start
            refused(
                driver
                    .mounts(&MountsRequest {
                        root: None,
                        volumes: vec![a.request(Purpose::Volume { index: 0 })],
                    })
                    .expect_err("a start with owners outside the mapping")
                    .to_string(),
            );
            // and at the create
            refused(
                driver
                    .image_volume_create(&a.request(Purpose::Volume { index: 0 }))
                    .expect_err("a create with owners outside the mapping")
                    .to_string(),
            );
            // squashed, they are served
            a.translate.squash = true;
            let r = mounts(driver, None, 1, &a).volumes.remove(0);
            assert!(r.server.is_some() && r.fd.is_some(), "{:?}", r.plan);
        });
        std::mem::forget(rt);
    });
}

/// A link in the place of an image is not followed, a missing image is not
/// made again: the start fails, as for the kernel's
/// mount, and no server is left.
#[test]
fn a_swapped_or_linked_image_is_not_served() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (e, id) = pulled().await;
            let service = with_server(&e, server_binary());
            let driver = service.storage().clone();
            let a = Ask::new(&e, &id).await;
            let layer = a.layers.last().unwrap();
            let image =
                velarx_fuse::composefs::layer_image_path(e.store.root(), &layer.key.file_stem());
            let original = std::fs::read(&image).unwrap();
            // (a changed byte is the digests' to find, on a file system that has
            // fs-verity: the e2e tests of the enforced start do)
            let refused = |driver: &dyn StorageDriver| {
                driver
                    .mounts(&MountsRequest {
                        root: None,
                        volumes: vec![a.request(Purpose::Volume { index: 0 })],
                    })
                    .unwrap_err()
            };
            // a link to a copy of the right image
            let copy = image.with_extension("copy");
            std::fs::write(&copy, &original).unwrap();
            std::fs::remove_file(&image).unwrap();
            std::os::unix::fs::symlink(&copy, &image).unwrap();
            let err = refused(&*driver);
            assert!(matches!(err.kind, DriverErrorKind::Corrupt { .. }), "{err}");
            std::fs::remove_file(&image).unwrap();
            let err = refused(&*driver);
            assert!(
                matches!(
                    err.kind,
                    DriverErrorKind::Missing { .. } | DriverErrorKind::Corrupt { .. }
                ),
                "{err}"
            );
            std::fs::write(&image, &original).unwrap();
            std::fs::set_permissions(&image, std::os::unix::fs::PermissionsExt::from_mode(0o444))
                .unwrap();
            let r = mounts(&*driver, None, 1, &a).volumes.remove(0);
            assert!(r.server.is_some());
        });
        std::mem::forget(rt);
    });
}

/// More layers than one message carries descriptors for are served: the
/// descriptors follow the request in more messages.
#[test]
fn an_image_of_many_layers_is_served() {
    velarx_base::testing::in_child(|| {
        if !namespace() {
            return;
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let e = composefs_env().await;
            let layers: Vec<_> = (0..130)
                .map(|n| {
                    build_chunked(&[Item::File {
                        name: Box::leak(format!("l{n}").into_boxed_str()),
                        data: format!("layer {n}\n").into_bytes(),
                        chunk: 4096,
                    }])
                })
                .collect();
            let refs: Vec<&Built> = layers.iter().collect();
            e.publish(&refs, &vec![ZSTD; refs.len()]);
            let id = e.pull().await.unwrap().id;
            let service = with_server(&e, server_binary());
            let a = Ask::new(&e, &id).await;
            assert_eq!(a.layers.len(), 130);
            let r = mounts(&**service.storage(), None, 1, &a).volumes.remove(0);
            let view = viewed(r.fd.expect("a mount"));
            assert_eq!(read(&view, "l0"), b"layer 0\n");
            assert_eq!(read(&view, "l129"), b"layer 129\n");
            drop(view);
            assert!(velarx_sys::pidfd::wait_exit(r.server.unwrap().as_fd(), ENDS).unwrap());
        });
        std::mem::forget(rt);
    });
}
