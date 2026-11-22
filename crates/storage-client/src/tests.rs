// SPDX-License-Identifier: Apache-2.0
//! The client against a fake driver in the process (`fake`): each call, the
//! descriptors, the version, the deadline, the errors it does not know and
//! the messages that are too large.

use crate::fake::{error, reply, Call, Fake};
use crate::{Link, Options, VarlinkDriver};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use velarx_db::{ImageRecord, LayerRecord};
use velarx_graph::{
    DriverError, DriverErrorKind, IdmapDone, LabelDone, LayerRef, MountRequest, MountsRequest,
    ObjectRange, Prefs, Purpose, Remedy, StorageDriver, VerityAsk, Writable, WritableOptions,
};
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::LayerKey;
use velarx_wire::varlink::Conn;

mod pull;

pub(crate) struct Env {
    pub fake: Fake,
    pub graph: tempfile::TempDir,
    pub driver: VarlinkDriver,
}

pub(crate) fn open(
    fake: &Fake,
    graph: &Path,
    timeout: Duration,
) -> Result<VarlinkDriver, DriverError> {
    VarlinkDriver::open(Options {
        link: Link {
            socket: fake.socket.clone(),
            timeout,
        },
        graph_root: graph.to_path_buf(),
    })
}

pub(crate) fn env_with(timeout: Duration) -> Env {
    env_over(Fake::start(), timeout)
}

/// An environment over `fake`, as it is set up (what its `GetInfo` says is
/// read when the driver opens).
pub(crate) fn env_over(fake: Fake, timeout: Duration) -> Env {
    let graph = tempfile::tempdir().unwrap();
    let driver = VarlinkDriver::open(Options {
        link: Link {
            socket: fake.socket.clone(),
            timeout,
        },
        graph_root: graph.path().to_path_buf(),
    })
    .expect("open");
    Env {
        fake,
        graph,
        driver,
    }
}

pub(crate) fn env() -> Env {
    env_with(Duration::from_secs(5))
}

pub(crate) fn digest(n: u8) -> Digest {
    format!("sha256:{}", format!("{n:02x}").repeat(32))
        .parse()
        .unwrap()
}

pub(crate) fn key(n: u8) -> LayerKey {
    LayerKey::Whole(digest(n))
}

fn layer_ref(n: u8) -> LayerRef {
    LayerRef {
        key: key(n),
        diff_id: digest(n),
        chain_id: digest(n),
    }
}

fn expect_err<T: std::fmt::Debug>(r: Result<T, DriverError>, what: &str) -> DriverError {
    match r {
        Ok(v) => panic!("{what}: expected an error, got {v:?}"),
        Err(e) => e,
    }
}

fn memfd(content: &str) -> OwnedFd {
    let fd = rustix::fs::memfd_create("t", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
    std::fs::File::from(fd.try_clone().unwrap())
        .write_all(content.as_bytes())
        .unwrap();
    fd
}

fn read_bytes(fd: OwnedFd) -> Vec<u8> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::from(fd);
    let mut s = vec![0u8; f.metadata().unwrap().len() as usize];
    f.read_exact_at(&mut s, 0).unwrap();
    s
}

fn read_all(fd: OwnedFd) -> String {
    String::from_utf8(read_bytes(fd)).unwrap()
}

fn image() -> ImageRecord {
    ImageRecord {
        id: "i".repeat(64),
        manifest_digest: digest(0xa0),
        config_digest: digest(0xa1),
        manifest: "{}".into(),
        config: json!({
            "architecture": "amd64", "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [digest(1).to_string(), digest(2).to_string()]}
        })
        .to_string(),
        created_at: String::new(),
        is_lazy: false,
    }
}

fn layer_records() -> Vec<LayerRecord> {
    [1u8, 2]
        .into_iter()
        .map(|n| LayerRecord {
            stream_size: Some(0),
            key: key(n),
            blob: Some(digest(n)),
            diff_id: Some(digest(n)),
            other_diff_id: None,
            size: 1,
            status: "ready".into(),
            created_at: String::new(),
            registry_ref: None,
            erofs: Some("fsverity-sha256-12:aa".into()),
            owners: None,
        })
        .collect()
}

fn request<'a>(
    w: &'a Writable,
    image: &'a ImageRecord,
    layers: &'a [LayerRecord],
    purpose: Purpose,
) -> MountRequest<'a> {
    MountRequest {
        container: w,
        purpose,
        image,
        layers,
        mapping: None,
        translate: None,
        idmap_mount: false,
        label: None,
        verity: VerityAsk::Off,
        volatile: false,
    }
}

fn writable() -> Writable {
    Writable::new("c1", "/bundles/c1")
}

fn not_found_reason(reason: &str) -> Value {
    json!({ "reason": reason })
}

/// The open reads `GetInfo`, makes the id of the store in a file of the graph
/// root, and the capabilities are what the driver said; what it adds that is
/// not known is ignored; the name is its own.
#[test]
fn open_reads_the_capabilities_and_makes_the_store_id() {
    let e = env();
    assert_eq!(e.driver.name(), "fake");
    assert_eq!(e.driver.version(), "1.2.3");
    let caps = e.driver.capabilities();
    assert!(caps.rootless && caps.writable_size_limit && !caps.lazy);
    assert_eq!(caps.max_layers, Some(128));
    assert_eq!(
        caps.verity,
        Prefs::new(&[velarx_graph::VerityEnforcement::PullOnly])
    );
    assert_eq!(
        caps.root.idmap,
        Prefs::new(&[
            velarx_graph::IdmapWay::DriverMount,
            velarx_graph::IdmapWay::AtCopy
        ])
    );
    assert_eq!(
        caps.volume.unwrap().idmap,
        Prefs::new(&[velarx_graph::IdmapWay::AtCopy])
    );
    assert_eq!(caps.limits, velarx_graph::Limits::V1);
    // the id of the store is the file of the graph root, and every call has it
    let id = std::fs::read_to_string(velarx_graph::StoreId::path(e.graph.path())).unwrap();
    assert_eq!(id.trim(), e.driver.store().as_str());
    assert!(velarx_graph::stores::is_store_id(e.driver.store().as_str()));
    e.fake
        .handle(|_, conn| reply(conn, &json!({"exists": true}), false, &[]));
    assert!(e.driver.writable_exists(&writable()).unwrap());
    let calls = e.fake.calls_of("Exists");
    assert_eq!(calls[0]["store"], id.trim());
    assert_eq!(calls[0]["container"], "c1");
    // a second driver on the same graph root has the same store
    let again = open(&e.fake, e.graph.path(), Duration::from_secs(1)).unwrap();
    assert_eq!(again.store(), e.driver.store());
    // a driver that says it is lazy is not taken at its word: the client
    // serves no lazy image yet, and a lazy pull is refused up front
    e.fake.say(|i| {
        i["capabilities"]
            .as_array_mut()
            .unwrap()
            .push(json!("lazy"))
    });
    let lazy = open(&e.fake, e.graph.path(), Duration::from_secs(1)).unwrap();
    assert!(!lazy.capabilities().lazy);
    // a name is a short word, never text for the logs to take as theirs
    for bad in ["", "a\nb", "\u{1b}[31mred", &"n".repeat(65)] {
        e.fake.say(|i| i["name"] = json!(bad));
        let err = expect_err(
            open(&e.fake, e.graph.path(), Duration::from_secs(1)),
            "a bad name",
        );
        assert!(err.message().contains("calls itself"), "{err}");
    }
}

/// A driver of another version is refused at connect, whatever else it says,
/// naming both versions; one that changes its version later is refused at the
/// next call.
#[test]
fn a_driver_of_another_version_is_refused_at_connect_and_at_each_call() {
    let fake = Fake::start();
    let graph = tempfile::tempdir().unwrap();
    // (a version 3 may have another shape altogether)
    fake.say(|i| *i = json!({"proto": 3, "something": "else"}));
    let e = expect_err(
        open(&fake, graph.path(), Duration::from_secs(1)),
        "version 2",
    );
    assert!(matches!(e.kind, DriverErrorKind::ProtocolMismatch), "{e:?}");
    assert!(
        e.message().contains("Storage.3") && e.message().contains("Storage.2"),
        "{e}"
    );
    assert!(e.message().contains("upgrade"), "{e}");
    // the id of the store is not made for a driver that is refused? it is:
    // the engine's graph root has one store whatever the driver
    fake.say(|i| *i = crate::fake::default_info());
    let driver = open(&fake, graph.path(), Duration::from_secs(1)).unwrap();
    fake.handle(|_, conn| reply(conn, &json!({"exists": true}), false, &[]));
    assert!(driver.writable_exists(&writable()).unwrap());
    fake.say(|i| i["proto"] = json!(7));
    let before = fake.calls_of("Exists").len();
    let e = expect_err(
        driver.writable_exists(&writable()),
        "the driver was upgraded",
    );
    assert!(matches!(e.kind, DriverErrorKind::ProtocolMismatch), "{e:?}");
    assert_eq!(
        fake.calls_of("Exists").len(),
        before,
        "the call is not sent to a driver of another version"
    );
}

/// What the engine cannot honour, or a driver that states nonsense, is refused
/// at open; the limits are the driver's but never above what this build takes.
#[test]
fn limits_are_honoured_and_nonsense_is_refused() {
    let fake = Fake::start();
    let graph = tempfile::tempdir().unwrap();
    fake.say(|i| {
        i["limits"] =
            json!({"max_message": 100_000_000, "max_fds": 400, "max_wants": 10, "max_ranges": 3})
    });
    let d = open(&fake, graph.path(), Duration::from_secs(1)).unwrap();
    let l = d.capabilities().limits;
    assert_eq!(
        (l.message, l.fds, l.wants, l.ranges),
        (velarx_graph::Limits::V1.message, 16, 10, 3)
    );
    for (limits, why) in [
        (
            json!({"max_message": 100, "max_fds": 16, "max_wants": 1, "max_ranges": 1}),
            "too small",
        ),
        (
            json!({"max_message": 100_000, "max_fds": 0, "max_wants": 1, "max_ranges": 1}),
            "too small",
        ),
        (
            json!({"max_message": 100_000, "max_fds": 4, "max_wants": 1, "max_ranges": 0}),
            "too small",
        ),
    ] {
        fake.say(|i| i["limits"] = limits.clone());
        let e = expect_err(open(&fake, graph.path(), Duration::from_secs(1)), "limits");
        assert!(e.message().contains(why), "{e}");
    }
}

/// A value of an enum that this build does not know is a `Storage` error that
/// names it, in every reply that has one.
#[test]
fn an_unknown_value_of_an_enum_is_a_storage_error_that_names_it() {
    let fake = Fake::start();
    let graph = tempfile::tempdir().unwrap();
    fake.say(|i| i["mounts"]["root"] = json!({"idmap": ["time_travel"]}));
    let e = expect_err(open(&fake, graph.path(), Duration::from_secs(1)), "root");
    assert!(matches!(e.kind, DriverErrorKind::Storage), "{e:?}");
    assert!(e.message().contains("time_travel"), "{e}");
    assert!(e.message().contains("does not know"), "{e}");
    fake.say(|i| *i = crate::fake::default_info());
    // (a word of the capabilities that is not known is ignored)
    fake.say(|i| {
        i["capabilities"]
            .as_array_mut()
            .unwrap()
            .push(json!("telepathy"))
    });
    open(&fake, graph.path(), Duration::from_secs(1)).unwrap();
    fake.say(|i| *i = crate::fake::default_info());
    let e = env();
    let w = writable();
    let (img, layers) = (image(), layer_records());
    let mounts = |root: Value| {
        e.fake.handle(move |_, conn| {
            let fd = memfd("x");
            reply(
                conn,
                &json!({"root": root, "volumes": []}),
                false,
                &[fd.as_fd()],
            )
        });
        let req = MountsRequest {
            root: Some(request(&w, &img, &layers, Purpose::Root)),
            volumes: Vec::new(),
        };
        e.driver.mounts(&req)
    };
    let mount = |k: &str, i: &str, l: &str| json!({"kind": k, "fd": 0, "idmap": i, "label": l});
    for (m, named) in [
        (mount("hologram", "none", "none"), "hologram"),
        (mount("mount_fd", "sideways", "none"), "sideways"),
        (mount("mount_fd", "none", "stained"), "stained"),
    ] {
        let err = expect_err(mounts(m), named);
        assert!(matches!(err.kind, DriverErrorKind::Storage), "{err:?}");
        assert!(err.message().contains(named), "{err}");
        assert!(!err.message().contains("protocol"), "{err}");
    }
    // the known ones go through
    let ok = mounts(mount("mount_fd", "mount", "files"))
        .unwrap()
        .root
        .unwrap();
    assert_eq!((ok.idmap, ok.label), (IdmapDone::Mount, LabelDone::Files));
}

/// The errors of the interface are the engine's, with their remedy and layer;
/// a name that is not known is a `Storage` error that carries it, the
/// verdicts of the engine are never taken from a driver.
#[test]
fn errors_are_mapped_and_unknown_names_are_carried() {
    let e = env();
    let answer = |name: &'static str, params: Value| {
        e.fake.handle(move |_, conn| error(conn, name, &params));
        e.driver.writable_exists(&writable()).unwrap_err()
    };
    let layer = key(3).to_string();
    let miss = answer(
        "org.velarx.Storage.Missing",
        json!({"reason": "gone: pull the image again", "layer": layer, "remedy": "pull_again"}),
    );
    assert!(
        matches!(
            miss.kind,
            DriverErrorKind::Missing {
                remedy: Remedy::PullAgain
            }
        ),
        "{miss:?}"
    );
    assert_eq!(miss.layer.as_deref(), Some(layer.as_str()));
    assert_eq!(miss.message(), "gone: pull the image again");
    let bad = answer(
        "org.velarx.Storage.Corrupt",
        json!({"reason": "x", "remedy": "recreate_container"}),
    );
    assert_eq!(bad.remedy(), Some(Remedy::RecreateContainer));
    // a remedy that is not known does not make a Missing one
    let odd = answer(
        "org.velarx.Storage.Missing",
        json!({"reason": "gone", "remedy": "reboot"}),
    );
    assert!(matches!(odd.kind, DriverErrorKind::Storage), "{odd:?}");
    assert!(odd.message().contains("missing"), "{odd}");
    for (name, want) in [
        ("Unsupported", "unsupported"),
        ("NotFound", "not found"),
        ("Busy", "busy"),
        ("LabelRefused", "label refused"),
        ("Unavailable", "unavailable"),
        ("Failed", "failed"),
    ] {
        let err = answer(
            Box::leak(format!("org.velarx.Storage.{name}").into_boxed_str()),
            not_found_reason("because"),
        );
        let ok = matches!(
            (&err.kind, want),
            (DriverErrorKind::Unsupported, "unsupported")
                | (DriverErrorKind::NotFound, "not found")
                | (DriverErrorKind::Busy, "busy")
                | (DriverErrorKind::LabelRefused, "label refused")
                | (DriverErrorKind::Unavailable, "unavailable")
                | (DriverErrorKind::Storage, "failed")
        );
        assert!(ok, "{name}: {err:?}");
        assert!(err.message().contains("because"), "{err}");
    }
    // names the engine does not know, or gives alone, and the service's own
    for name in [
        "org.velarx.Storage.BrandNewError",
        "org.velarx.Storage.Contradicted",
        "org.velarx.Storage.DigestEnforced",
        "org.velarx.Storage.Refused",
        "org.varlink.service.MethodNotFound",
    ] {
        let err = answer(name, not_found_reason("odd"));
        assert!(
            matches!(err.kind, DriverErrorKind::Storage),
            "{name}: {err:?}"
        );
        let last = name.rsplit('.').next().unwrap();
        assert!(
            err.message().contains(last) && err.message().contains("odd"),
            "{err}"
        );
    }
}

/// A driver that does not answer is `TimedOut`, naming the call; one that is
/// not there is `Unavailable`; one that goes away in the middle of a call too.
#[test]
fn a_silent_driver_is_timed_out_and_a_gone_one_is_unavailable() {
    let e = env_with(Duration::from_millis(300));
    e.fake
        .handle(|_, _| std::thread::sleep(Duration::from_secs(3)));
    let started = Instant::now();
    let err = expect_err(e.driver.writable_exists(&writable()), "silent");
    assert!(matches!(err.kind, DriverErrorKind::TimedOut), "{err:?}");
    assert!(
        err.message().contains("Exists") && err.message().contains("timeout_secs"),
        "{err}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    // goes away in the middle of the call
    let e = env();
    e.fake.handle(|_, conn| {
        let _ = conn.socket().shutdown(std::net::Shutdown::Both);
    });
    let err = expect_err(e.driver.writable_size(&writable()), "hung up");
    assert!(matches!(err.kind, DriverErrorKind::Unavailable), "{err:?}");
    assert!(err.message().contains("Size") && err.message().contains("start the storage service"));
    // not there: refused (the socket is a file nothing listens on) or gone
    let graph = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("nothing.sock");
    let err = expect_err(
        VarlinkDriver::open(Options {
            link: Link {
                socket,
                timeout: Duration::from_secs(1),
            },
            graph_root: graph.path().to_path_buf(),
        }),
        "no service",
    );
    assert!(matches!(err.kind, DriverErrorKind::Unavailable), "{err:?}");
    assert!(err.message().contains("start the storage service"), "{err}");
    // the fake is dropped: the socket file is left and nothing listens
    let fake = Fake::start();
    let socket = fake.socket.clone();
    let g2 = tempfile::tempdir().unwrap();
    let live = open(&fake, g2.path(), Duration::from_secs(1)).unwrap();
    drop(fake);
    assert!(!socket.exists());
    let err = expect_err(live.writable_exists(&writable()), "the service stopped");
    assert!(matches!(err.kind, DriverErrorKind::Unavailable), "{err:?}");
}

/// A socket this user may not connect to is there, not gone: the error says
/// the permission, and not that the service is to be started (and the engine
/// does not start it and ask again).
#[test]
fn a_socket_that_is_not_ours_to_use_is_permission_denied() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        // (root connects whatever the mode)
        return;
    }
    let fake = Fake::start();
    std::fs::set_permissions(&fake.socket, std::fs::Permissions::from_mode(0o000)).unwrap();
    let graph = tempfile::tempdir().unwrap();
    let err = expect_err(
        open(&fake, graph.path(), Duration::from_secs(1)).map(|_| ()),
        "a socket of mode 000",
    );
    assert!(
        matches!(&err.kind, DriverErrorKind::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
    assert!(
        err.message().contains(fake.socket.to_str().unwrap())
            && !err.message().contains("start the storage service"),
        "{err}"
    );
}

/// A message larger than the limit is refused, in both directions: a reply is
/// not read past it, a request is not sent.
#[test]
fn messages_over_the_limit_are_refused_both_ways() {
    let e = env();
    e.fake.handle(|_, conn| {
        let big = "x".repeat(2 * 1024 * 1024);
        reply(
            conn,
            &json!({"pairs": [{"name": "n", "value": big}]}),
            false,
            &[],
        );
    });
    let err = expect_err(e.driver.usage().map(|_| ()), "a reply of 2 MiB");
    assert!(matches!(err.kind, DriverErrorKind::Storage), "{err:?}");
    assert!(err.message().contains("too large"), "{err}");
    // the status of a driver that sends too much is a line that says so
    let status = e.driver.status();
    assert!(status.last().unwrap().1.contains("too large"), "{status:?}");
    // a request over the limit the driver states is not sent
    let small = Fake::start();
    small.say(|i| i["limits"]["max_message"] = json!(4096));
    let graph = tempfile::tempdir().unwrap();
    let d = open(&small, graph.path(), Duration::from_secs(1)).unwrap();
    let layers: Vec<LayerRef> = (0..100).map(|_| layer_ref(1)).collect();
    let err = expect_err(
        futures::executor::block_on(d.has_layers(&layers)),
        "100 layers in 4096 bytes",
    );
    assert!(err.message().contains("at most 4096"), "{err}");
    assert!(small.calls_of("HasLayers").is_empty(), "nothing was sent");
}

/// `HasLayers` has one reply and no progress: it must come within
/// `timeout_secs`, and a slower one is `TimedOut` naming the call and the key
/// that raises the deadline; the same service answers when the deadline is
/// longer than it takes.
#[test]
fn has_layers_must_be_answered_within_the_timeout() {
    let slow = |e: &Env| {
        e.fake.handle(|c, conn| {
            std::thread::sleep(Duration::from_millis(700));
            let n = c.params["layers"].as_array().unwrap().len();
            reply(conn, &json!({ "have": vec![true; n] }), false, &[]);
        })
    };
    let e = env_with(Duration::from_millis(300));
    slow(&e);
    let err = expect_err(
        futures::executor::block_on(e.driver.has_layers(&[layer_ref(1)])).map(|_| ()),
        "a slow HasLayers",
    );
    assert!(matches!(err.kind, DriverErrorKind::TimedOut), "{err:?}");
    assert!(
        err.message().contains("HasLayers")
            && err.message().contains("[storage.varlink] timeout_secs"),
        "{err}"
    );
    let e = env_with(Duration::from_secs(5));
    slow(&e);
    let have = futures::executor::block_on(e.driver.has_layers(&[layer_ref(1)])).unwrap();
    assert_eq!(have, [true]);
}

#[test]
fn has_layers_answers_each_place_in_the_order_asked() {
    let e = env();
    e.fake.handle(|c, conn| {
        let n = c.params["layers"].as_array().unwrap().len();
        // (the same layer at two places is two questions)
        let have: Vec<bool> = (0..n).map(|i| i % 2 == 0).collect();
        reply(conn, &json!({ "have": have }), false, &[]);
    });
    let layers = [layer_ref(1), layer_ref(2), layer_ref(1)];
    let have = futures::executor::block_on(e.driver.has_layers(&layers)).unwrap();
    assert_eq!(have, [true, false, true]);
    let sent = &e.fake.calls_of("HasLayers")[0]["layers"];
    assert_eq!(sent[0]["key"], key(1).to_string());
    assert_eq!(sent[0]["chain_id"], digest(1).to_string());
    assert_eq!(sent.as_array().unwrap().len(), 3);
    // an answer of the wrong length is refused
    e.fake
        .handle(|_, conn| reply(conn, &json!({"have": [true]}), false, &[]));
    let err = expect_err(
        futures::executor::block_on(e.driver.has_layers(&layers)),
        "short",
    );
    assert!(err.message().contains("1 layers for the 3 asked"), "{err}");
}

/// The descriptors of `Mounts` go to the mounts that name them, by position;
/// a reply that numbers them wrongly is refused; the mounts of two containers
/// in one request are never sent.
#[test]
fn mounts_give_each_mount_the_descriptor_it_names() {
    let e = env();
    let w = writable();
    let (img, layers) = (image(), layer_records());
    let ask = || MountsRequest {
        root: Some(request(&w, &img, &layers, Purpose::Root)),
        volumes: vec![
            request(&w, &img, &layers, Purpose::Volume { index: 0 }),
            request(&w, &img, &layers, Purpose::Volume { index: 1 }),
        ],
    };
    let m = |fd: Value| json!({"kind": "mount_fd", "fd": fd, "idmap": "applied", "label": "files"});
    let answer = |root: Value, vols: Vec<Value>, n: usize| {
        e.fake.handle(move |_, conn| {
            let fds: Vec<OwnedFd> = (0..n).map(|i| memfd(&format!("fd{i}"))).collect();
            let b: Vec<_> = fds.iter().map(AsFd::as_fd).collect();
            reply(conn, &json!({"root": root, "volumes": vols}), false, &b);
        });
    };
    // root names 1, the volumes 0 and 2
    answer(m(json!(1)), vec![m(json!(0)), m(json!(2))], 3);
    let got = e.driver.mounts(&ask()).unwrap();
    let root = got.root.unwrap();
    assert_eq!(read_all(root.fd.unwrap()), "fd1");
    assert_eq!(
        (root.idmap, root.label),
        (IdmapDone::Applied, LabelDone::Files)
    );
    assert!(matches!(root.plan, velarx_fuse::plan::RootfsPlan::MountFd(p) if !p.idmap));
    let fds: Vec<String> = got
        .volumes
        .into_iter()
        .map(|v| read_all(v.fd.unwrap()))
        .collect();
    assert_eq!(fds, ["fd0", "fd2"]);
    let sent = &e.fake.calls_of("Mounts")[0];
    assert_eq!(sent["container"], "c1");
    assert_eq!(sent["volumes"][1]["index"], 1);
    assert_eq!(sent["root"]["idmap_mount"], false);
    for (root, vols, n, why) in [
        (
            m(json!(0)),
            vec![m(json!(0)), m(json!(1))],
            2,
            "named by two mounts",
        ),
        (
            m(json!(5)),
            vec![m(json!(0)), m(json!(1))],
            3,
            "names the descriptor 5",
        ),
        (
            m(json!(0)),
            vec![m(json!(1)), m(json!(2))],
            4,
            "named by no mount",
        ),
        (
            m(Value::Null),
            vec![m(json!(0)), m(json!(1))],
            2,
            "without the position",
        ),
    ] {
        answer(root, vols, n);
        let err = expect_err(e.driver.mounts(&ask()).map(|_| ()), why);
        assert!(err.message().contains(why), "{why}: {err}");
    }
    // a volume that answers a directory: only a root may
    answer(
        m(json!(0)),
        vec![
            json!({"kind": "directory", "path": "/x/y", "idmap": "none", "label": "none"}),
            m(json!(1)),
        ],
        2,
    );
    let err = expect_err(e.driver.mounts(&ask()).map(|_| ()), "a directory volume");
    assert!(err.message().contains("only a root"), "{err}");
    // a root that is a directory has a path, relative to the work directory
    // of the store, and no descriptor
    answer(
        json!({"kind": "directory", "path": "c1/root", "idmap": "applied", "label": "none"}),
        vec![],
        0,
    );
    let only_root = MountsRequest {
        root: Some(request(&w, &img, &layers, Purpose::Root)),
        volumes: Vec::new(),
    };
    let root = e.driver.mounts(&only_root).unwrap().root.unwrap();
    assert!(root.fd.is_none());
    let workdir = std::fs::canonicalize(e.graph.path().join("varlink/work")).unwrap();
    match root.plan {
        velarx_fuse::plan::RootfsPlan::Directory(d) => {
            assert_eq!(d.beneath, workdir);
            assert_eq!(d.path, Path::new("c1/root"));
        }
        other => panic!("{other:?}"),
    }
    // the work directory is the engine's and closed to others
    let meta = std::fs::metadata(&workdir).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    // a driver cannot name another place of the host: an absolute path,
    // one that goes up, or one that is not plain
    for path in [
        "/etc",
        "/var/lib/d/root",
        "../../etc",
        "c1/../..",
        "c1//root",
        "./c1",
        "",
    ] {
        answer(
            json!({"kind": "directory", "path": path, "idmap": "applied", "label": "none"}),
            vec![],
            0,
        );
        let err = expect_err(e.driver.mounts(&only_root).map(|_| ()), path);
        assert!(
            matches!(err.kind, DriverErrorKind::Storage)
                && err.message().contains("root directory"),
            "{path}: {err}"
        );
    }
    // two containers in one request
    let other = Writable::new("c2", "/bundles/c2");
    let two = MountsRequest {
        root: Some(request(&w, &img, &layers, Purpose::Root)),
        volumes: vec![request(&other, &img, &layers, Purpose::Volume { index: 0 })],
    };
    let before = e.fake.calls_of("Mounts").len();
    let err = expect_err(e.driver.mounts(&two).map(|_| ()), "two containers");
    assert!(
        err.message().contains("c1") && err.message().contains("c2"),
        "{err}"
    );
    assert_eq!(e.fake.calls_of("Mounts").len(), before);
    // nothing asked, nothing called
    let none = MountsRequest {
        root: None,
        volumes: Vec::new(),
    };
    assert!(e.driver.mounts(&none).unwrap().root.is_none());
    assert_eq!(e.fake.calls_of("Mounts").len(), before);
}

/// `CreateRoot` and `CreateImageVolume` are long calls that answer what the
/// mount will be, with no descriptor; `idmap_mount` and the label are sent.
#[test]
fn create_calls_answer_the_plan_without_a_descriptor() {
    let e = env();
    let w = writable();
    let (img, layers) = (image(), layer_records());
    e.fake.handle(|_, conn| {
        reply(
            conn,
            &json!({"progress": {"message": "copying", "done": 1, "total": 2}}),
            true,
            &[],
        );
        reply(
            conn,
            &json!({"root": {"kind": "mount_fd", "idmap": "mount", "label": "mount_context"}}),
            false,
            &[],
        );
    });
    let mut base = request(&w, &img, &layers, Purpose::Root);
    base.idmap_mount = true;
    base.label = Some("system_u:object_r:container_file_t:s0:c1,c2");
    let translate = velarx_fuse::IdTranslate {
        uid: vec![velarx_proto::pod::IdMapping {
            container_id: 0,
            host_id: 100000,
            size: 65536,
        }],
        gid: vec![],
        squash: true,
    };
    base.mapping = Some(&translate);
    let planned = e
        .driver
        .writable_create(
            &w,
            Some((100000, 100000)),
            &WritableOptions {
                size_limit: Some(1 << 20),
            },
            Some(&base),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        (planned.idmap, planned.label),
        (IdmapDone::Mount, LabelDone::MountContext)
    );
    assert!(matches!(planned.plan, velarx_fuse::plan::RootfsPlan::MountFd(p) if p.idmap));
    let sent = &e.fake.calls_of("CreateRoot")[0];
    assert_eq!(sent["image"], img.id.as_str());
    // (the work directory of the store, the one base of a `directory` root)
    let workdir = std::fs::canonicalize(e.graph.path().join("varlink/work")).unwrap();
    assert_eq!(sent["workdir"], workdir.to_str().unwrap());
    assert_eq!(sent["owner"], json!({"uid": 100000, "gid": 100000}));
    assert_eq!(sent["size_limit"], 1 << 20);
    assert_eq!(sent["ask"]["idmap_mount"], true);
    assert_eq!(sent["ask"]["mapping"]["squash"], true);
    assert_eq!(sent["ask"]["mapping"]["uid"][0]["host_id"], 100000);
    // the chain ids are the engine's: the configuration's diff ids
    assert_eq!(sent["layers"][1]["diff_id"], digest(2).to_string());
    assert_ne!(sent["layers"][1]["chain_id"], sent["layers"][1]["diff_id"]);
    assert_eq!(sent["layers"][0]["chain_id"], digest(1).to_string());
    // no image: no root
    e.fake.handle(|_, conn| reply(conn, &json!({}), false, &[]));
    assert!(e
        .driver
        .writable_create(&w, None, &WritableOptions::default(), None)
        .unwrap()
        .is_none());
    // a descriptor in the reply, or a position in it: the mount is made at
    // create and handed over at the start
    e.fake.handle(|_, conn| {
        let fd = memfd("x");
        reply(
            conn,
            &json!({"root": {"kind": "mount_fd", "fd": 0, "idmap": "none", "label": "none"}}),
            false,
            &[fd.as_fd()],
        )
    });
    let err = expect_err(
        e.driver
            .writable_create(&w, None, &WritableOptions::default(), Some(&base)),
        "fd",
    );
    assert!(err.message().contains("descriptor"), "{err}");
    // a size limit the driver cannot honour is refused, not dropped
    e.fake
        .say(|i| i["capabilities"] = json!(["rootless", "verity_pull_only"]));
    let d = open(&e.fake, e.graph.path(), Duration::from_secs(1)).unwrap();
    let before = e.fake.calls_of("CreateRoot").len();
    let err = expect_err(
        d.writable_create(
            &w,
            None,
            &WritableOptions {
                size_limit: Some(5),
            },
            None,
        ),
        "no quota",
    );
    assert!(matches!(err.kind, DriverErrorKind::Unsupported), "{err:?}");
    assert_eq!(e.fake.calls_of("CreateRoot").len(), before);
    e.fake.say(|i| *i = crate::fake::default_info());
    // the image volume
    e.fake.handle(|_, conn| {
        reply(
            conn,
            &json!({"volume": {"kind": "mount_fd", "idmap": "applied", "label": "files"}}),
            false,
            &[],
        )
    });
    let vol = request(&w, &img, &layers, Purpose::Volume { index: 3 });
    let planned = e.driver.image_volume_create(&vol).unwrap();
    assert_eq!(planned.label, LabelDone::Files);
    let sent = &e.fake.calls_of("CreateImageVolume")[0];
    assert_eq!(
        (sent["index"].as_u64(), sent["container"].as_str()),
        (Some(3), Some("c1"))
    );
    let err = expect_err(
        e.driver
            .image_volume_create(&request(&w, &img, &layers, Purpose::Root)),
        "root",
    );
    assert!(err.message().contains("not for an image mount"), "{err}");
}

/// A long call lasts as long as the driver sends progress, and is `TimedOut`
/// when it goes silent: the rule of `wait_for_call`, through the wire.
#[test]
fn long_calls_live_on_progress_and_die_of_silence() {
    let e = env_with(Duration::from_millis(400));
    let w = writable();
    e.fake.handle(|_, conn| {
        for n in 0..6 {
            std::thread::sleep(Duration::from_millis(150));
            reply(conn, &json!({"progress": {"done": n}}), true, &[]);
        }
        reply(conn, &json!({}), false, &[]);
    });
    let started = Instant::now();
    e.driver
        .writable_create(&w, None, &WritableOptions::default(), None)
        .unwrap();
    assert!(
        started.elapsed() > Duration::from_millis(800),
        "outlived the 400 ms deadline: {:?}",
        started.elapsed()
    );
    // silent after some progress
    e.fake.handle(|_, conn| {
        reply(conn, &json!({"progress": {}}), true, &[]);
        std::thread::sleep(Duration::from_secs(3));
    });
    let started = Instant::now();
    let err = expect_err(
        e.driver
            .writable_create(&w, None, &WritableOptions::default(), None),
        "silent",
    );
    assert!(matches!(err.kind, DriverErrorKind::TimedOut), "{err:?}");
    assert!(err.message().contains("CreateRoot"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
    // the call is made with more
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    e.fake.handle(move |c: Call, conn| {
        log.lock().unwrap().push((c.method.clone(), c.more));
        reply(
            conn,
            &json!({"bytes_freed": 7, "errors": ["one"]}),
            false,
            &[],
        );
    });
    let c = e.driver.collect(&velarx_graph::Keep::default()).unwrap();
    assert_eq!(
        (c.bytes_freed, c.errors.as_slice()),
        (7, &["one".to_string()][..])
    );
    assert_eq!(seen.lock().unwrap()[0], ("Collect".to_string(), true));
    // a reply that ends the call without its answer
    e.fake
        .handle(|_, conn| reply(conn, &json!({"progress": {}}), false, &[]));
    let err = expect_err(
        e.driver.collect(&velarx_graph::Keep::default()).map(|_| ()),
        "no answer",
    );
    assert!(err.message().contains("without its answer"), "{err}");
}

/// The keep set travels as a sealed memory file of JSON lines whose length is
/// the argument.
#[test]
fn collect_sends_the_keep_set_in_a_sealed_memory_file() {
    let e = env();
    let seen = Arc::new(std::sync::Mutex::new(None));
    let log = seen.clone();
    e.fake.handle(move |mut c: Call, conn| {
        let fd = c.fds.remove(0);
        let sealed = rustix::fs::fcntl_get_seals(&fd).unwrap();
        let length = c.params["keep_length"].as_u64().unwrap();
        *log.lock().unwrap() = Some((sealed, length, read_all(fd)));
        reply(conn, &json!({"progress": {"message": "x"}}), true, &[]);
        reply(conn, &json!({"bytes_freed": 0}), false, &[]);
    });
    let keep = velarx_graph::Keep {
        layers: vec![key(1), key(2)],
        chains: vec![digest(9)],
        images: vec!["img".into()],
        containers: vec!["ctr".into()],
        pulls: vec!["p".into()],
        grace: Duration::from_secs(60),
    };
    e.driver.collect(&keep).unwrap();
    let (seals, length, lines) = seen.lock().unwrap().take().unwrap();
    assert_eq!(seals, velarx_base::sealed::memory_seals());
    assert_eq!(length as usize, lines.len());
    let back = velarx_graph::Keep::read_lines(&mut lines.as_bytes()).unwrap();
    assert_eq!(
        (back.layers, back.chains),
        (keep.layers.clone(), keep.chains.clone())
    );
    assert_eq!(back.grace, Duration::from_secs(60));
    assert_eq!(
        e.fake.calls_of("Collect")[0]["store"],
        e.driver.store().as_str()
    );
}

#[test]
fn repair_and_check_are_long_calls_with_typed_answers() {
    let e = env();
    let (img, layers) = (image(), layer_records());
    e.fake.handle(|c, conn| match c.method.as_str() {
        "Repair" => {
            reply(conn, &json!({"progress": {"message": "remaking"}}), true, &[]);
            reply(
                conn,
                &json!({"artifacts": [{"key": key(1).to_string(), "image_digest": "fsverity-sha256-12:ab", "owners": {"uids": [0], "gids": [0]}}]}),
                false,
                &[],
            );
        }
        _ => {
            let kind = c.params["image"].as_str().map(|_| "toc_differs").unwrap();
            reply(
                conn,
                &json!({"problems": [
                    {"kind": kind, "message": "m", "layer": key(2).to_string(), "path": "/p", "repair": true},
                    {"kind": "from_the_future", "message": "n", "repair": false}
                ]}),
                false,
                &[],
            );
        }
    });
    let refs = [layer_ref(1)];
    let made = futures::executor::block_on(e.driver.repair(&refs)).unwrap();
    assert_eq!(made[&key(1)].image_digest, "fsverity-sha256-12:ab");
    assert_eq!(
        e.fake.calls_of("Repair")[0]["layers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // a problem kind the engine does not know is a Storage error naming it
    let err = expect_err(
        futures::executor::block_on(e.driver.check(&img, &layers, true)),
        "kind",
    );
    assert!(matches!(err.kind, DriverErrorKind::Storage), "{err:?}");
    assert!(err.message().contains("from_the_future"), "{err}");
    let sent = &e.fake.calls_of("Check")[0];
    assert_eq!(
        (sent["full"].as_bool(), sent["image"].as_str()),
        (Some(true), Some(img.id.as_str()))
    );
    e.fake.handle(|_, conn| {
        reply(
            conn,
            &json!({"problems": [{"kind": "object_differs", "message": "m", "layer": key(2).to_string(), "path": "/p", "repair": true}]}),
            false,
            &[],
        )
    });
    let p = futures::executor::block_on(e.driver.check(&img, &layers, false)).unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].kind, velarx_graph::ProblemKind::ObjectDiffers);
    assert_eq!(
        (p[0].layer, p[0].path.clone(), p[0].repair),
        (Some(key(2)), Some("/p".into()), true)
    );
}

/// Every kind of problem has the same name on the wire and in the engine.
#[test]
fn the_wire_names_of_the_enums_are_the_engines() {
    use crate::proto::{ProblemKind, Remedy as WireRemedy};
    let wire = [
        ProblemKind::ArtifactMissing,
        ProblemKind::ArtifactUnreadable,
        ProblemKind::ArtifactWritable,
        ProblemKind::ArtifactIdMismatch,
        ProblemKind::ArtifactDiffers,
        ProblemKind::ArtifactSealMismatch,
        ProblemKind::AnnotationMissing,
        ProblemKind::AnnotationMismatch,
        ProblemKind::IdentityMissing,
        ProblemKind::TocMissing,
        ProblemKind::TocDiffers,
        ProblemKind::ObjectMissing,
        ProblemKind::ObjectDiffers,
    ];
    let names: Vec<String> = wire
        .iter()
        .map(|k| {
            serde_json::to_value(k)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let engine: Vec<&str> = velarx_graph::ProblemKind::ALL
        .iter()
        .map(|k| k.as_str())
        .collect();
    assert_eq!(names, engine);
    for (w, r) in [
        (WireRemedy::PullAgain, Remedy::PullAgain),
        (WireRemedy::Repair, Remedy::Repair),
        (WireRemedy::RecreateContainer, Remedy::RecreateContainer),
    ] {
        let name = serde_json::to_value(w).unwrap();
        assert_eq!(name.as_str(), Some(r.wire_name()));
    }
}

#[test]
fn the_plain_calls_are_typed_and_carry_the_store() {
    let e = env();
    let w = writable();
    e.fake.handle(|c, conn| {
        let answer = match c.method.as_str() {
            "Size" => json!({"bytes": 42}),
            "Exists" => json!({"exists": false}),
            "Usage" => json!({"files": 3, "bytes": 9000}),
            "Status" => json!({"pairs": [{"name": "backend", "value": "memory"}]}),
            "ListStores" => json!({"stores": [
                {"store": "a".repeat(32), "bytes": 5, "last_open": 1700000000},
                {"store": "b".repeat(32), "bytes": 6}
            ]}),
            _ => json!({}),
        };
        reply(conn, &answer, false, &[]);
    });
    assert_eq!(e.driver.writable_size(&w).unwrap(), 42);
    assert!(!e.driver.writable_exists(&w).unwrap());
    e.driver.writable_remove(&w).unwrap();
    e.driver.remove_image("imgid").unwrap();
    assert_eq!(e.driver.usage().unwrap().artifacts, (3, 9000));
    // (what the engine knows of the service, then what the service says)
    let status = e.driver.status();
    let names: Vec<&str> = status.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["socket", "service", "store", "capabilities", "backend"]
    );
    assert_eq!(status[1].1, "fake 1.2.3");
    assert_eq!(status[4], ("backend".to_string(), "memory".to_string()));
    let stores = e.driver.list_stores().unwrap();
    assert_eq!(
        (stores[0].bytes, stores[0].last_open),
        (5, Some(1700000000))
    );
    assert_eq!(stores[1].last_open, None);
    e.driver.drop_store(&"c".repeat(32)).unwrap();
    // a name is never a path: refused before it is sent
    let before = e.fake.calls_of("DropStore").len();
    for bad in ["../etc", "", &"G".repeat(32)] {
        assert!(e.driver.drop_store(bad).is_err(), "{bad:?}");
    }
    assert_eq!(e.fake.calls_of("DropStore").len(), before);
    let store = e.driver.store().as_str().to_string();
    for (m, field) in [
        ("RemoveRoot", "container"),
        ("RemoveImage", "image"),
        ("Usage", "store"),
    ] {
        let c = &e.fake.calls_of(m)[0];
        assert_eq!(c["store"], store.as_str(), "{m}");
        assert!(c.get(field).is_some(), "{m}");
    }
    // the stores are listed without one named
    assert!(e.fake.calls_of("ListStores")[0].get("store").is_none());
    // what the trait leaves to the engine
    assert!(
        futures::executor::block_on(e.driver.leftovers(Duration::ZERO))
            .unwrap()
            .is_empty()
    );
    assert!(e.driver.graph_data(&w).is_empty());
    assert!(e.driver.writable_paths(&w).work.is_none());
    let err = expect_err(
        futures::executor::block_on(e.driver.remake_staged("p")),
        "lazy",
    );
    assert!(matches!(err.kind, DriverErrorKind::Unsupported), "{err:?}");
    let err = expect_err(
        e.driver.is_root_of(&w, Path::new("/proc/1")),
        "no wire call",
    );
    assert!(matches!(err.kind, DriverErrorKind::Unsupported), "{err:?}");
}

/// `WritableRoot` is one descriptor, and what the engine reads and writes of a
/// root goes through it (the changes, the extraction of a layer).
#[test]
fn the_writable_root_is_a_descriptor_the_engine_walks() {
    let e = env();
    let w = writable();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("kept"), "data").unwrap();
    let path = dir.path().to_path_buf();
    e.fake.handle(move |_, conn| {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            &path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        reply(conn, &json!({}), false, &[fd.as_fd()]);
    });
    let fd = e.driver.writable_root(&w).unwrap();
    assert!(std::fs::File::from(fd).metadata().unwrap().is_dir());
    // a layer applied lands in the directory the driver handed over
    let mut tar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(5);
    h.set_mode(0o644);
    h.set_cksum();
    tar.append_data(&mut h, "applied", &b"hello"[..]).unwrap();
    let bytes = tar.into_inner().unwrap();
    let me = rustix::process::getuid().as_raw();
    let ids = vec![velarx_content::layer::dirtar::IdRange {
        container: 0,
        host: me,
        size: 1,
    }];
    let opts = velarx_graph::DiffOptions {
        uid_map: ids.clone(),
        gid_map: ids,
        ..Default::default()
    };
    e.driver.apply(&w, &opts, &mut bytes.as_slice()).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("applied")).unwrap(),
        "hello"
    );
    // the changes are found against an image: none given is an error
    let err = expect_err(
        e.driver
            .changes(&w, None, &velarx_graph::DiffOptions::default()),
        "no lower",
    );
    assert!(err.message().contains("none was given"), "{err}");
    // the wrong number of descriptors
    e.fake.handle(|_, conn| reply(conn, &json!({}), false, &[]));
    let err = expect_err(e.driver.writable_root(&w), "no descriptor");
    assert!(err.message().contains("0 descriptors"), "{err}");
    // one that is not a directory
    e.fake.handle(|_, conn| {
        let file = memfd("x");
        reply(conn, &json!({}), false, &[file.as_fd()]);
    });
    let err = expect_err(e.driver.writable_root(&w), "a file");
    assert!(err.message().contains("not a directory"), "{err}");
}

/// `MountImage` is one descriptor, a directory, which the view of the image
/// reads below; a reply with none, with two, with a file or with the root of
/// the host is refused naming the call.
#[test]
fn the_image_is_read_below_the_descriptor_of_mount_image() {
    let e = env();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("etc")).unwrap();
    std::fs::write(dir.path().join("etc/passwd"), "root:x:0:0::/:/bin/sh\n").unwrap();
    let open_dir = |path: &Path| {
        rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    };
    let path = dir.path().to_path_buf();
    let store = e.driver.store().as_str().to_string();
    e.fake.handle(move |c, conn| {
        assert_eq!(c.method, "MountImage");
        assert_eq!(c.params["store"].as_str(), Some(store.as_str()));
        assert_eq!(c.params["layers"].as_array().unwrap().len(), 2);
        reply(conn, &json!({}), false, &[open_dir(&path).as_fd()]);
    });
    let view = e.driver.image_view("img", &layer_records()).unwrap();
    let node = view.node(view.resolve("etc/passwd").unwrap()).unwrap();
    assert_eq!(node.entry.size, 22);
    assert!(!view.has_verity());
    drop(view);
    for (what, fds, says) in [
        ("none", 0, "0 descriptors"),
        ("two", 2, "2 descriptors"),
        ("a file", 1, "not a directory"),
        ("the root of the host", 1, "the root of the host"),
    ] {
        let path = dir.path().to_path_buf();
        e.fake.handle(move |_, conn| {
            let fd = match what {
                "a file" => memfd("x"),
                "the root of the host" => open_dir(Path::new("/")),
                _ => open_dir(&path),
            };
            let all: Vec<_> = (0..fds).map(|_| fd.as_fd()).collect();
            reply(conn, &json!({}), false, &all);
        });
        let err = expect_err(
            e.driver.image_view("img", &layer_records()).map(|_| ()),
            what,
        );
        assert!(err.message().contains(says), "{what}: {err}");
        assert!(err.message().contains("MountImage"), "{what}: {err}");
    }
}

/// The files of a layer are the service's: `toc.zst` is the descriptor 0 of
/// `LayerFiles` and `tarsplit.zst` the descriptor 1, which a canonical layer
/// does not have.
#[test]
fn the_files_of_a_layer_are_read_from_the_service() {
    use velarx_db::layer_files::{Source, TARSPLIT, TOC};
    let e = env();
    let key = layer_records()[0].key;
    let digest = Digest::of(velarx_types::digest::Algorithm::Sha256, b"table");
    let store = e.driver.store().as_str().to_string();
    let layer = key.to_string();
    e.fake.handle(move |c, conn| {
        assert_eq!(c.method, "LayerFiles");
        assert_eq!(c.params["store"].as_str(), Some(store.as_str()));
        assert_eq!(c.params["layer"].as_str(), Some(layer.as_str()));
        reply(
            conn,
            &json!({}),
            false,
            &[memfd("table").as_fd(), memfd("split").as_fd()],
        );
    });
    assert_eq!(e.driver.read(&key, TOC, &digest).unwrap(), b"table");
    assert_eq!(e.driver.read(&key, TARSPLIT, &digest).unwrap(), b"split");
    e.fake
        .handle(|_, conn| reply(conn, &json!({}), false, &[memfd("table").as_fd()]));
    assert_eq!(e.driver.read(&key, TOC, &digest).unwrap(), b"table");
    let none = e.driver.read(&key, TARSPLIT, &digest).unwrap_err();
    assert_eq!(none.kind(), std::io::ErrorKind::NotFound);
}

fn bytes_of(range: &ObjectRange) -> Vec<u8> {
    (0..range.length)
        .map(|i| (range.offset + i) as u8 ^ range.key.len() as u8)
        .collect()
}

/// Serve `ReadObjects`: the reply of a range before its bytes on the pipe.
fn serve_reads(e: &Env) {
    e.fake.handle(|mut c: Call, conn| {
        let pipe = std::fs::File::from(c.fds.remove(0));
        let ranges: Vec<ObjectRange> = c.params["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| ObjectRange {
                key: r["key"].as_str().unwrap().to_string(),
                offset: r["offset"].as_u64().unwrap(),
                length: r["length"].as_u64().unwrap(),
            })
            .collect();
        for (i, r) in ranges.iter().enumerate() {
            if r.key == "missing" {
                error(
                    conn,
                    "org.velarx.Storage.Missing",
                    &json!({"reason": "no such object: pull the image again", "remedy": "pull_again"}),
                );
                return;
            }
            // (the object `zz` has 20 bytes)
            if r.key == "zz" && r.offset + r.length > 20 {
                error(
                    conn,
                    "org.velarx.Storage.Corrupt",
                    &json!({"reason": "past the end", "remedy": "pull_again"}),
                );
                return;
            }
            // (a driver that tells the size of the object: the object `long`
            // has one byte more than any range of it wants)
            let reply_of = match r.key.as_str() {
                "long" => json!({"index": i, "size": r.offset + r.length + 1}),
                "told" => json!({"index": i, "size": r.offset + r.length}),
                _ => json!({"index": i}),
            };
            reply(conn, &reply_of, i + 1 < ranges.len(), &[]);
            (&pipe).write_all(&bytes_of(r)).unwrap();
        }
    });
}

/// The files of the image below the changes of a writable layer are read
/// back through the service (`ReadObjects`), not from a store of the engine:
/// the engine has no path to them.
#[test]
fn the_image_below_the_changes_is_read_through_the_service() {
    let e = env();
    serve_reads(&e);
    let tree = velarx_fuse::view::ImageView::new(Vec::new());
    let lower = e.driver.lower(Some(Arc::new(tree))).unwrap();
    let mut f = lower.objects.object_file("zz", 20).unwrap();
    let mut s = Vec::new();
    f.read_to_end(&mut s).unwrap();
    assert_eq!(s, bytes_of(&ObjectRange::whole("zz", 20)));
    assert!(!e.fake.calls_of("ReadObjects").is_empty());
    // (spooled on disk, in the scratch directory of the graph root, not in
    // TMPDIR, which may be a tmpfs)
    let at = std::fs::read_link(format!(
        "/proc/self/fd/{}",
        std::os::fd::AsRawFd::as_raw_fd(&f)
    ))
    .unwrap();
    assert!(
        at.starts_with(e.graph.path().join("varlink/scratch")),
        "{}",
        at.display()
    );
    let err = lower.objects.object_file("missing", 3).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn read_objects_reads_ranges_in_order_through_a_pipe() {
    let e = env();
    serve_reads(&e);
    let ranges = [
        ObjectRange {
            key: "a".into(),
            offset: 0,
            length: 10,
        },
        ObjectRange {
            key: "bb".into(),
            offset: 5,
            length: 0,
        },
        // (larger than a pipe holds: the reply is sent before the bytes)
        ObjectRange {
            key: "ccc".into(),
            offset: 7,
            length: 1 << 20,
        },
    ];
    let mut got: Vec<Vec<u8>> = vec![Vec::new(); 3];
    e.driver
        .read_objects(&ranges, &mut |i: usize, b: &[u8]| {
            got[i].extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    for (r, g) in ranges.iter().zip(&got) {
        assert_eq!(g, &bytes_of(r), "{}", r.key);
    }
    // the file of an object (the default open_object, spooled)
    let mut f = e.driver.open_object("zz", 20).unwrap();
    let mut s = Vec::new();
    f.read_to_end(&mut s).unwrap();
    assert_eq!(s, bytes_of(&ObjectRange::whole("zz", 20)));
    // an object that is not there: Missing, with its remedy, nothing after
    let err = expect_err(
        e.driver.read_objects(
            &[ObjectRange::whole("missing", 3)],
            &mut |_: usize, _: &[u8]| Ok(()),
        ),
        "missing",
    );
    assert!(
        matches!(
            err.kind,
            DriverErrorKind::Missing {
                remedy: Remedy::PullAgain
            }
        ),
        "{err:?}"
    );
    // no pull is named by a read of the committed
    assert!(e.fake.calls_of("ReadObjects")[0].get("pull").is_none());
}

/// More ranges than the driver takes are read in calls of at most its limit,
/// in order, and the sink sees the index in the whole list; one call with more
/// is an error and is not sent.
#[test]
fn read_objects_in_batches_follows_the_limit_the_driver_states() {
    let fake = Fake::start();
    fake.say(|i| i["limits"]["max_ranges"] = json!(3));
    let graph = tempfile::tempdir().unwrap();
    let e = Env {
        driver: open(&fake, graph.path(), Duration::from_secs(5)).unwrap(),
        fake,
        graph,
    };
    serve_reads(&e);
    let ranges: Vec<ObjectRange> = (0..7)
        .map(|i| ObjectRange {
            key: format!("k{i}"),
            offset: i,
            length: 4,
        })
        .collect();
    let mut got = vec![Vec::new(); 7];
    velarx_graph::read_objects_in_batches(&e.driver, &ranges, &mut |i: usize, b: &[u8]| {
        got[i].extend_from_slice(b);
        Ok(())
    })
    .unwrap();
    for (r, g) in ranges.iter().zip(&got) {
        assert_eq!(g, &bytes_of(r));
    }
    let sizes: Vec<usize> = e
        .fake
        .calls_of("ReadObjects")
        .iter()
        .map(|c| c["ranges"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes, [3, 3, 1]);
    let before = e.fake.calls_of("ReadObjects").len();
    let err = expect_err(
        e.driver
            .read_objects(&ranges, &mut |_: usize, _: &[u8]| Ok(())),
        "over the limit",
    );
    assert!(err.message().contains("read_objects_in_batches"), "{err}");
    assert_eq!(e.fake.calls_of("ReadObjects").len(), before);
}

/// The files of a list that a reader takes in order are read in calls of
/// the driver's limits (up to 256 objects), not in one call each; what each
/// file holds is what a read of it alone gives; an object not in the list
/// and one asked for again are read alone, and a missing one is `NotFound`.
#[test]
fn objects_taken_in_order_are_read_in_batches() {
    let e = env();
    serve_reads(&e);
    let order: Vec<(String, u64)> = (0..600).map(|i| (format!("o{i}"), 1 + i % 7)).collect();
    let tree = velarx_fuse::view::ImageView::new(Vec::new());
    let objects = e
        .driver
        .lower(Some(Arc::new(tree)))
        .unwrap()
        .objects
        .clone();
    let opener = objects
        .ordered(&mut || order.clone())
        .expect("a varlink driver reads ahead");
    for (key, size) in &order {
        let mut f = opener.object_file(key, *size).unwrap();
        let mut got = Vec::new();
        f.read_to_end(&mut got).unwrap();
        assert_eq!(
            got,
            bytes_of(&ObjectRange::whole(key.clone(), *size)),
            "{key}"
        );
    }
    let sizes: Vec<usize> = e
        .fake
        .calls_of("ReadObjects")
        .iter()
        .map(|c| c["ranges"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes, [256, 256, 88], "one call for each batch of objects");
    assert!(e
        .fake
        .calls_of("ReadObjects")
        .iter()
        .all(|c| c.get("pull").is_none()));
    // an object asked for again, or that the list does not name, is read
    // alone (with its probe past the end: two ranges), and a missing one is
    // NotFound
    let before = e.fake.calls_of("ReadObjects").len();
    let mut again = Vec::new();
    opener
        .object_file("zz", 20)
        .unwrap()
        .read_to_end(&mut again)
        .unwrap();
    assert_eq!(again, bytes_of(&ObjectRange::whole("zz", 20)));
    let err = opener.object_file("missing", 3).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
    assert!(e.fake.calls_of("ReadObjects").len() > before);
}

/// A driver that tells the size of each object lets the batch see one that is
/// longer than its index; one that is as long, or that tells none, is taken.
#[test]
fn a_batch_refuses_an_object_longer_than_its_index_when_the_driver_tells_the_size() {
    let e = env();
    serve_reads(&e);
    let objects = |order: Vec<(String, u64)>| {
        let tree = velarx_fuse::view::ImageView::new(Vec::new());
        e.driver
            .lower(Some(Arc::new(tree)))
            .unwrap()
            .objects
            .clone()
            .ordered(&mut || order.clone())
            .expect("a varlink driver reads ahead")
    };
    for key in ["told", "plain"] {
        let opener = objects(vec![(key.to_string(), 5)]);
        let mut got = Vec::new();
        opener
            .object_file(key, 5)
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, bytes_of(&ObjectRange::whole(key, 5)), "{key}");
    }
    let opener = objects(vec![("long".to_string(), 5)]);
    let err = opener.object_file("long", 5).unwrap_err();
    assert!(
        err.to_string().contains("has 6 bytes, its index says 5"),
        "{err}"
    );
}

/// An object read ahead for the list is handed over only as the bytes the
/// list says: asked for with another size, it is an error, never the bytes of
/// the list's size.
#[test]
fn an_object_read_ahead_is_not_handed_over_with_another_size() {
    let e = env();
    serve_reads(&e);
    let order: Vec<(String, u64)> = (0..3).map(|i| (format!("o{i}"), 5)).collect();
    let tree = velarx_fuse::view::ImageView::new(Vec::new());
    let objects = e
        .driver
        .lower(Some(Arc::new(tree)))
        .unwrap()
        .objects
        .clone();
    let opener = objects
        .ordered(&mut || order.clone())
        .expect("a varlink driver reads ahead");
    // (the first brings the others ahead)
    opener.object_file("o0", 5).unwrap();
    let err = opener.object_file("o1", 6).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    let mut got = Vec::new();
    opener
        .object_file("o2", 5)
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, bytes_of(&ObjectRange::whole("o2", 5)));
}

/// A reader that does not use the list costs nothing: the list is made only
/// when the driver reads ahead (a driver of local files answers `None`).
#[test]
fn the_list_of_a_reader_is_asked_for_only_by_a_driver_that_reads_ahead() {
    let e = env();
    let tree = velarx_fuse::view::ImageView::new(Vec::new());
    let objects = e
        .driver
        .lower(Some(Arc::new(tree)))
        .unwrap()
        .objects
        .clone();
    let mut asked = 0;
    assert!(objects
        .ordered(&mut || {
            asked += 1;
            Vec::new()
        })
        .is_some());
    assert_eq!(asked, 1);
}

/// A driver that writes the bytes of a range before its reply is named as
/// having done so; one that goes silent in the middle of a range is
/// `TimedOut`.
#[test]
fn a_driver_that_breaks_the_order_of_a_read_is_named() {
    let e = env_with(Duration::from_millis(400));
    e.fake.handle(|mut c: Call, conn| {
        let pipe = std::fs::File::from(c.fds.remove(0));
        // more than a pipe holds, before any reply
        let _ = (&pipe).write_all(&vec![1u8; 4 << 20]);
        let _ = conn;
    });
    let err = expect_err(
        e.driver.read_objects(
            &[ObjectRange::whole("a", 1 << 20)],
            &mut |_: usize, _: &[u8]| Ok(()),
        ),
        "bytes first",
    );
    assert!(matches!(err.kind, DriverErrorKind::TimedOut), "{err:?}");
    assert!(err.message().contains("before its reply"), "{err}");
    // silent in the middle of the bytes
    e.fake.handle(|mut c: Call, conn| {
        let pipe = std::fs::File::from(c.fds.remove(0));
        reply(conn, &json!({"index": 0}), false, &[]);
        let _ = (&pipe).write_all(&[1u8; 10]);
        std::thread::sleep(Duration::from_secs(2));
    });
    let err = expect_err(
        e.driver.read_objects(
            &[ObjectRange::whole("a", 100)],
            &mut |_: usize, _: &[u8]| Ok(()),
        ),
        "silent",
    );
    assert!(matches!(err.kind, DriverErrorKind::TimedOut), "{err:?}");
    assert!(err.message().contains("90 short"), "{err}");
    // a pipe closed short
    e.fake.handle(|mut c: Call, conn| {
        let pipe = std::fs::File::from(c.fds.remove(0));
        reply(conn, &json!({"index": 0}), false, &[]);
        let _ = (&pipe).write_all(&[1u8; 10]);
    });
    let err = expect_err(
        e.driver.read_objects(
            &[ObjectRange::whole("a", 100)],
            &mut |_: usize, _: &[u8]| Ok(()),
        ),
        "short",
    );
    assert!(err.message().contains("closed 90 bytes short"), "{err}");
    // an answer for the wrong range
    e.fake.handle(|mut c: Call, conn| {
        let _pipe = c.fds.remove(0);
        reply(conn, &json!({"index": 1}), false, &[]);
    });
    let err = expect_err(
        e.driver
            .read_objects(&[ObjectRange::whole("a", 1)], &mut |_: usize, _: &[u8]| {
                Ok(())
            }),
        "wrong index",
    );
    assert!(err.message().contains("in the order asked"), "{err}");
}

/// The wire-side docs say the same as the interface file: the calls of the
/// table of `docs/STORAGE.md` are the methods of the definition, with the same
/// arguments and the same answers.
#[test]
fn the_interface_and_the_table_of_the_documentation_agree() {
    let doc = include_str!("../../../docs/STORAGE.md");
    let table = &doc[doc.find("| call | arguments and reply | notes |").unwrap()..];
    let table = &table[..table.find("\n\n").unwrap()];
    let definition = crate::interface::definition();
    // the methods of the definition, with their arguments and answer fields
    let mut methods: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    let mut rest = definition.as_str();
    while let Some(at) = rest.find("\nmethod ") {
        rest = &rest[at + 8..];
        let name = &rest[..rest.find('(').unwrap()];
        let args_end = matching(rest, rest.find('(').unwrap());
        let args = fields(&rest[rest.find('(').unwrap() + 1..args_end]);
        let after = &rest[args_end..];
        let reply_start = after.find("-> (").unwrap() + 3;
        let reply_end = matching(after, reply_start);
        methods.push((
            name.to_string(),
            args,
            fields(&after[reply_start + 1..reply_end]),
        ));
    }
    assert!(methods.len() >= 21, "{}", methods.len());
    let find = |n: &str| {
        methods
            .iter()
            .find(|m| m.0 == n)
            .unwrap_or_else(|| panic!("no method {n}"))
    };
    // each row of the table
    let mut covered = std::collections::HashSet::new();
    for row in table.lines().skip(2) {
        let cells: Vec<&str> = row.trim_matches('|').split('|').collect();
        let names: Vec<String> = cells[0]
            .split(',')
            .map(|n| n.trim().trim_matches('`').to_string())
            .collect();
        for name in &names {
            if !methods.iter().any(|m| &m.0 == name) {
                // (rows that stand for several calls name them in the notes:
                // the feed, which is another interface)
                assert!(
                    name == "the feed",
                    "the table names the call `{name}`, which the definition lacks"
                );
                continue;
            }
            covered.insert(name.clone());
        }
        let text = cells[1].trim().trim_matches('`');
        let Some((args, answer)) = text.split_once("->") else {
            continue;
        };
        if names.len() != 1 || !methods.iter().any(|m| m.0 == names[0]) {
            continue;
        }
        let (_, wire_args, wire_answer) = find(&names[0]);
        let doc_fields = |s: &str| -> Vec<String> {
            let s = s.trim().trim_start_matches('(').trim_end_matches(')');
            let mut out = Vec::new();
            let mut depth = 0;
            let mut cur = String::new();
            for c in s.chars() {
                match c {
                    '(' | '[' => depth += 1,
                    ')' | ']' => depth -= 1,
                    _ => {}
                }
                if c == ',' && depth == 0 {
                    out.push(std::mem::take(&mut cur));
                } else {
                    cur.push(c);
                }
            }
            out.push(cur);
            out.into_iter()
                .map(|f| {
                    let f = f.trim();
                    let name = f.split([':', ' ']).next().unwrap().trim_end_matches('?');
                    name.to_string()
                })
                .filter(|n| !n.is_empty())
                .collect()
        };
        // the store is in every call but two, and said once in the text
        let wire_args: Vec<&String> = wire_args.iter().filter(|a| *a != "store").collect();
        let mut doc_args = doc_fields(args);
        doc_args.retain(|a| a != "store");
        assert_eq!(
            doc_args.iter().collect::<Vec<_>>(),
            wire_args,
            "the arguments of {} in the table and in the definition",
            names[0]
        );
        // the answer: the fields the definition has besides progress
        let wire_answer: Vec<&String> = wire_answer.iter().filter(|a| *a != "progress").collect();
        let doc_answer = doc_fields(answer);
        assert_eq!(
            doc_answer.iter().collect::<Vec<_>>(),
            wire_answer,
            "the answer of {} in the table and in the definition",
            names[0]
        );
    }
    // every call of the definition is in the table (GetInfo has its section)
    for (name, ..) in &methods {
        if name != "GetInfo" {
            assert!(covered.contains(name), "the table lacks the call `{name}`");
        }
    }
    // GetInfo: the section lists what the definition answers
    let (_, _, info) = find("GetInfo");
    let section = &doc[doc.find("`GetInfo -> (").unwrap()..];
    let section = &section[..section.find(")`").unwrap()];
    for f in info {
        assert!(
            section.contains(f.as_str()),
            "GetInfo answers {f}, the documentation lacks it"
        );
    }
    // the errors of the section "Errors" are those of the definition
    for e in [
        "Missing",
        "Corrupt",
        "Unsupported",
        "NotFound",
        "Busy",
        "Unavailable",
        "Failed",
    ] {
        assert!(definition.contains(&format!("\nerror {e} (")), "{e}");
    }
}

/// The index of the `)` that closes the `(` at `open`.
fn matching(text: &str, open: usize) -> usize {
    let mut depth = 0;
    for (i, c) in text.char_indices().skip_while(|(i, _)| *i < open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced");
}

/// The names of the fields of a list, comments left out.
fn fields(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut cur = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        for c in line.chars() {
            match c {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                _ => {}
            }
            if c == ',' && depth == 0 {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        cur.push(' ');
    }
    out.push(cur);
    out.into_iter()
        .filter_map(|f| {
            let n = f.trim().split(':').next()?.trim().to_string();
            (!n.is_empty()).then_some(n)
        })
        .collect()
}
