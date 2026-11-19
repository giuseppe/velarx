// SPDX-License-Identifier: Apache-2.0
//! The user namespace of a container: the mappings each mode produces, the
//! allocation of automatic ranges and the checks against the ids the daemon
//! owns.  They run on a throwaway database and sub id files: no namespace is
//! created.

use std::sync::Arc;
use tempfile::TempDir;
use velarx_config::UserNamespaceConfig;
use velarx_db::{ContainerRecord, Database, ImageRecord, RecordState};
use velarx_runtime::container::ContainerConfig;
use velarx_runtime::userns::{DaemonIds, UserNamespaceManager, UsernsRequest};
use velarx_types::digest::{Algorithm, Digest};
use velarx_wire::request::IdMapping;

fn m(container_id: u32, host_id: u32, size: u32) -> IdMapping {
    IdMapping {
        container_id,
        host_id,
        size,
    }
}

/// The namespace of a rootless daemon of the user 1000.
fn rootless_ids() -> DaemonIds {
    DaemonIds {
        uid_map: vec![m(0, 1000, 1), m(1, 655360, 65536)],
        gid_map: vec![m(0, 1000, 1), m(1, 655360, 65536)],
    }
}

fn initial_ids() -> DaemonIds {
    DaemonIds {
        uid_map: vec![m(0, 0, u32::MAX)],
        gid_map: vec![m(0, 0, u32::MAX)],
    }
}

struct Fixture {
    _dir: TempDir,
    db: Database,
    manager: Arc<UserNamespaceManager>,
}

async fn fixture(ids: DaemonIds, config: UserNamespaceConfig) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let subs = "alice:655360:65536\ncontainers:786432:65536\nbob:1000000:1000\nbob:2000000:500\n";
    std::fs::write(dir.path().join("subuid"), subs).unwrap();
    std::fs::write(dir.path().join("subgid"), subs).unwrap();
    let db = Database::open_in_memory().await.unwrap();
    let manager = Arc::new(UserNamespaceManager::with_ids(
        db.clone(),
        &config,
        ids,
        dir.path().join("subuid"),
        dir.path().join("subgid"),
    ));
    Fixture {
        _dir: dir,
        db,
        manager,
    }
}

fn req(mode: &str) -> UsernsRequest {
    UsernsRequest {
        mode: mode.parse().unwrap(),
        ..Default::default()
    }
}

impl Fixture {
    /// Record a container that uses these mappings.
    async fn record(&self, id: &str, uid: Vec<IdMapping>, gid: Vec<IdMapping>) {
        let config = ContainerConfig {
            id: id.into(),
            uid_mappings: uid,
            gid_mappings: gid,
            ..Default::default()
        };
        self.record_config(id, serde_json::to_string(&config).unwrap())
            .await;
    }

    /// Record a container with this text as its configuration.
    async fn record_config(&self, id: &str, config: String) {
        let image = format!("image-{id}");
        self.db
            .insert_image(&ImageRecord {
                id: image.clone(),
                manifest_digest: Digest::of(Algorithm::Sha256, id.as_bytes()),
                config_digest: Digest::of(Algorithm::Sha256, b"cfg"),
                manifest: "{}".into(),
                config: "{}".into(),
                created_at: "2024-01-01T00:00:00Z".into(),
                is_lazy: false,
            })
            .await
            .unwrap();
        self.db
            .insert_container(&ContainerRecord {
                id: id.into(),
                name: None,
                image_id: image,
                config,
                state: RecordState::Created,
                created_at: "2024-01-01T00:00:00Z".into(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
}

/// A container whose configuration cannot be read has ranges nobody knows:
/// they are not handed out again, the allocation fails and names it.
#[tokio::test]
async fn a_container_that_cannot_be_read_stops_the_allocation() {
    let f = fixture(rootless_ids(), Default::default()).await;
    f.record("good", vec![m(0, 1, 1024)], vec![m(0, 1, 1024)])
        .await;
    f.record_config("broken", "not json".into()).await;
    let e = f.manager.resolve(&req("auto")).await.expect_err("an error");
    let text = e.to_string();
    assert!(text.contains("broken"), "{text}");
}

#[tokio::test]
async fn host_has_no_mappings() {
    let f = fixture(rootless_ids(), Default::default()).await;
    for mode in ["", "host", "default"] {
        let r = f.manager.resolve(&req(mode)).await.unwrap();
        assert_eq!(r.mode, "host");
        assert!(r.uid_mappings.is_empty() && r.gid_mappings.is_empty());
        assert!(r.reservation.is_none());
    }
}

#[tokio::test]
async fn rootless_auto_ranges_do_not_overlap_and_are_released() {
    let f = fixture(rootless_ids(), Default::default()).await;
    // Nothing is in the database yet: the reservation of the first one is
    // what keeps the second away.
    let a = f.manager.resolve(&req("auto")).await.unwrap();
    assert_eq!(a.uid_mappings, [m(0, 1, 1024)]);
    assert_eq!(a.gid_mappings, [m(0, 1, 1024)]);
    let b = f.manager.resolve(&req("auto:size=2000")).await.unwrap();
    assert_eq!(b.uid_mappings, [m(0, 1025, 2000)]);
    drop(a);
    // The range of `a` is free again (it never became a container).
    let c = f.manager.resolve(&req("auto:size=100")).await.unwrap();
    assert_eq!(c.uid_mappings, [m(0, 1, 100)]);
    // A recorded container keeps its range after the reservation is gone.
    f.record("one", b.uid_mappings.clone(), b.gid_mappings.clone())
        .await;
    drop(b);
    drop(c);
    let d = f.manager.resolve(&req("auto:size=1500")).await.unwrap();
    // the hole of 1024 ids and what follows the recorded range
    assert_eq!(d.uid_mappings, [m(0, 1, 1024), m(1024, 3025, 476)]);
    let e = f.manager.resolve(&req("auto:size=1000")).await.unwrap();
    assert_eq!(e.uid_mappings, [m(0, 3501, 1000)]);
    // Never the user's own id.
    assert!(d.uid_mappings.iter().all(|x| x.host_id >= 1));
}

#[tokio::test]
async fn auto_size_follows_the_image() {
    let f = fixture(rootless_ids(), Default::default()).await;
    let mut r = req("auto");
    r.image_max_id = 3000;
    let a = f.manager.resolve(&r).await.unwrap();
    assert_eq!(a.uid_mappings, [m(0, 1, 3000)]);
    r.mode = "auto:size=10".parse().unwrap();
    assert_eq!(
        f.manager.resolve(&r).await.unwrap().uid_mappings,
        [m(0, 3001, 10)]
    );
    r.mode = "auto".parse().unwrap();
    r.image_max_id = 70000;
    let e = f.manager.resolve(&r).await.unwrap_err().to_string();
    assert!(e.contains("70000") && e.contains("65536"), "{e}");
}

#[tokio::test]
async fn auto_runs_out_of_ids() {
    let f = fixture(rootless_ids(), Default::default()).await;
    let _all = f.manager.resolve(&req("auto:size=65536")).await.unwrap();
    let e = f
        .manager
        .resolve(&req("auto:size=1"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("no free range"), "{e}");
}

#[tokio::test]
async fn root_auto_uses_the_sub_ids_of_containers() {
    let f = fixture(initial_ids(), Default::default()).await;
    let a = f.manager.resolve(&req("auto")).await.unwrap();
    assert_eq!(a.uid_mappings, [m(0, 786432, 1024)]);
    assert_eq!(a.gid_mappings, [m(0, 786432, 1024)]);
    let b = f.manager.resolve(&req("auto:size=2000")).await.unwrap();
    assert_eq!(b.uid_mappings, [m(0, 787456, 2000)]);
    // private: allocation_size ids.
    drop((a, b));
    let p = f.manager.resolve(&req("private")).await.unwrap();
    assert_eq!(p.mode, "private");
    assert_eq!(p.uid_mappings, [m(0, 786432, 65536)]);
    // The pool is the entry of `containers`, nothing else: no room left.
    assert!(f.manager.resolve(&req("auto")).await.is_err());
}

#[tokio::test]
async fn root_without_sub_ids_says_what_to_do() {
    let f = fixture(
        initial_ids(),
        UserNamespaceConfig {
            auto_user: "nobody-here".into(),
            ..Default::default()
        },
    )
    .await;
    let e = f
        .manager
        .resolve(&req("auto"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("nobody-here") && e.contains("subuid"), "{e}");
    f.manager.resolve(&req("host")).await.unwrap();
}

#[tokio::test]
async fn configured_ranges_replace_the_sub_ids() {
    let f = fixture(
        initial_ids(),
        UserNamespaceConfig {
            uid_ranges: vec!["100000-101999".into()],
            gid_ranges: vec!["200000-201999".into()],
            ..Default::default()
        },
    )
    .await;
    let a = f.manager.resolve(&req("auto")).await.unwrap();
    assert_eq!(a.uid_mappings, [m(0, 100000, 1024)]);
    assert_eq!(a.gid_mappings, [m(0, 200000, 1024)]);
    // 976 ids are left.
    assert!(f.manager.resolve(&req("auto:size=1000")).await.is_err());
    assert_eq!(
        f.manager
            .resolve(&req("auto:size=976"))
            .await
            .unwrap()
            .uid_mappings,
        [m(0, 101024, 976)]
    );
}

#[tokio::test]
async fn keep_id_rootless() {
    let f = fixture(rootless_ids(), Default::default()).await;
    let r = f.manager.resolve(&req("keep-id")).await.unwrap();
    assert_eq!(r.mode, "keep-id");
    assert_eq!(
        r.uid_mappings,
        [m(0, 1, 1000), m(1000, 0, 1), m(1001, 1001, 64536)]
    );
    assert_eq!(r.gid_mappings, r.uid_mappings);
    assert_eq!(r.user, Some((1000, 1000)));
    let r = f
        .manager
        .resolve(&req("keep-id:uid=2000,gid=3000"))
        .await
        .unwrap();
    assert_eq!(
        r.uid_mappings,
        [m(0, 1, 2000), m(2000, 0, 1), m(2001, 2001, 63536)]
    );
    assert_eq!(
        r.gid_mappings,
        [m(0, 1, 3000), m(3000, 0, 1), m(3001, 3001, 62536)]
    );
    assert_eq!(r.user, Some((2000, 3000)));
    let r = f.manager.resolve(&req("keep-id:size=1500")).await.unwrap();
    assert_eq!(
        r.uid_mappings,
        [m(0, 1, 1000), m(1000, 0, 1), m(1001, 1001, 499)]
    );
}

#[tokio::test]
async fn keep_id_and_nomap_are_for_rootless() {
    let f = fixture(initial_ids(), Default::default()).await;
    for mode in ["keep-id", "nomap"] {
        let e = f.manager.resolve(&req(mode)).await.unwrap_err().to_string();
        assert!(e.contains("rootless"), "{e}");
    }
}

#[tokio::test]
async fn keep_id_without_sub_ids_maps_the_user_only() {
    let ids = DaemonIds {
        uid_map: vec![m(0, 1000, 1)],
        gid_map: vec![m(0, 1000, 1)],
    };
    let f = fixture(ids, Default::default()).await;
    let r = f.manager.resolve(&req("keep-id")).await.unwrap();
    assert_eq!(r.uid_mappings, [m(1000, 0, 1)]);
    assert!(f.manager.resolve(&req("nomap")).await.is_err());
    assert!(f.manager.resolve(&req("auto")).await.is_err());
}

#[tokio::test]
async fn nomap_leaves_the_user_out() {
    let f = fixture(rootless_ids(), Default::default()).await;
    let r = f.manager.resolve(&req("nomap")).await.unwrap();
    assert_eq!(r.uid_mappings, [m(0, 1, 65536)]);
    assert_eq!(r.gid_mappings, [m(0, 1, 65536)]);
}

#[tokio::test]
async fn explicit_maps_rootless_are_ids_of_the_daemon() {
    let f = fixture(rootless_ids(), Default::default()).await;
    let mut r = req("");
    r.uidmap = vec!["0:1:5000".into()];
    let ok = f.manager.resolve(&r).await.unwrap();
    assert_eq!(ok.mode, "custom");
    assert_eq!(ok.uid_mappings, [m(0, 1, 5000)]);
    assert_eq!(ok.gid_mappings, [m(0, 1, 5000)]);
    // `+` and `@`: the user and all the sub ids.
    r.uidmap = vec!["+0:@1000:1".into()];
    let ok = f.manager.resolve(&r).await.unwrap();
    // the kernel takes no line over two extents of the daemon's map
    assert_eq!(ok.uid_mappings, [m(0, 0, 1), m(1, 1, 65536)]);
    r.uidmap = vec![];
    r.gidmap = vec!["0:100:10".into()];
    let ok = f.manager.resolve(&r).await.unwrap();
    assert_eq!(
        (ok.uid_mappings.clone(), ok.gid_mappings),
        (vec![m(0, 100, 10)], vec![m(0, 100, 10)])
    );
}

#[tokio::test]
async fn explicit_maps_outside_the_daemon_ids_are_refused() {
    let f = fixture(rootless_ids(), Default::default()).await;
    for bad in [
        "0:1:99999999",
        "0:70000:1",
        "0:65536:2",
        "0:1:2:3",
        "a:b:c",
        "0:1:5,0:2:5",
    ] {
        let mut r = req("");
        r.uidmap = vec![bad.into()];
        assert!(f.manager.resolve(&r).await.is_err(), "{bad}");
    }
    let mut r = req("");
    r.uidmap = vec!["0:1:10".into(), "5:100:10".into()];
    assert!(f.manager.resolve(&r).await.is_err());
    let mut r = req("");
    r.uid_mappings = vec![m(0, 700000, 1)];
    r.gid_mappings = vec![m(0, 1, 1)];
    assert!(f.manager.resolve(&r).await.is_err());
}

#[tokio::test]
async fn userns_and_maps_exclude_each_other() {
    let f = fixture(rootless_ids(), Default::default()).await;
    let mut r = req("auto");
    r.uidmap = vec!["0:1:10".into()];
    let e = f.manager.resolve(&r).await.unwrap_err().to_string();
    assert!(e.contains("mutually exclusive"), "{e}");
    let mut r = req("private");
    r.uidmap = vec!["0:1:10".into()];
    assert_eq!(f.manager.resolve(&r).await.unwrap().mode, "custom");
}

#[tokio::test]
async fn root_may_map_any_host_id_and_the_sub_ids_of_a_user() {
    let f = fixture(initial_ids(), Default::default()).await;
    let mut r = req("");
    r.uidmap = vec!["0:300000:65536".into()];
    r.gidmap = vec!["0:400000:65536".into()];
    let ok = f.manager.resolve(&r).await.unwrap();
    assert_eq!(ok.uid_mappings, [m(0, 300000, 65536)]);
    assert_eq!(ok.gid_mappings, [m(0, 400000, 65536)]);
    r.uidmap = vec!["0:4294967000:1000".into()];
    assert!(f.manager.resolve(&r).await.is_err());
    // --subuidname: the ranges of bob, one after the other.
    let mut r = req("");
    r.subuidname = Some("bob".into());
    let ok = f.manager.resolve(&r).await.unwrap();
    assert_eq!(
        ok.uid_mappings,
        [m(0, 1000000, 1000), m(1000, 2000000, 500)]
    );
    assert_eq!(ok.gid_mappings, ok.uid_mappings);
    r.subuidname = Some("nobody-at-all".into());
    assert!(f.manager.resolve(&r).await.is_err());
    let f = fixture(rootless_ids(), Default::default()).await;
    let mut r = req("");
    r.subuidname = Some("bob".into());
    assert!(f.manager.resolve(&r).await.is_err());
}

#[tokio::test]
async fn explicit_maps_do_not_hide_from_auto() {
    // The sub ids that an explicit map of another container uses are not
    // handed out.
    let f = fixture(initial_ids(), Default::default()).await;
    f.record("hand", vec![m(0, 786432, 1000)], vec![m(0, 786432, 1000)])
        .await;
    let a = f.manager.resolve(&req("auto")).await.unwrap();
    assert_eq!(a.uid_mappings, [m(0, 787432, 1024)]);
    let mut r = req("");
    r.uidmap = vec!["0:786432:1000".into()];
    assert_eq!(
        f.manager.resolve(&r).await.unwrap().uid_mappings,
        [m(0, 786432, 1000)]
    );
}

#[tokio::test]
async fn auto_with_additional_mappings() {
    let f = fixture(rootless_ids(), Default::default()).await;
    // Container id 100 is mapped by hand to the daemon id 5; the automatic
    // range of 10 ids takes neither.
    let r = f
        .manager
        .resolve(&req("auto:size=10,uidmapping=5:2:1"))
        .await
        .unwrap();
    assert!(r.uid_mappings.contains(&m(5, 2, 1)));
    let covered: u32 = r.uid_mappings.iter().map(|x| x.size).sum();
    assert_eq!(covered, 10);
    assert!(r
        .uid_mappings
        .iter()
        .filter(|x| x.container_id != 5)
        .all(|x| x.host_id != 2));
    assert_eq!(r.gid_mappings.iter().map(|x| x.size).sum::<u32>(), 10);
}

#[tokio::test]
async fn container_and_ns_modes_carry_no_mappings() {
    let f = fixture(rootless_ids(), Default::default()).await;
    let r = f.manager.resolve(&req("container:web")).await.unwrap();
    assert_eq!(r.mode, "container:web");
    assert!(r.uid_mappings.is_empty());
    let r = f.manager.resolve(&req("ns:/proc/1/ns/user")).await.unwrap();
    assert_eq!(r.mode, "ns:/proc/1/ns/user");
    // (a text that is no choice is refused where it is read)
    for bad in ["bogus", "container:", "ns:rel"] {
        assert!(
            bad.parse::<velarx_wire::request::UsernsChoice>().is_err(),
            "{bad}"
        );
    }
    // (the options are read where the ids are known)
    assert!(f.manager.resolve(&req("auto:bogus")).await.is_err());
}

/// Concurrent creates get disjoint ranges.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_auto_allocations_are_disjoint() {
    let f = fixture(initial_ids(), Default::default()).await;
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let manager = f.manager.clone();
        tasks.push(tokio::spawn(async move {
            manager.resolve(&req("auto:size=1000")).await.unwrap()
        }));
    }
    let mut all = Vec::new();
    for t in tasks {
        all.push(t.await.unwrap());
    }
    let mut ranges: Vec<(u32, u32)> = all
        .iter()
        .flat_map(|r| {
            r.uid_mappings
                .iter()
                .map(|x| (x.host_id, x.host_id + x.size))
        })
        .collect();
    ranges.sort();
    assert_eq!(ranges.iter().map(|r| r.1 - r.0).sum::<u32>(), 32000);
    for w in ranges.windows(2) {
        assert!(w[0].1 <= w[1].0, "{ranges:?}");
    }
    assert!(ranges[0].0 >= 786432 && ranges.last().unwrap().1 <= 786432 + 65536);
    // 65 ranges of 1000 fit in the pool, the 66th does not.
    let mut held = all;
    for _ in 0..33 {
        held.push(f.manager.resolve(&req("auto:size=1000")).await.unwrap());
    }
    assert!(f.manager.resolve(&req("auto:size=1000")).await.is_err());
}

#[tokio::test]
async fn manual_allocations_are_taken_into_account() {
    let f = fixture(initial_ids(), Default::default()).await;
    let a = f.manager.allocate(Some("mine")).await.unwrap();
    assert_eq!((a.uid_start, a.uid_count), (786432, 65536));
    assert!(f.manager.resolve(&req("auto")).await.is_err());
    f.manager.release(&a.id).await.unwrap();
    assert_eq!(
        f.manager.resolve(&req("auto")).await.unwrap().uid_mappings,
        [m(0, 786432, 1024)]
    );
    let (uid, _, available, allocated) = f.manager.get_available().await.unwrap();
    assert_eq!((uid.len(), available, allocated), (1, 1, 0));
}
