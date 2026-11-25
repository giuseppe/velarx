// SPDX-License-Identifier: Apache-2.0
//! The holds of the staging directory between processes: several commands
//! on one store with no service (daemonless), each its own process with its
//! own database connection, one of them ending or dying while another goes
//! on.  Each test starts the test binary again as such a command
//! ([`the_child`], told what to do by the environment).

use crate::common::*;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use velarx_config::StorageConfig;
use velarx_content::pull::holds;
use velarx_core::services::{CheckService, GcOptions, GcService};
use velarx_db::Database;
use velarx_proto::system::CheckSpec;

const MODE: &str = "VELARX_TEST_HOLD_CHILD";
const ROOT: &str = "VELARX_TEST_HOLD_ROOT";
const DB: &str = "VELARX_TEST_HOLD_DB";
const HOST: &str = "VELARX_TEST_HOLD_HOST";
const IMAGE: &str = "VELARX_TEST_HOLD_IMAGE";

/// A store with a database in a file, which commands of other processes
/// open too.
struct Shared {
    e: Env,
    _db: tempfile::TempDir,
    db: PathBuf,
}

async fn shared() -> Shared {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    let database = Database::open(&db).await.unwrap();
    let e = env_on(
        database,
        Default::default(),
        Default::default(),
        Default::default(),
        None,
    )
    .await;
    Shared { e, _db: dir, db }
}

/// A command of another process: its lines `child: ...` arrive by
/// [`Other::says`]; it is killed when this is dropped.
struct Other {
    process: std::process::Child,
    says: mpsc::Receiver<String>,
}

impl Drop for Other {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Shared {
    fn root(&self) -> &Path {
        self.e._tmp.path()
    }

    /// Start a command that does `mode` (see [`the_child`]).
    fn other(&self, mode: &str, image: Option<&str>) -> Other {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "hold_tests::the_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MODE, mode)
            .env(ROOT, self.root())
            .env(DB, &self.db)
            .env(HOST, &self.e.host)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if let Some(image) = image {
            command.env(IMAGE, image);
        }
        let mut process = command.spawn().unwrap();
        let out = process.stdout.take().unwrap();
        let (tx, says) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                // (the first one follows the name of the test on its line)
                if let Some((_, said)) = line.split_once("child: ") {
                    let _ = tx.send(said.to_string());
                }
            }
        });
        Other { process, says }
    }

    /// The holds the staging directory has.
    fn holds(&self) -> Vec<String> {
        std::fs::read_dir(&self.e.staging)
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| holds::is_hold_name(n))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn gc(&self) -> GcService {
        gc_of(&self.e.db, &self.e.store, self.root(), &self.e.service)
    }
}

fn gc_of(
    db: &Database,
    store: &Arc<velarx_storage::FileStore>,
    root: &Path,
    service: &velarx_core::services::ImageService,
) -> GcService {
    let storage = StorageConfig {
        root: root.to_path_buf(),
        ..Default::default()
    };
    GcService::new(
        db.clone(),
        store.clone(),
        &storage,
        service.storage().clone(),
    )
}

impl Other {
    /// What the command says next (a line `child: WHAT`).
    async fn says(&self) -> String {
        for _ in 0..4000 {
            if let Ok(said) = self.says.try_recv() {
                return said;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the command said nothing");
    }

    /// Ask the command to end (it reads its input until it is closed) and
    /// wait for it.
    async fn ended(mut self) -> bool {
        drop(self.process.stdin.take());
        for _ in 0..4000 {
            if let Some(status) = self.process.try_wait().unwrap() {
                return status.success();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the command did not end");
    }

    /// Kill the command and wait for its end.
    fn killed(mut self) {
        self.process.kill().unwrap();
        self.process.wait().unwrap();
    }
}

/// The command another process runs: told by the environment what to do,
/// and doing nothing in a normal run of the tests.
///
/// - `pull`: pull the image of the registry and say its id;
/// - `check`: check the store, and say the kinds of the problems;
/// - `churn`: check with a repair, and collect, until its input is closed;
/// - `sweep`: sweep the holds of the staging directory until its input is
///   closed;
/// - `join`: join the holds of the staging directory in `ROOT` it is told
///   of, and let go when told;
/// - `probe`: look for holds nobody holds in the staging directory in `ROOT`
///   until its input is closed, and say how many it found;
/// - `build`: make the hold of a build that pins the image in `IMAGE`, and
///   hold it until its input is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_child() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let var = |name| PathBuf::from(std::env::var_os(name).unwrap());
    if mode == "join" {
        // (no service: it joins the holds it is told of, and lets go on
        // being told)
        let mut input = std::io::stdin().lines().map_while(Result::ok);
        let staging = var(ROOT);
        while let Some(name) = input.next() {
            let hold = holds::Hold::join(&staging, &name).unwrap();
            println!("child: joined");
            // (it works in the directory until it is told)
            assert!(hold.path().join(holds::PINS).exists());
            let _ = input.next();
            drop(hold);
            println!("child: let go");
        }
        std::process::exit(0);
    }
    if mode == "probe" {
        // (no service: it looks at the holds of the staging directory all
        // the time, and says each one that looks unheld)
        let staging = var(ROOT);
        let open = Arc::new(std::sync::atomic::AtomicBool::new(true));
        {
            let open = open.clone();
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
                open.store(false, Ordering::SeqCst);
            });
        }
        println!("child: probing");
        let mut seen = 0;
        while open.load(Ordering::SeqCst) {
            seen += holds::stale(&staging).unwrap().len();
        }
        println!("child: seen {seen}");
        std::process::exit(0);
    }
    let (root, db) = (var(ROOT), var(DB));
    let host = std::env::var(HOST).unwrap();
    let (service, database, store) = service_on(&root, &db, &host).await;
    let staging = root.join("staging");
    let open = Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let open = open.clone();
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
            open.store(false, Ordering::SeqCst);
        });
    }
    let checker = || {
        CheckService::new(
            database.clone(),
            Arc::new(service.clone()),
            store.clone(),
            staging.clone(),
        )
    };
    match mode.as_str() {
        "pull" => {
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            let image = format!("{host}/test:latest");
            let pulled = service
                .pull_with_client(&client_for(&[&host]), &image, tx)
                .await
                .unwrap();
            println!("child: {}", pulled.id);
        }
        "check" => {
            let report = checker()
                .check(&CheckSpec {
                    quick: true,
                    ..Default::default()
                })
                .await
                .unwrap();
            let mut kinds: Vec<_> = report.problems.iter().map(|p| p.kind.clone()).collect();
            kinds.sort();
            println!("child: {}", kinds.join(","));
        }
        "churn" => {
            let gc = gc_of(&database, &store, &root, &service);
            while open.load(Ordering::SeqCst) {
                checker()
                    .check(&CheckSpec {
                        quick: true,
                        repair: true,
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                gc.collect(GcOptions {
                    wait: false,
                    ..Default::default()
                })
                .await
                .unwrap();
                println!("child: round");
            }
        }
        "sweep" => {
            println!("child: sweeping");
            while open.load(Ordering::SeqCst) {
                holds::sweep(&staging);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        "build" => {
            let hold = service.hold_build().unwrap();
            let pinned = service
                .build_cache_get(velarx_db::BUILD_SCRATCH, "step", hold.name())
                .await
                .unwrap();
            assert_eq!(pinned, std::env::var(IMAGE).ok());
            println!("child: pinned");
            while open.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            drop(hold);
        }
        other => panic!("no command {other}"),
    }
    // (the service owns a runtime: never dropped from here)
    std::process::exit(0);
}

fn layer(name: &'static str, data: &[u8]) -> Built {
    build_chunked(&[
        Item::Dir("etc/"),
        Item::File {
            name,
            data: data.to_vec(),
            chunk: 4096,
        },
    ])
}

/// Every file the layers of the image reference is in the store.
async fn all_files_stored(e: &Env, image: &str) {
    let layers = e.db.get_image_layers(image).await.unwrap();
    assert!(!layers.is_empty());
    for l in layers {
        let toc = stored_toc(&e.db, &l.key).await;
        for entry in &toc.entries {
            if let Some(d) = entry.verity() {
                assert!(e.store.contains(&d), "{} of {} is gone", entry.name, l.key);
            }
        }
    }
}

/// Pull the image of the environment in this process, in the background.
fn pulling(
    e: &Env,
) -> tokio::task::JoinHandle<Result<velarx_core::services::PullResult, velarx_types::ImageError>> {
    let (service, client, image) = (
        (*e.service).clone(),
        e.client(),
        format!("{}/test:latest", e.host),
    );
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        service.pull_with_client(&client, &image, tx).await
    })
}

/// A pull held after it took its hold: a check in another process finds
/// nothing to say about its staging directory, however often it looks; and
/// when the pull has ended nothing is left, though the fetcher it started
/// still runs (it holds no descriptor of the hold).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_check_of_another_process_leaves_a_pull_in_progress_alone() {
    let s = shared().await;
    let l = layer("etc/a", &[1u8; 20_000]);
    s.e.publish(&[&l], &[ZSTD]);
    s.e.reg.delay_ms.store(2000, Ordering::SeqCst);
    let pull = pulling(&s.e);
    let blob = sha(&l.blob);
    poll_until("the pull fetches the layer, held", || async {
        s.e.reg.hits.lock().unwrap().contains_key(&blob) && !s.holds().is_empty()
    })
    .await;
    for _ in 0..3 {
        let check = s.other("check", None);
        assert_eq!(check.says().await, "");
        assert!(check.ended().await);
        assert!(!pull.is_finished(), "the pull ended before the checks did");
    }
    s.e.reg.delay_ms.store(0, Ordering::SeqCst);
    let pulled = pull.await.unwrap().unwrap();
    all_files_stored(&s.e, &pulled.id).await;
    assert!(s.holds().is_empty(), "{:?}", s.holds());
}

/// The process of a pull is killed: its hold is stale at once, the check
/// reports it and the repair removes it; its pins stop pinning, and the
/// collection frees what they kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hold_of_a_pull_that_was_killed_is_found_and_removed() {
    let s = shared().await;
    let shared_layer = layer("etc/shared", &[3u8; 20_000]);
    s.e.publish(&[&shared_layer], &[ZSTD]);
    let first = s.e.pull().await.unwrap();
    // (stored, and no image uses it: the row alone is removed)
    s.e.db.delete_image(&first.id).await.unwrap();
    let new = layer("etc/new", &[4u8; 20_000]);
    s.e.publish(&[&shared_layer, &new], &[ZSTD, ZSTD]);
    s.e.reg.delay_ms.store(2000, Ordering::SeqCst);
    let pull = s.other("pull", None);
    poll_until("the pull holds the layers it found", || async {
        holds::pinned(&s.e.staging)
            .unwrap()
            .layers
            .contains(&shared_layer.key().to_string())
    })
    .await;

    // alive: nothing to report, and the collection leaves what it pins
    let stale = |report: &velarx_proto::system::CheckReport| {
        report
            .problems
            .iter()
            .filter(|p| p.kind == "stale_staging")
            .count()
    };
    let checker = CheckService::new(
        s.e.db.clone(),
        Arc::new((*s.e.service).clone()),
        s.e.store.clone(),
        s.e.staging.clone(),
    );
    let spec = |repair| CheckSpec {
        quick: true,
        repair,
        ..Default::default()
    };
    assert_eq!(stale(&checker.check(&spec(false)).await.unwrap()), 0);
    let report = s.gc().collect(GcOptions::default()).await.unwrap();
    assert_eq!((report.layers_removed, report.staging_removed), (0, 0));
    assert_eq!(s.holds().len(), 1);

    pull.killed();
    s.e.reg.delay_ms.store(0, Ordering::SeqCst);
    assert_eq!(stale(&checker.check(&spec(false)).await.unwrap()), 1);
    let repaired = checker.check(&spec(true)).await.unwrap();
    assert_eq!(stale(&repaired), 1);
    assert!(s.holds().is_empty());
    let report = s.gc().collect(GcOptions::default()).await.unwrap();
    assert_eq!(report.layers_removed, 1, "what the dead pull pinned goes");
}

/// A collection and a repair that run again and again in another process
/// never take from a pull of this one what it is about to use: each pull
/// ends, with its files in the store, whether the layers it finds there are
/// pinned in time or not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repair_and_a_collection_never_take_what_a_starting_pull_uses() {
    let s = shared().await;
    let l = layer("etc/race", &[7u8; 20_000]);
    s.e.publish(&[&l], &[ZSTD]);
    let id = s.e.pull().await.unwrap().id;
    let churn = s.other("churn", None);
    assert_eq!(churn.says().await, "round");
    for i in 0..300 {
        // (stored, and no image uses it)
        s.e.db.delete_image(&id).await.unwrap();
        let pulled =
            s.e.pull()
                .await
                .unwrap_or_else(|e| panic!("the pull {i} failed: {e}"));
        assert_eq!(pulled.id, id);
        all_files_stored(&s.e, &id).await;
    }
    assert!(churn.ended().await);
}

/// Two processes pull one image at once: both end with the image, and
/// neither of them has its pins collected by a collection that runs
/// meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_pull_one_image() {
    let s = shared().await;
    let l = layer("etc/two", &[9u8; 20_000]);
    let m = layer("etc/two-more", &[8u8; 20_000]);
    s.e.publish(&[&l, &m], &[ZSTD, ZSTD]);
    s.e.reg.delay_ms.store(300, Ordering::SeqCst);
    let (a, b) = (s.other("pull", None), s.other("pull", None));
    let gc = s.gc();
    let (mut said_a, mut said_b) = (None, None);
    for _ in 0..4000 {
        if said_a.is_none() {
            said_a = a.says.try_recv().ok();
        }
        if said_b.is_none() {
            said_b = b.says.try_recv().ok();
        }
        if said_a.is_some() && said_b.is_some() {
            break;
        }
        let report = gc
            .collect(GcOptions {
                wait: false,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(report.layers_removed, 0);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let id = said_a.expect("the first pull ended");
    assert_eq!(Some(&id), said_b.as_ref());
    assert!(a.ended().await && b.ended().await);
    all_files_stored(&s.e, &id).await;
    assert!(s.holds().is_empty(), "{:?}", s.holds());
}

/// An image a build of another process pins is not pruned while that
/// process lives, and is once it is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prune_leaves_what_a_build_of_another_process_pins() {
    let s = shared().await;
    let l = layer("etc/b", &[6u8; 20_000]);
    s.e.publish(&[&l], &[ZSTD]);
    let id = s.e.pull().await.unwrap().id;
    s.e.service
        .build_cache_put(velarx_db::BUILD_SCRATCH, "step", &id)
        .await
        .unwrap();
    let build = s.other("build", Some(&id));
    assert_eq!(build.says().await, "pinned");
    assert!(s.e.service.prune(true, &[]).await.unwrap().is_empty());
    assert!(s.e.service.prune_build_cache().await.unwrap().0.is_empty());
    build.killed();
    let pruned = s.e.service.prune(true, &[]).await.unwrap();
    assert_eq!(pruned.len(), 1);
    assert_eq!(pruned[0].0, id);
}

/// A process that sweeps the staging directory all the time never removes
/// the directory of a hold being made here: each is whole when it is
/// returned and pins what it is asked to, while a hold nobody has is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hold_is_never_swept_from_under_the_process_that_makes_it() {
    let s = shared().await;
    std::fs::create_dir_all(&s.e.staging).unwrap();
    let sweeper = s.other("sweep", None);
    assert_eq!(sweeper.says().await, "sweeping");
    let dead = s.e.staging.join("pull-0000dead");
    std::fs::create_dir_all(dead.join("sub")).unwrap();
    for i in 0..400 {
        let hold = holds::Hold::create(&s.e.staging, &format!("pull-{i:08x}")).unwrap();
        hold.pin(holds::LAYER, [i]).unwrap();
        std::thread::sleep(Duration::from_millis(1));
        let pins = std::fs::read_to_string(hold.path().join(holds::PINS)).unwrap();
        assert_eq!(pins, format!("layer {i}\n"));
    }
    poll_until("the sweeper removes what nobody holds", || async {
        !dead.exists()
    })
    .await;
    assert!(sweeper.ended().await);
}

/// A commit in progress is no staging directory of a pull that is gone: a
/// check that looks while it runs reports nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_check_does_not_report_a_commit_in_progress() {
    let s = shared().await;
    let l = layer("etc/c", &[2u8; 20_000]);
    s.e.publish(&[&l], &[ZSTD]);
    s.e.pull().await.unwrap();
    // (a file to read for a while)
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    std::fs::write(dir.path().join("big"), vec![0x5au8; 512 << 20]).unwrap();
    let service = (*s.e.service).clone();
    let path = dir.path().to_path_buf();
    let commit = tokio::spawn(async move {
        service
            .commit_dir(None, Some(&path), &Default::default())
            .await
    });
    let checker = CheckService::new(
        s.e.db.clone(),
        Arc::new((*s.e.service).clone()),
        s.e.store.clone(),
        s.e.staging.clone(),
    );
    let mut looked = 0;
    while !commit.is_finished() {
        let report = checker
            .check(&CheckSpec {
                quick: true,
                ..Default::default()
            })
            .await
            .unwrap();
        if !commit.is_finished() {
            looked += 1;
            assert!(
                report.problems.iter().all(|p| p.kind != "stale_staging"),
                "{:?}",
                report.problems
            );
        }
    }
    commit.await.unwrap().unwrap();
    assert!(looked > 0, "the commit ended before a check looked");
}

/// Two users of one hold, in two processes, let go at the same instant, many
/// times: the directory is gone when both have, and is never removed while
/// one of them still works in it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_letting_go_of_a_hold_at_once_leave_none() {
    use std::io::Write;
    let s = shared().await;
    std::fs::create_dir_all(&s.e.staging).unwrap();
    let mut other = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hold_tests::the_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "join")
        .env(ROOT, &s.e.staging)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = other.stdin.take().unwrap();
    let out = other.stdout.take().unwrap();
    let (tx, says) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if let Some((_, said)) = line.split_once("child: ") {
                let _ = tx.send(said.to_string());
            }
        }
    });
    let other = Other {
        process: other,
        says,
    };
    for round in 0..300 {
        let name = format!("pull-{round:08x}");
        let mine = holds::Hold::create(&s.e.staging, &name).unwrap();
        writeln!(input, "{name}").unwrap();
        assert_eq!(other.says().await, "joined");
        if round % 2 == 0 {
            // one lets go, the other works: the hold stays, whole
            drop(mine);
            assert!(s.e.staging.join(&name).join(holds::PINS).exists());
            assert!(holds::any_live(&s.e.staging).unwrap());
            writeln!(input, "go").unwrap();
        } else {
            // both at once
            writeln!(input, "go").unwrap();
            drop(mine);
        }
        assert_eq!(other.says().await, "let go");
        assert!(
            !s.e.staging.join(&name).exists(),
            "the hold {name} is left after both let go"
        );
    }
    drop(input);
    assert!(other.ended().await);
    assert!(s.holds().is_empty());
}

/// A process that probes all the time never takes for unheld a hold whose
/// only user is in the middle of letting go of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_probe_never_sees_a_hold_being_let_go_of_as_unheld() {
    let s = shared().await;
    std::fs::create_dir_all(&s.e.staging).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "hold_tests::the_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "probe")
        .env(ROOT, &s.e.staging)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut process = command.spawn().unwrap();
    let out = process.stdout.take().unwrap();
    let (tx, says) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if let Some((_, said)) = line.split_once("child: ") {
                let _ = tx.send(said.to_string());
            }
        }
    });
    let probing = Other { process, says };
    assert_eq!(probing.says().await, "probing");
    for round in 0..3000 {
        let hold = holds::Hold::create(&s.e.staging, &format!("pull-{round:08x}")).unwrap();
        hold.pin(holds::LAYER, [round]).unwrap();
        drop(hold);
    }
    let mut probing = probing;
    drop(probing.process.stdin.take());
    assert_eq!(probing.says().await, "seen 0");
    assert!(probing.ended().await);
}
