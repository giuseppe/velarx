// SPDX-License-Identifier: Apache-2.0
//! Pulls through confined workers: the same images, and the checks that the
//! daemon makes of what the workers send.

use crate::common::*;
use axum::http::{header, StatusCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// What starts the workers of `registry_bin()`: a process forked while the test
/// binary has no other thread running tests (the one of every test).
pub fn spawner() -> std::sync::Arc<velarx_sys::spawner::Spawner> {
    static SPAWNER: std::sync::OnceLock<std::sync::Arc<velarx_sys::spawner::Spawner>> =
        std::sync::OnceLock::new();
    SPAWNER
        .get_or_init(|| {
            std::sync::Arc::new(
                velarx_sys::spawner::Spawner::start_beside_idle_threads(
                    vec![
                        velarx_registry_lib::net::pool::worker_program(std::path::Path::new(
                            registry_bin(),
                        ))
                        .expect("the worker program"),
                    ],
                    |_| Ok(()),
                )
                .expect("the worker spawner"),
            )
        })
        .clone()
}

#[tokio::test]
async fn test_chunked_and_gzip_layers_through_workers() {
    let e = env().await;
    let chunked = build_chunked(&sample());
    let gzip = build_gzip(&sample()[..2]);
    e.publish(&[&gzip, &chunked], &[GZIP, ZSTD]);
    let result = e.pull().await.unwrap();
    assert!(e.reg.ranged.load(Ordering::SeqCst) > 0, "no range request");
    let image = e.service.get(&result.id).await.unwrap();
    assert!(!image.is_lazy);
    for l in [&gzip, &chunked] {
        let rec = e.db.get_layer(&l.key()).await.unwrap();
        assert_eq!(rec.status, "ready");
        // (a layer of a table of contents has no diff id of its own)
        assert_eq!(
            rec.diff_id.as_ref(),
            (!l.key().is_toc()).then_some(&l.diff_id)
        );
    }
    assert!(e.store.contains(&vid(b"hello\n")));
    assert_eq!(e.staged_leftovers(), 0);
    assert_eq!(
        e.reg.mine.load(Ordering::SeqCst),
        0,
        "the daemon connected itself"
    );
}

/// The front of the registry fetcher, confined as it is for a store (the
/// staging handed as a descriptor), tries from inside what that allows and
/// refuses, and so does a worker its spawner starts for it, which narrows the domain to the
/// TCP port it is given: files beneath the staging only, no other program,
/// no signal out of the domain, no TCP bind, and the worker no TCP
/// connection but to its port.
#[test]
fn test_the_front_and_its_worker_try_their_confinement_from_inside() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("staging")).unwrap();
    let out = std::process::Command::new("sh")
        .args([
            "-c",
            "exec \"$0\" --config \"$1/none.toml\" --staging-fd 5 --self-test 5<\"$1/staging\"",
        ])
        .arg(registry_bin())
        .arg(dir.path())
        .env_clear()
        .env("HOME", dir.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    let results: Vec<(String, bool)> = serde_json::from_slice(&out.stdout).unwrap();
    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
    assert!(failed.is_empty(), "{failed:?}");
    for want in [
        "makes a file beneath the staging",
        "makes nothing next to the staging",
        "executes nothing",
        "starts no process",
        "makes no namespace",
        "signals no process outside its domain",
        "binds no TCP port",
        "connects to no TCP port",
        "connects to no UNIX socket by name",
        "worker: connect to a TCP port it was not given",
        "worker: connect to a TCP port it was given",
        "worker: signal the daemon",
        "worker: create a file",
        "worker: execve",
    ] {
        assert!(
            results.iter().any(|(w, _)| w == want),
            "{want}: {results:?}"
        );
    }
}

/// The fetcher of a directory (`velarx-dir`), confined as it is for a
/// store, tries from inside what that allows and refuses: files beneath the
/// staging only, nothing written in the directory it reads, no program, no
/// process, no namespace, no TCP port, no UNIX socket by name.
#[test]
fn test_the_directory_fetcher_tries_its_confinement_from_inside() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("staging")).unwrap();
    std::fs::create_dir(dir.path().join("items")).unwrap();
    let out = std::process::Command::new("sh")
        .args([
            "-c",
            "exec \"$0\" --name d --dir \"$1/items\" --staging-fd 5 --self-test 5<\"$1/staging\"",
        ])
        .arg(dir_bin())
        .arg(dir.path())
        .env_clear()
        .env("HOME", dir.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    let results: Vec<(String, bool)> = serde_json::from_slice(&out.stdout).unwrap();
    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
    assert!(failed.is_empty(), "{failed:?}");
    for want in [
        "makes a file beneath the staging",
        "makes nothing next to the staging",
        "executes nothing",
        "starts no process",
        "makes no namespace",
        "binds no TCP port",
        "connects to no TCP port",
        "connects to no UNIX socket by name",
        "reads the directory it serves",
        "writes nothing in the directory it serves",
    ] {
        assert!(
            results.iter().any(|(w, _)| w == want),
            "{want}: {results:?}"
        );
    }
}

/// The pusher of a path (`velarx-dir --push`), confined as it is for a push,
/// tries from inside what that allows and refuses: files beneath the
/// destination it was handed only (an archive: only the file it was
/// handed), no program, no process, no namespace, no TCP port, no UNIX
/// socket by name, and nothing written outside the destination.
#[test]
fn test_the_directory_pusher_tries_its_confinement_from_inside() {
    for mode in ["oci:", "dir:", "oci-archive:"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("dest")).unwrap();
        std::fs::write(dir.path().join("file"), b"").unwrap();
        let dest = if mode == "oci-archive:" {
            "file"
        } else {
            "dest"
        };
        // (a directory is opened for reading, the archive for writing)
        let redirect = if mode == "oci-archive:" { "<>" } else { "<" };
        let script = format!("exec \"$0\" --push --self-test {mode} 5{redirect}\"$1/{dest}\"");
        let out = std::process::Command::new("sh")
            .args(["-c", &script])
            .arg(dir_bin())
            .arg(dir.path())
            .env_clear()
            .env("HOME", dir.path())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{mode}: {text}");
        let results: Vec<(String, bool)> = serde_json::from_slice(&out.stdout).unwrap();
        let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
        assert!(failed.is_empty(), "{mode}: {failed:?}");
        let mut want = vec![
            "executes nothing",
            "starts no process",
            "makes no namespace",
            "binds no TCP port",
            "connects to no TCP port",
            "creates no file by a name",
            "reads nothing it does not need",
        ];
        if mode == "oci-archive:" {
            want.push("writes the file it was handed");
        } else {
            want.extend([
                "makes a file beneath the staging",
                "makes nothing next to the staging",
                "connects to no UNIX socket by name",
            ]);
        }
        for want in want {
            assert!(
                results.iter().any(|(w, _)| w == want),
                "{mode} {want}: {results:?}"
            );
        }
    }
}

/// The origin of a path (`velarx-dir --origin`), confined as it is for a
/// pull, tries from inside what that allows and refuses: files beneath the
/// staging only, the directory or the file it was handed read and nothing
/// else of the file system, no program, no process, no namespace, no TCP
/// port, no UNIX socket by name.
#[test]
fn test_the_origin_of_a_path_tries_its_confinement_from_inside() {
    for scheme in ["oci:", "oci-archive:"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("staging")).unwrap();
        std::fs::create_dir(dir.path().join("layout")).unwrap();
        std::fs::write(dir.path().join("layout/index.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("archive"), b"x").unwrap();
        let target = if scheme == "oci:" {
            "layout"
        } else {
            "archive"
        };
        let script = format!(
            "exec \"$0\" --origin --staging-fd 6 --self-test {scheme} 5<\"$1/{target}\" 6<\"$1/staging\""
        );
        let out = std::process::Command::new("sh")
            .args(["-c", &script])
            .arg(dir_bin())
            .arg(dir.path())
            .env_clear()
            .env("HOME", dir.path())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{scheme}: {text}");
        let results: Vec<(String, bool)> = serde_json::from_slice(&out.stdout).unwrap();
        let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
        assert!(failed.is_empty(), "{scheme}: {failed:?}");
        for want in [
            "makes a file beneath the staging",
            "makes nothing next to the staging",
            "executes nothing",
            "starts no process",
            "makes no namespace",
            "binds no TCP port",
            "connects to no TCP port",
            "connects to no UNIX socket by name",
            "opens no file outside its origin",
            "writes nothing in its origin",
            if scheme == "oci:" {
                "reads the directory it was handed"
            } else {
                "reads the file it was handed"
            },
        ] {
            assert!(
                results.iter().any(|(w, _)| w == want),
                "{scheme} {want}: {results:?}"
            );
        }
    }
}

/// The engine starts the fetcher of a directory as a process of its own with
/// a connection handed to it ([`velarx_content::list::private_dir`]): it
/// answers on it under the name it was given, and ends with the connection.
#[test]
fn test_the_engine_starts_a_directory_fetcher_with_a_connection_of_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = velarx_config::Config::default();
    config.storage.root = dir.path().join("storage");
    config.pull.dir_path = Some(dir_bin().into());
    let items = dir.path().join("items");
    std::fs::create_dir(&items).unwrap();
    let velarx_content::list::Private { stream, mut child } =
        velarx_content::list::private_dir(&config, "mirror", &items).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut conn = velarx_content::fetcher::fetch_client::FetchConn::new(stream).unwrap();
        let info = conn.get_info().await.unwrap();
        assert_eq!(info.name, "mirror");
    });
    assert!(child.wait().unwrap().success());
}

/// The pusher of a path learns its destination from `Open` and confines
/// itself there: before `Open` the process has no seccomp filter, after it
/// has; a destination that is not a path is refused and leaves it as it was.
#[test]
fn test_the_directory_pusher_confines_itself_at_open() {
    use velarx_content::pusher::push_client::PushScoping;
    let seccomp = |pid: u32| {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("Seccomp:").map(|v| v.trim().to_string()))
            .unwrap()
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = velarx_config::Config::default();
    config.storage.root = dir.path().join("storage");
    config.pull.dir_path = Some(dir_bin().into());
    let dest = dir.path().join("dest");
    std::fs::create_dir(&dest).unwrap();
    let velarx_content::list::Private { stream, mut child } =
        velarx_content::list::private_dir_origin(&config, velarx_content::list::Direction::Push)
            .unwrap();
    let pid = child.id();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut conn = velarx_content::fetcher::fetch_client::FetchConn::new(stream).unwrap();
        conn.push_get_info().await.unwrap();
        assert_eq!(seccomp(pid), "0", "no filter before Open");
        let scoping =
            |destination: &'static str, target: Option<std::os::fd::OwnedFd>| PushScoping {
                destination,
                tls_verify: None,
                target,
                access: None,
                idle: std::time::Duration::from_secs(30),
                requires: &[],
            };
        let target: std::os::fd::OwnedFd = std::fs::File::open(&dest).unwrap().into();
        // (a destination that names no path: refused, still unconfined)
        let refused = conn
            .push_open(scoping(
                "registry.example/x",
                Some(target.try_clone().unwrap()),
            ))
            .await;
        assert!(refused.is_err());
        assert_eq!(seccomp(pid), "0", "a refused Open confines nothing");
        conn.push_open(scoping("oci:", Some(target))).await.unwrap();
        assert_eq!(seccomp(pid), "2", "the filter is there once Open answered");
    });
    drop(runtime);
    let _ = child.wait();
}

/// Run the worker's self-test with ARGS and ENV: whether it started, and
/// its results (or its error).
fn self_test(args: &[&str], env: &[(&str, &str)]) -> (bool, Vec<(String, bool)>, String) {
    let mut cmd = std::process::Command::new(registry_bin());
    cmd.args(["pull-worker", "--self-test"]).args(args);
    run_self_test(cmd, env)
}

/// [`self_test`] of the command CMD, which starts the worker.
fn run_self_test(
    mut cmd: std::process::Command,
    env: &[(&str, &str)],
) -> (bool, Vec<(String, bool)>, String) {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    let (mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let theirs: OwnedFd = theirs.into();
    let mut child = cmd
        .env_clear()
        .envs(env.iter().copied())
        .stdin(std::process::Stdio::from(theirs))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // (the socket of the worker is held by the command until it is dropped)
    drop(cmd);
    let mut reply = Vec::new();
    (&mine).read_to_end(&mut reply).unwrap();
    let ok = child.wait().unwrap().success();
    let text = String::from_utf8_lossy(reply.get(24..).unwrap_or_default()).into_owned();
    // A reply frame: kind, three zero bytes, the lengths, the JSON.
    let results = if reply.first() == Some(&3) {
        serde_json::from_slice(&reply[24..]).unwrap()
    } else {
        Vec::new()
    };
    (ok, results, text)
}

/// What the worker cannot do once it is confined, tried by the worker.
#[test]
fn test_the_worker_is_confined() {
    let (ok, results, text) = self_test(&[], &[]);
    assert!(ok, "{text}");
    assert!(results.len() > 15, "{text}");
    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
    assert!(failed.is_empty(), "{failed:?}");
    assert!(
        results
            .iter()
            .any(|(w, _)| w == "a user namespace of its own"),
        "{text}"
    );
}

/// The command `sh -c SCRIPT` of the worker in a user namespace that is
/// allowed to make no other: the kernel refuses (ENOSPC) the user namespace
/// the worker asks for, as one that has none to give does.
fn where_no_user_namespace_is_left(script: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new("unshare");
    cmd.args(["-Ur", "sh", "-c"])
        .arg(format!(
            "echo 0 > /proc/sys/user/max_user_namespaces && {script}"
        ))
        .arg(registry_bin());
    cmd
}

/// A kernel that refuses user namespaces: the worker is confined without
/// one and says so, unless one is required.
#[test]
fn test_a_worker_without_a_user_namespace() {
    let (ok, results, text) = run_self_test(
        where_no_user_namespace_is_left("exec \"$0\" pull-worker --self-test"),
        &[],
    );
    assert!(ok, "{text}");
    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
    assert!(failed.is_empty(), "{failed:?}");
    assert!(
        results
            .iter()
            .any(|(w, _)| w == "no user namespace: the kernel refused it"),
        "{text}"
    );
    let (ok, _, text) = run_self_test(
        where_no_user_namespace_is_left("exec \"$0\" pull-worker --self-test --require-userns"),
        &[],
    );
    assert!(!ok);
    assert!(text.contains("require_userns"), "{text}");
}

/// A worker that cannot confine itself tells the daemon why on its socket,
/// whichever descriptors it was started with (here one on descriptor 3,
/// which the socket cannot take then).
#[test]
fn test_a_worker_that_cannot_confine_itself_says_why_with_a_descriptor_on_3() {
    let cmd = where_no_user_namespace_is_left(
        "exec \"$0\" pull-worker --self-test --require-userns 3</dev/null",
    );
    let (ok, _, text) = run_self_test(cmd, &[]);
    assert!(!ok);
    assert!(text.contains("require_userns"), "{text}");
}

#[tokio::test]
async fn test_a_missing_worker_fails_the_pull_without_leaving_anything() {
    let e = env_with(velarx_config::PullConfig {
        worker_path: Some("/nonexistent/velarx".into()),
        ..Default::default()
    })
    .await;
    e.publish(&[&build_gzip(&sample())], &[GZIP]);
    // (the fetcher cannot open its worker when it starts, as the spawner
    // holds the program open from the start: the pull is the error of a
    // fetcher that is not there)
    e.pull().await.unwrap_err();
    assert!(e.db.list_images().await.unwrap().is_empty());
    assert_eq!(e.staged_leftovers(), 0);
}

/// A server on 127.0.0.1 that answers every request with RESPONSE.
fn http_server(response: &'static [u8]) -> u16 {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(response);
        }
    });
    port
}

/// A URL is downloaded by a confined worker: the body, Last-Modified, the
/// limit, an error status.
#[tokio::test]
async fn test_urls_through_a_confined_worker() {
    use velarx_registry_lib::net::url::Fetcher;
    let ok = http_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nConnection: close\r\n\r\nhello",
    );
    let missing =
        http_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let f = Fetcher::new(spawner(), &Default::default());
    let mut got = Vec::new();
    let t = f
        .fetch(&format!("http://127.0.0.1:{ok}/f"), 100, &mut |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(got, b"hello");
    assert_eq!(t.size, 5);
    assert_eq!(
        t.last_modified.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    let e = f
        .fetch(&format!("http://127.0.0.1:{ok}/f"), 3, &mut |_| Ok(()))
        .await
        .unwrap_err();
    assert!(
        matches!(e, velarx_content::pull::net::origin::UrlError::TooLarge(3)),
        "{e}"
    );
    let e = f
        .fetch(&format!("http://127.0.0.1:{missing}/f"), 100, &mut |_| {
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(e.to_string().contains("404"), "{e}");
    let e = f
        .fetch("file:///etc/passwd", 100, &mut |_| Ok(()))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("scheme"), "{e}");
}

/// The URLs of the engine (an import, an ADD, a remote context) are read by
/// the registry fetcher process: the body and its Last-Modified, the limit,
/// a 404, and no scheme but http and https.
#[tokio::test]
async fn test_urls_through_the_registry_fetcher() {
    let ok = http_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nLast-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nConnection: close\r\n\r\nhello",
    );
    let missing =
        http_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let e = env().await;
    let f = e.service.url_fetcher().unwrap();
    let mut got = Vec::new();
    let t = f
        .fetch(&format!("http://127.0.0.1:{ok}/f"), 100, &mut |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(got, b"hello");
    assert_eq!(t.size, 5);
    assert_eq!(
        t.last_modified.as_deref(),
        Some("Wed, 21 Oct 2015 07:28:00 GMT")
    );
    let err = f
        .fetch(&format!("http://127.0.0.1:{ok}/f"), 3, &mut |_| Ok(()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("larger than 3"), "{err}");
    let none = f
        .fetch_opt(&format!("http://127.0.0.1:{missing}/f"), 100, &mut |_| {
            Ok(())
        })
        .await
        .unwrap();
    assert!(none.is_none());
    let err = f
        .fetch("file:///etc/passwd", 100, &mut |_| Ok(()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("http or https"), "{err}");
}

/// A URL whose server sends a byte now and then is given up by the minimum
/// speed it was given (`[pull] min_speed_kib`), by a confined worker: the
/// speed is the configured one, not a constant.
#[tokio::test]
async fn test_a_url_that_trickles_is_given_up_at_the_configured_speed() {
    use std::io::{Read, Write};
    use velarx_registry_lib::net::url::Fetcher;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n");
                for _ in 0..1000 {
                    if s.write_all(b"x").is_err() {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            });
        }
    });
    let url = format!("http://127.0.0.1:{port}/f");
    let speed = velarx_registry::speed::Speed::new(1024, 1);
    {
        let f = Fetcher::new(spawner(), &Default::default()).with_min_speed(speed);
        let e = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            f.fetch(&url, 1 << 20, &mut |_| Ok(())),
        )
        .await
        .expect("the download went on with a byte every 250 ms")
        .unwrap_err();
        assert!(e.to_string().contains("min_speed_kib"), "{e}");
    }
}

/// An image imported from a URL: the registry fetcher downloads it, this
/// process (the daemon) opens no connection.
#[tokio::test]
async fn test_an_import_from_a_url_is_downloaded_by_a_worker() {
    use std::io::{Read, Seek};
    use std::sync::atomic::Ordering;
    let (port, mine) = watched_http_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nrootfs!",
    );
    let url = format!("http://127.0.0.1:{port}/rootfs.tar");
    let e = env().await;
    let mut got = String::new();
    let mut f = e.service.download(&url).await.unwrap();
    f.rewind().unwrap();
    f.read_to_string(&mut got).unwrap();
    assert_eq!(got, "rootfs!");
    assert_eq!(
        mine.load(Ordering::SeqCst),
        0,
        "the daemon connected itself"
    );
}

/// A remote manifest (manifest inspect, manifest add) is fetched by a
/// confined worker: the daemon opens no connection to the registry.
#[tokio::test]
async fn test_remote_manifests_are_fetched_by_workers() {
    use std::sync::atomic::Ordering;
    let e = env().await;
    e.publish(&[&build_gzip(&sample()[..1])], &[GZIP]);
    let reference = format!("{}/test:latest", e.host);
    let access = velarx_registry::auth::RegistryAccess::default();
    let m = e
        .service
        .remote_manifest(&reference, false, &access)
        .await
        .unwrap();
    assert!(m["layers"].is_array(), "{m}");
    assert_eq!(
        e.reg.mine.load(Ordering::SeqCst),
        0,
        "the daemon connected itself"
    );
}

/// A login (the /auth route) is checked by a confined worker: the daemon
/// opens no connection to the registry.
#[tokio::test]
async fn test_a_login_is_checked_by_a_worker() {
    use std::sync::atomic::Ordering;
    use velarx_registry_lib::net::url::Fetcher;
    let (host, reg) = start_registry().await;
    let access = velarx_registry::auth::RegistryAccess {
        creds: Some(velarx_registry::Credentials {
            username: "user".into(),
            password: "secret".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    // (a registry on the loopback: its certificate is not checked)
    Fetcher::new(spawner(), &Default::default())
        .login(&host, &access, false)
        .await
        .unwrap();
    assert_eq!(
        reg.mine.load(Ordering::SeqCst),
        0,
        "the daemon connected itself"
    );
    let e = Fetcher::new(spawner(), &Default::default())
        .login("127.0.0.1:1", &access, false)
        .await
        .unwrap_err();
    assert!(
        !matches!(e, velarx_types::ImageError::Unauthorized(_)),
        "{e}"
    );
}

/// A search and a list of tags are made by a confined worker: the daemon
/// opens no connection to the registry.
#[tokio::test]
async fn test_searches_are_made_by_workers() {
    use std::sync::atomic::Ordering;
    use velarx_core::services::SearchOptions;
    let e = env().await;
    let opts = SearchOptions {
        tls_verify: Some(false),
        ..Default::default()
    };
    let found = e
        .service
        .search(&format!("{}/tes", e.host), &opts)
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].name, format!("{}/test", e.host));
    let tags = SearchOptions {
        list_tags: true,
        ..opts
    };
    let found = e
        .service
        .search(&format!("{}/test", e.host), &tags)
        .await
        .unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(
        e.reg.mine.load(Ordering::SeqCst),
        0,
        "the daemon connected itself"
    );
}

/// A push (blobs uploaded in pieces, mounted, a manifest) is made by
/// confined workers: neither registry sees a connection of the daemon.
#[tokio::test]
async fn test_pushes_are_made_by_workers() {
    use std::sync::atomic::Ordering;
    use velarx_core::services::PushOptions;
    let e = env_full(
        velarx_config::PullConfig {
            worker_path: Some(registry_bin().into()),
            ..velarx_config::PullConfig::default()
        },
        velarx_config::PushConfig {
            chunk_mib: 1,
            ..velarx_config::PushConfig::default()
        },
    )
    .await;
    let big: Vec<u8> = {
        use rand::{Rng, SeedableRng};
        let mut data = vec![0u8; 3 * 1024 * 1024];
        rand::rngs::StdRng::seed_from_u64(7).fill(&mut data[..]);
        data
    };
    let items = vec![Item::File {
        name: "big",
        data: big,
        chunk: 64 * 1024,
    }];
    // (another registry, which the fetcher knows from its start)
    let (host_b, b) = start_registry().await;
    e.trust(&[&host_b]);
    e.publish(&[&build_gzip(&items)], &[GZIP]);
    e.pull().await.unwrap();
    let source = format!("{}/test:latest", e.host);

    let client = client_for(&[&e.host, &host_b]);
    let r = e
        .service
        .push_with_client(
            &client,
            &source,
            &PushOptions {
                destination: Some(format!("{host_b}/copy:v1")),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(r.blobs_uploaded, 2);
    assert!(b.logged("PATCH") >= 2, "{:?}", b.log.lock().unwrap());
    assert!(b.blobs.lock().unwrap().contains_key("manifest:v1"));
    assert_eq!(
        b.mine.load(Ordering::SeqCst),
        0,
        "the daemon connected itself"
    );

    let r = e
        .service
        .push_with_client(
            &client,
            &source,
            &PushOptions {
                destination: Some(format!("{}/copy:v2", e.host)),
                ..PushOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(r.blobs_mounted, 2);
    assert_eq!(
        e.reg.mine.load(Ordering::SeqCst),
        0,
        "the daemon connected itself"
    );
}

/// The same without the test switch: in a user namespace whose
/// `user.max_user_namespaces` is 0, the kernel refuses the worker one
/// (EPERM/ENOSPC) and it is confined without.  Skipped where `unshare -r`
/// cannot run, and as root: there `unshare -r` maps the host's root, so
/// the worker is the host's root in it, which no real host has (a root
/// daemon's worker becomes nobody; test_a_worker_without_a_user_namespace
/// checks that case as root).
#[test]
fn test_a_kernel_that_refuses_user_namespaces() {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipped as root: unshare -r would map the host's root");
        return;
    }
    use std::io::Read;
    use std::os::fd::OwnedFd;
    let script = format!(
        "echo 0 > /proc/sys/user/max_user_namespaces && exec {} pull-worker --self-test",
        registry_bin()
    );
    let (mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let theirs: OwnedFd = theirs.into();
    let Ok(mut child) = std::process::Command::new("unshare")
        .args(["-r", "sh", "-c", &script])
        .stdin(std::process::Stdio::from(theirs))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        eprintln!("skipped: no unshare");
        return;
    };
    let mut reply = Vec::new();
    (&mine).read_to_end(&mut reply).unwrap();
    if !child.wait().unwrap().success() && reply.is_empty() {
        eprintln!("skipped: unshare -r is not allowed here");
        return;
    }
    let text = String::from_utf8_lossy(reply.get(24..).unwrap_or_default()).into_owned();
    assert_eq!(reply.first(), Some(&3), "{text}");
    let results: Vec<(String, bool)> = serde_json::from_slice(&reply[24..]).unwrap();
    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
    assert!(failed.is_empty(), "{failed:?}");
    assert!(
        results
            .iter()
            .any(|(w, _)| w == "no user namespace: the kernel refused it"),
        "{text}"
    );
}

/// A registry with a token service that knows alice: the manifests need
/// the token she gets.
async fn token_registry() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let realm = format!("http://{host}/token");
    let challenge = move || {
        (
            StatusCode::UNAUTHORIZED,
            [(
                "www-authenticate",
                format!(r#"Bearer realm="{realm}",service="t""#),
            )],
        )
            .into_response()
    };
    let c2 = challenge.clone();
    let l2 = log.clone();
    let app = axum::Router::new()
        .route("/v2/", get(move || async move { challenge() }))
        .route(
            "/v2/:a/:b/manifests/:r",
            get(move |headers: HeaderMap| async move {
                let ok = headers.get("authorization").and_then(|v| v.to_str().ok())
                    == Some("Bearer alice-token");
                if !ok {
                    return c2();
                }
                (
                    [("content-type", "application/vnd.oci.image.manifest.v1+json")],
                    AUTH_MANIFEST,
                )
                    .into_response()
            }),
        )
        .route(
            "/token",
            get(move |headers: HeaderMap| async move {
                use base64::Engine;
                let user = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Basic "))
                    .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                l2.lock().unwrap().push(user.clone());
                if user == "alice:secret" {
                    (
                        [("content-type", "application/json")],
                        r#"{"token": "alice-token"}"#,
                    )
                        .into_response()
                } else {
                    StatusCode::UNAUTHORIZED.into_response()
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (host, log)
}

const AUTH_MANIFEST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}"#;

/// A pull worker gets no credentials; the daemon asks a worker that
/// has those of the endpoint alone for the token, and a worker that asks
/// for what is not brokered gets nothing.
#[tokio::test]
async fn test_credentials_stay_with_the_daemon() {
    use velarx_registry::client::RegistryClient;
    use velarx_registry::target::TransportConfig;
    use velarx_registry::{AuthConfig, Credentials, RegistriesConfig};
    use velarx_registry_lib::net::pool::Pool;
    let (host, log) = token_registry().await;
    let client = RegistryClient::with_config(
        TransportConfig {
            registries: RegistriesConfig::parse(&format!(
                "[[registry]]\nlocation = \"{host}\"\ninsecure = true\n"
            ))
            .unwrap(),
            certs_dirs: vec![],
            tls_verify: true,
        },
        AuthConfig::from_credentials([(host.as_str(), Credentials::basic("alice", "secret"))]),
    );
    let r = velarx_types::ImageReference::parse(&format!("{host}/team/app:latest")).unwrap();
    let target = client.target(&r).unwrap();
    let (specs, auth) = client.brokered_specs(&target).unwrap();
    assert!(specs.iter().all(|s| s.credentials.is_none() && s.brokered));
    assert!(auth[0].as_ref().is_some_and(|a| a.credentials.is_some()));

    let pool = Pool::new_brokered(spawner(), specs.clone(), auth, 2);
    let (body, _) = pool.manifest("latest", 1 << 20).await.unwrap();
    assert_eq!(&body[..], AUTH_MANIFEST.as_bytes());
    assert!(log.lock().unwrap().iter().all(|u| u == "alice:secret"));

    // without the worker of the credentials, the pull worker has none
    let bare = Pool::new(spawner(), specs, 1);
    let err = bare
        .manifest("latest", 1 << 20)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a brokered endpoint"), "{err}");
}

/// A registry that answers ranges with the whole blob: the layer comes all
/// the same (what the fetcher learns of it for its next requests is its
/// own: `ranges` tests).
#[tokio::test]
async fn test_a_registry_that_ignores_ranges_gives_the_layer_all_the_same() {
    let e = env().await;
    let chunked = build_chunked(&sample());
    e.publish(&[&chunked], &[ZSTD]);
    *e.reg.mode.lock().unwrap() = RangeMode::Ignore;
    e.pull().await.unwrap();
    assert!(e.store.contains(&vid(b"hello\n")));
}

/// A server that answers `HEAD` and the byte ranges of `blob` on connections
/// that stay open, and counts the connections it accepts and the requests
/// it serves.
async fn counting_cdn(
    blob: Vec<u8>,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    use axum::body::Body;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let (accepted, requests) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (told, heads) = tokio::sync::mpsc::unbounded_channel();
    let (count, served) = (accepted.clone(), requests.clone());
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let (blob, served, told) = (blob.clone(), served.clone(), told.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let (blob, served, told) = (blob.clone(), served.clone(), told.clone());
                        async move {
                            served.fetch_add(1, Ordering::SeqCst);
                            let response = if req.method() == hyper::Method::HEAD {
                                let _ = told.send(());
                                hyper::Response::builder().status(200).body(Body::empty())
                            } else {
                                let range = req
                                    .headers()
                                    .get(hyper::header::RANGE)
                                    .and_then(|v| v.to_str().ok())
                                    .and_then(|v| v.strip_prefix("bytes="))
                                    .and_then(|v| v.split_once('-'))
                                    .and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?)))
                                    .unwrap_or((0usize, blob.len() - 1));
                                hyper::Response::builder()
                                    .status(206)
                                    .header(
                                        hyper::header::CONTENT_RANGE,
                                        format!("bytes {}-{}/{}", range.0, range.1, blob.len()),
                                    )
                                    .body(Body::from(blob[range.0..=range.1].to_vec()))
                            };
                            Ok::<_, std::convert::Infallible>(response.unwrap())
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (host, accepted, requests, heads)
}

/// The workers that were made ready connect to the CDN of the registry (a
/// hint) before the first range is asked, and the ranges, a request for
/// each worker, use those connections: no connection is made for them.
#[tokio::test]
async fn test_workers_connect_to_the_cdn_before_the_first_range() {
    use axum::routing::get;
    use velarx_registry::hints::{Auth, Hint};
    let blob: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
    let (cdn, accepted, requests, mut heads) = counting_cdn(blob.clone()).await;
    let location = format!("http://{cdn}/blob");
    let digest = sha(&blob);
    let app = axum::Router::new()
        .route("/v2/", get(|| async { StatusCode::OK }))
        .route(
            "/v2/r/blobs/:digest",
            get(move || {
                let location = location.clone();
                async move { (StatusCode::FOUND, [(header::LOCATION, location)]) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let spec = velarx_registry::target::EndpointSpec {
        host,
        repository: "r".into(),
        insecure: true,
        allow_private: false,
        credentials: None,
        certs: Default::default(),
        brokered: false,
        hint: Some(Hint {
            transport: "http".into(),
            auth: Auth::None,
            cdn: Some(cdn),
        }),
        hints: true,
        min_speed: Default::default(),
    };
    let pool = velarx_registry_lib::net::pool::Pool::new(spawner(), vec![spec], 3);
    pool.warm(3);
    // the workers hold their slots until they are ready: the ranges wait for them
    for _ in 0..3 {
        heads.recv().await.unwrap();
    }
    let asked = |i: u64| {
        let (pool, digest, blob) = (pool.clone(), digest, blob.clone());
        async move {
            let wanted = [i * 1000..(i + 1) * 1000];
            let mut got = Vec::new();
            let mut sink = |piece: velarx_content::pull::ranges::Piece| {
                got.extend_from_slice(&piece.data);
                Box::pin(async { Ok(()) })
                    as futures::future::BoxFuture<'_, Result<(), velarx_types::ImageError>>
            };
            pool.ranges(&digest, &wanted, &mut sink).await.unwrap();
            assert_eq!(got, blob[(i * 1000) as usize..((i + 1) * 1000) as usize]);
        }
    };
    futures::future::join_all((0..3).map(asked)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        3,
        "a connection for each worker"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        6,
        "a request in advance and a range, on the same connection, for each"
    );
}

#[test]
fn test_the_worker_comes_from_the_override_when_set() {
    assert_eq!(
        pick_worker(Some("/copy/velarx".into()), Some("/t/velarx")).as_deref(),
        Some("/copy/velarx")
    );
    assert_eq!(
        pick_worker(Some(String::new()), Some("/t/velarx")).as_deref(),
        Some("/t/velarx")
    );
    assert_eq!(
        pick_worker(None, Some("/t/velarx")).as_deref(),
        Some("/t/velarx")
    );
    assert_eq!(pick_worker(None, None), None);
}

/// The registry fetcher started with `--varlink-fd` serves the one connection
/// of the process that started it, handed as a descriptor: no socket by name
/// anywhere (the confinement it takes is the one the test above tries from
/// inside, which connects to no socket by name), and it leaves with its
/// connection.
#[test]
fn test_the_fetcher_serves_the_connection_it_was_handed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("staging")).unwrap();
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    // (the connection is the standard input of the shell, which gives it as 6)
    let mut child = std::process::Command::new("sh")
        .args([
            "-c",
            "exec \"$0\" --config \"$1/none.toml\" --staging-fd 5 --varlink-fd 6 5<\"$1/staging\" 6<&0 0</dev/null",
        ])
        .arg(registry_bin())
        .arg(dir.path())
        .stdin(std::os::fd::OwnedFd::from(theirs))
        .env_clear()
        .env("HOME", dir.path())
        .spawn()
        .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut conn = velarx_content::fetcher::fetch_client::FetchConn::new(ours).unwrap();
        let info = conn.get_info().await.unwrap();
        assert!(info.capabilities.iter().any(|c| c == "origin"));
    });
    // (the connection is closed: the fetcher has nothing left to serve)
    assert!(child.wait().unwrap().success());
}

/// The engine starts a registry fetcher of its own with a connection
/// handed to it ([`velarx_content::list::private_registry`]): it answers on
/// that connection, no socket of the services directory exists, and it ends
/// with the connection.
#[test]
fn test_the_engine_starts_a_fetcher_with_a_connection_of_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = velarx_config::Config::default();
    config.storage.root = dir.path().join("storage");
    config.pull.registry_path = Some(registry_bin().into());
    let sockets = || {
        std::fs::read_dir(config.services_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("fetcher-"))
            .count()
    };
    let before = sockets();
    let private = velarx_content::list::private_registry(&config).unwrap();
    let velarx_content::list::Private { stream, mut child } = private;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut conn = velarx_content::fetcher::fetch_client::FetchConn::new(stream).unwrap();
        let info = conn.get_info().await.unwrap();
        assert!(info.capabilities.iter().any(|c| c == "origin"));
        // (the services directory has no socket of it: it is nobody else's)
        assert_eq!(sockets(), before);
    });
    assert!(child.wait().unwrap().success());
}
