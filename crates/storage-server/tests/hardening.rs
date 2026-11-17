// SPDX-License-Identifier: Apache-2.0
//! What a client of the reference server cannot make it do: name a file of the
//! server's or a directory of the host by the id of a container, have a root
//! made outside the engine's work directory, pass a keep set that can change
//! under the server, or take the socket of a server that runs.

use serde_json::{json, Value};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use velarx_storage_server::{parse_idle, Config, Running, Server};
use velarx_wire::varlink::Conn;

const STORE: &str = "0123456789abcdef0123456789abcdef";

struct Env {
    dir: tempfile::TempDir,
    socket: PathBuf,
    _server: Arc<Server>,
    _running: Running,
}

fn start() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("storage.sock");
    let server = Server::new(Config {
        root: dir.path().join("server"),
        timeout: Duration::from_secs(10),
        decision: Duration::from_secs(10),
    })
    .unwrap();
    let running = server.listen(&socket).unwrap();
    Env {
        dir,
        socket,
        _server: server,
        _running: running,
    }
}

/// One call, its first reply.
fn call(socket: &Path, method: &str, params: Value, fds: &[BorrowedFd<'_>]) -> Value {
    let mut c = Conn::connect(socket).unwrap();
    c.set_deadline(Instant::now() + Duration::from_secs(20));
    c.call_raw(
        &format!("org.velarx.Storage.{method}"),
        Some(params.to_string().as_bytes()),
        false,
        fds,
    )
    .unwrap();
    serde_json::from_slice(&c.message().unwrap()).unwrap()
}

fn error_of(reply: &Value) -> Option<String> {
    reply["error"].as_str().map(|e| {
        format!(
            "{e}: {}",
            reply["parameters"]["reason"].as_str().unwrap_or_default()
        )
    })
}

fn store_dir(e: &Env) -> PathBuf {
    let uid = rustix::process::geteuid().as_raw();
    e.dir
        .path()
        .join("server")
        .join(uid.to_string())
        .join(STORE)
}

/// An id with a `/` or `..` would name `<store>/containers/../NAME.json`:
/// every call refuses it before it reads or removes anything, here a record
/// planted where such an id leads, whose bundle is a directory of the host.
#[test]
fn a_container_id_names_no_file_outside_the_server_s_records() {
    let e = start();
    let usage = call(&e.socket, "Usage", json!({ "store": STORE }), &[]);
    assert!(error_of(&usage).is_none(), "{usage}");
    let victim = e.dir.path().join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("data"), b"keep me").unwrap();
    let planted = store_dir(&e).join("escape.json");
    std::fs::write(
        &planted,
        json!({
            "bundle": victim, "workdir": e.dir.path(), "image": null,
            "layers": [], "volumes": {}
        })
        .to_string(),
    )
    .unwrap();
    for bad in ["../escape", "a/b", "..", ".", ""] {
        for method in ["RemoveRoot", "Exists", "Size", "WritableRoot"] {
            let r = call(
                &e.socket,
                method,
                json!({ "store": STORE, "container": bad }),
                &[],
            );
            let err = error_of(&r).unwrap_or_else(|| panic!("{method} {bad:?}: {r}"));
            assert!(
                err.contains("not a container id"),
                "{method} {bad:?}: {err}"
            );
        }
        let r = call(
            &e.socket,
            "Mounts",
            json!({ "store": STORE, "container": bad, "volumes": [] }),
            &[],
        );
        assert!(error_of(&r).is_some(), "Mounts {bad:?}: {r}");
    }
    assert!(victim.join("data").exists(), "the bundle a record named");
    assert!(planted.exists(), "the record itself");
}

/// `MountImage` names layers and nothing else: no layer is an error, a layer
/// the store lacks is `Missing` and makes no copy, and a name that is no digest
/// is refused before it names a directory.
#[test]
fn mounting_an_image_makes_nothing_for_layers_it_lacks() {
    let e = start();
    let usage = call(&e.socket, "Usage", json!({ "store": STORE }), &[]);
    assert!(error_of(&usage).is_none(), "{usage}");
    let none = call(
        &e.socket,
        "MountImage",
        json!({ "store": STORE, "layers": [] }),
        &[],
    );
    assert!(error_of(&none).is_some(), "{none}");
    let digest = format!("sha256:{}", "ab".repeat(32));
    let missing = call(
        &e.socket,
        "MountImage",
        json!({ "store": STORE, "layers": [
            { "key": digest, "diff_id": digest, "chain_id": digest }
        ]}),
        &[],
    );
    let err = error_of(&missing).unwrap_or_else(|| panic!("{missing}"));
    assert!(err.contains("not stored"), "{err}");
    let bad = call(
        &e.socket,
        "MountImage",
        json!({ "store": STORE, "layers": [
            { "key": digest, "diff_id": digest, "chain_id": "../../escape" }
        ]}),
        &[],
    );
    assert!(error_of(&bad).is_some(), "{bad}");
    assert!(!store_dir(&e).join("read").exists());
    assert!(!e.dir.path().join("escape").exists());
}

/// The root of a container is made in the engine's work directory of the
/// store only: a directory of the client's user that nobody else can enter,
/// named without links.
#[test]
fn a_root_is_made_in_a_private_work_directory_only() {
    let e = start();
    let create = |workdir: &Path, container: &str| {
        call(
            &e.socket,
            "CreateRoot",
            json!({
                "store": STORE, "container": container, "workdir": workdir,
                "layers": [], "ask": { "idmap_mount": false }
            }),
            &[],
        )
    };
    let open = e.dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = create(&open, "c1");
    assert!(
        error_of(&r).is_some_and(|m| m.contains("work directory")),
        "{r}"
    );
    assert!(!open.join("c1").exists());

    let work = e.dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = e.dir.path().join("link");
    std::os::unix::fs::symlink(&work, &link).unwrap();
    let r = create(&link, "c1");
    assert!(
        error_of(&r).is_some_and(|m| m.contains("work directory")),
        "{r}"
    );
    let r = create(Path::new("work"), "c1");
    assert!(
        error_of(&r).is_some_and(|m| m.contains("work directory")),
        "{r}"
    );
    assert!(!work.join("c1").exists());

    let r = create(&work, "../c1");
    assert!(
        error_of(&r).is_some_and(|m| m.contains("not a container id")),
        "{r}"
    );

    let r = create(&work, "c1");
    assert!(error_of(&r).is_none(), "{r}");
    assert!(work.join("c1").is_dir());
    let r = call(
        &e.socket,
        "RemoveRoot",
        json!({ "store": STORE, "container": "c1" }),
        &[],
    );
    assert!(error_of(&r).is_none(), "{r}");
    assert!(!work.join("c1").exists());
}

/// The keep set of `Collect` is a sealed memory file of the length the call
/// says: a file that can still change, or another length, is refused.
#[test]
fn a_keep_set_that_can_change_is_refused() {
    let e = start();
    let lines = b"{\"grace_secs\":0}\n";
    let open = rustix::fs::memfd_create("keep", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
    std::io::Write::write_all(&mut std::fs::File::from(open.try_clone().unwrap()), lines).unwrap();
    let collect = |fd: BorrowedFd<'_>, length: usize| {
        call(
            &e.socket,
            "Collect",
            json!({ "store": STORE, "keep_length": length }),
            &[fd],
        )
    };
    let r = collect(open.as_fd(), lines.len());
    assert!(
        error_of(&r).is_some_and(|m| m.contains("not a sealed memory file")),
        "{r}"
    );
    let sealed = velarx_base::sealed::sealed_memory(lines).unwrap();
    let r = collect(sealed.as_fd(), lines.len() + 1);
    assert!(error_of(&r).is_some_and(|m| m.contains("length")), "{r}");
    let r = collect(sealed.as_fd(), lines.len());
    assert!(error_of(&r).is_none(), "{r}");
}

/// A second server does not take the socket of one that runs; a socket left
/// by one that stopped is replaced; anything else at the path is an error.
#[test]
fn the_socket_of_a_running_server_is_not_taken() {
    let mut e = start();
    let other = Server::new(Config {
        root: e.dir.path().join("other"),
        timeout: Duration::from_secs(10),
        decision: Duration::from_secs(10),
    })
    .unwrap();
    let err = other.listen(&e.socket).err().expect("a socket in use");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    assert_eq!(
        std::fs::metadata(&e.socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    e._running.stop();
    let running = other.listen(&e.socket).expect("a stale socket is replaced");
    drop(running);
    let file = e.dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    assert!(other.listen(&file).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"x");
}

/// A socket systemd passes (`LISTEN_FDS`, `LISTEN_PID`, descriptor 3) is
/// served as it is: the process binds nothing, and answers on it.
#[test]
fn a_socket_passed_as_descriptor_3_is_served() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("activated.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    // (a shell puts the socket on descriptor 3 and names its own pid, which
    // the server it execs keeps: what systemd does)
    let mut cmd = std::process::Command::new("sh");
    cmd.args([
        "-c",
        "LISTEN_PID=$$ LISTEN_FDS=1 exec \"$0\" \"$@\" 3<&0",
        env!("CARGO_BIN_EXE_velarx-storage-server"),
        "--root",
    ])
    .arg(dir.path().join("server"))
    .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
        listener,
    )));
    let mut child = cmd.spawn().unwrap();
    let reply = call(&socket, "GetInfo", json!({}), &[]);
    assert!(error_of(&reply).is_none(), "{reply}");
    assert!(reply["parameters"]["name"].is_string(), "{reply}");
    child.kill().unwrap();
    child.wait().unwrap();
}

/// `GetInfo` says the server holds objects, and `HasObjects` answers from the
/// objects of its store: false for an object it lacks and for a key that is no
/// name of an object (nothing is looked for at a path the client names), an
/// error for more keys than a call takes.
#[test]
fn has_objects_answers_from_the_store_only() {
    let e = start();
    let info = call(&e.socket, "GetInfo", json!({}), &[]);
    assert!(
        info["parameters"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("objects")),
        "{info}"
    );
    let verity = format!("fsverity-sha256-12:{}", "ab".repeat(32));
    let hash = format!("sha256:{}", "cd".repeat(32));
    let keys = json!([verity, hash, "../../etc/passwd", ""]);
    let reply = call(
        &e.socket,
        "HasObjects",
        json!({ "store": STORE, "objects": keys }),
        &[],
    );
    assert!(error_of(&reply).is_none(), "{reply}");
    assert_eq!(
        reply["parameters"]["have"],
        json!([false, false, false, false])
    );
    let many: Vec<String> = (0..4097).map(|_| verity.clone()).collect();
    let reply = call(
        &e.socket,
        "HasObjects",
        json!({ "store": STORE, "objects": many }),
        &[],
    );
    assert!(error_of(&reply).is_some(), "{reply}");
}

fn server_on(socket: &Path) -> (Arc<Server>, Running) {
    let server = Server::new(Config {
        root: socket.parent().unwrap().join("server"),
        timeout: Duration::from_secs(10),
        decision: Duration::from_secs(10),
    })
    .unwrap();
    let running = server.listen(socket).unwrap();
    (server, running)
}

/// Run `wait_idle(idle)` on a thread: the time it took, once it returns.
fn idle_watch(server: &Arc<Server>, idle: Duration) -> std::sync::mpsc::Receiver<Duration> {
    let (tx, rx) = std::sync::mpsc::channel();
    let server = server.clone();
    std::thread::spawn(move || {
        let t = Instant::now();
        server.wait_idle(idle);
        let _ = tx.send(t.elapsed());
    });
    rx
}

/// A server nobody connects to is idle after the idle time, and not before.
#[test]
fn an_idle_server_is_idle_after_the_idle_time() {
    let dir = tempfile::tempdir().unwrap();
    let (server, _running) = server_on(&dir.path().join("s.sock"));
    assert!(!server.busy());
    let rx = idle_watch(&server, Duration::from_millis(400));
    let took = rx.recv_timeout(Duration::from_secs(10)).expect("idle");
    assert!(took >= Duration::from_millis(400), "{took:?}");
}

/// A connection that is open keeps the server busy, a call or none, until it
/// is closed; the idle time counts from then.
#[test]
fn an_open_connection_keeps_the_server_from_being_idle() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let (server, _running) = server_on(&socket);
    let conn = Conn::connect(&socket).unwrap();
    let rx = idle_watch(&server, Duration::from_millis(200));
    std::thread::sleep(Duration::from_millis(1000));
    assert!(server.busy());
    assert!(rx.try_recv().is_err(), "left with a connection open");
    drop(conn);
    let closed = Instant::now();
    rx.recv_timeout(Duration::from_secs(10))
        .expect("idle after the close");
    // (counted from the last look at a busy server, a tick before the close)
    assert!(
        closed.elapsed() >= Duration::from_millis(140),
        "{:?}",
        closed.elapsed()
    );
}

fn wait_for_exit(
    child: &mut std::process::Child,
    within: Duration,
) -> Option<std::process::ExitStatus> {
    let t = Instant::now();
    while t.elapsed() < within {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn binary(dir: &Path, args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_velarx-storage-server"));
    cmd.arg("--socket")
        .arg(dir.join("s.sock"))
        .arg("--root")
        .arg(dir.join("server"))
        .args(args)
        .env_remove("NOTIFY_SOCKET")
        .env_remove("VELARX_STORAGE_IDLE_SECS");
    cmd
}

/// The program leaves, with status 0 and the socket it bound removed, once
/// idle; a client then finds nothing at the path.  A connection holds it.
#[test]
fn the_server_program_leaves_when_idle_and_removes_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let mut child = binary(dir.path(), &["--idle-secs", "2"]).spawn().unwrap();
    let t = Instant::now();
    while !socket.exists() {
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    let reply = call(&socket, "GetInfo", json!({}), &[]);
    assert!(error_of(&reply).is_none(), "{reply}");
    // (an open connection: no exit for longer than the idle time)
    let conn = Conn::connect(&socket).unwrap();
    assert!(wait_for_exit(&mut child, Duration::from_millis(3500)).is_none());
    drop(conn);
    let status = wait_for_exit(&mut child, Duration::from_secs(10)).expect("left when idle");
    assert!(status.success(), "{status:?}");
    assert!(!socket.exists(), "the socket is left");
    assert!(Conn::connect(&socket).is_err());
}

/// `0` and `off` (flag or environment) never leave; a value that is none is
/// a usage error.
#[test]
fn an_idle_time_of_zero_or_off_never_leaves_and_a_bad_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut off = binary(dir.path(), &["--idle-secs", "off"]).spawn().unwrap();
    let dir2 = tempfile::tempdir().unwrap();
    let mut zero = binary(dir2.path(), &[])
        .env("VELARX_STORAGE_IDLE_SECS", "0")
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    assert!(off.try_wait().unwrap().is_none());
    assert!(zero.try_wait().unwrap().is_none());
    off.kill().unwrap();
    zero.kill().unwrap();
    off.wait().unwrap();
    zero.wait().unwrap();
    let dir3 = tempfile::tempdir().unwrap();
    let status = binary(dir3.path(), &["--idle-secs", "soon"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    assert_eq!(parse_idle("300"), Some(Some(Duration::from_secs(300))));
    assert_eq!(parse_idle(" OFF "), Some(None));
    assert_eq!(parse_idle("0"), Some(None));
    assert_eq!(parse_idle("-1"), None);
}

/// With a `NOTIFY_SOCKET` the program says `READY=1` once the socket is
/// listening (a call on it works at once); without one it starts as before.
#[test]
fn the_server_program_sends_ready_to_the_notify_socket() {
    let dir = tempfile::tempdir().unwrap();
    let notify = dir.path().join("notify");
    let rx = std::os::unix::net::UnixDatagram::bind(&notify).unwrap();
    rx.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut child = binary(dir.path(), &["--idle-secs", "off"])
        .env("NOTIFY_SOCKET", &notify)
        .spawn()
        .unwrap();
    let mut buf = [0u8; 64];
    let n = rx.recv(&mut buf).expect("READY=1");
    assert_eq!(&buf[..n], b"READY=1");
    let reply = call(&dir.path().join("s.sock"), "GetInfo", json!({}), &[]);
    assert!(error_of(&reply).is_none(), "{reply}");
    child.kill().unwrap();
    child.wait().unwrap();
    // (no NOTIFY_SOCKET: the server runs, as the other tests show; and one
    // that nobody listens on is no reason to stop)
    let dir = tempfile::tempdir().unwrap();
    let mut child = binary(dir.path(), &["--idle-secs", "off"])
        .env("NOTIFY_SOCKET", dir.path().join("nobody"))
        .spawn()
        .unwrap();
    let t = Instant::now();
    while !dir.path().join("s.sock").exists() {
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// A call on `socket`: `None` when the connect fails (no server there),
/// `Some(reply)` when it is accepted, the reply or the error that ended it.
fn try_call(socket: &Path) -> Option<Result<Value, String>> {
    let mut c = Conn::connect(socket).ok()?;
    c.set_deadline(Instant::now() + Duration::from_secs(20));
    let r = c
        .call_raw("org.velarx.Storage.GetInfo", Some(b"{}"), false, &[])
        .map_err(|e| e.to_string())
        .and_then(|()| c.message().map_err(|e| e.to_string()))
        .and_then(|m| serde_json::from_slice::<Value>(&m).map_err(|e| e.to_string()));
    Some(r)
}

/// Once the server decided to leave it accepts nothing on a socket systemd
/// passed: a connection stays queued, and the next server on the same socket
/// answers it.
#[test]
fn a_server_that_leaves_takes_no_connection_of_a_passed_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server = |name: &str| {
        Server::new(Config {
            root: dir.path().join(name),
            timeout: Duration::from_secs(10),
            decision: Duration::from_secs(10),
        })
        .unwrap()
    };
    let first = server("first");
    let running = first.serve(listener.try_clone().unwrap(), &socket).unwrap();
    running.wait_idle(Duration::from_millis(50));
    running.leave();
    assert!(socket.exists(), "a passed socket is not removed");
    // (connected, queued: no call yet, so a connection taken would stay
    // counted)
    let mut conn = Conn::connect(&socket).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(!first.busy(), "a server that leaves accepted a connection");
    let second = server("second");
    let _next = second.serve(listener, &socket).unwrap();
    conn.set_deadline(Instant::now() + Duration::from_secs(20));
    conn.call_raw("org.velarx.Storage.GetInfo", Some(b"{}"), false, &[])
        .unwrap();
    let reply: Value = serde_json::from_slice(&conn.message().unwrap()).unwrap();
    assert!(error_of(&reply).is_none(), "{reply}");
    // (the first server's accept thread waits on the shared socket: the
    // test ends without its stop, which would shut the second one down)
    std::mem::forget(running);
}

/// A server of its own socket that leaves while clients come and go drops
/// none it accepted: each call either finds no server or gets its reply,
/// never a connection that is reset.
#[test]
fn a_server_that_leaves_drops_no_accepted_connection() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let clients: Vec<_> = (0..3u64)
        .map(|i| {
            let (socket, stop, served) = (socket.clone(), stop.clone(), served.clone());
            std::thread::spawn(move || {
                let mut n = i;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match try_call(&socket) {
                        None => {}
                        Some(Ok(reply)) => {
                            assert!(error_of(&reply).is_none(), "{reply}");
                            served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        Some(Err(e)) => panic!("an accepted call was dropped: {e}"),
                    }
                    // (gaps of 0 to 30 ms: the server is idle in some)
                    n = n
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    std::thread::sleep(Duration::from_micros((n >> 33) % 30_000));
                }
            })
        })
        .collect();
    let t = Instant::now();
    let mut rounds = 0;
    while t.elapsed() < Duration::from_secs(4) {
        let (_server, running) = server_on(&socket);
        running.wait_idle(Duration::from_millis(10));
        running.leave();
        drop(running);
        rounds += 1;
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    for c in clients {
        c.join().unwrap();
    }
    eprintln!("{rounds} rounds");
    assert!(rounds > 5, "{rounds}");
    assert!(served.load(std::sync::atomic::Ordering::SeqCst) > 0);
}
