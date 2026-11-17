// SPDX-License-Identifier: Apache-2.0
//! The following of the logs of a pod: the merged lines of its containers,
//! as the route streams them.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use velarx_core::services::podlogs::{
    follow, Entry, FollowOptions, Following, Member, Observe, Watchers,
};
use velarx_wire::monitor::logfmt::{Limits, LogWriter, Stream};

const WAIT: Duration = Duration::from_secs(20);

/// The containers of a pod, which a test changes.
struct Pod {
    dir: PathBuf,
    members: Mutex<Vec<Member>>,
    changes: broadcast::Sender<()>,
}

impl Pod {
    fn new(name: &str) -> Arc<Self> {
        let dir =
            std::env::temp_dir().join(format!("velarx-podlogs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Self {
            dir,
            members: Mutex::new(Vec::new()),
            changes: broadcast::channel(64).0,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.log"))
    }

    fn writer(&self, name: &str, limits: Limits) -> LogWriter {
        LogWriter::open(&self.path(name), limits).unwrap()
    }

    /// A container joins the pod (its log may not exist yet).
    fn add(&self, name: &str, active: bool) {
        self.add_as(name, active, false);
    }

    /// A container whose log is in the journal (`journalctl` is `stub`).
    fn add_journal(&self, name: &str, active: bool) {
        self.add_as(name, active, true);
    }

    fn add_as(&self, name: &str, active: bool, journal: bool) {
        let mut members = self.members.lock().unwrap();
        let index = members.len();
        members.push(Member {
            id: format!("id-{name}"),
            index,
            name: name.to_string(),
            path: self.path(name),
            allow_dir: None,
            active,
            journal,
        });
        drop(members);
        let _ = self.changes.send(());
    }

    fn set_active(&self, name: &str, active: bool) {
        for m in self.members.lock().unwrap().iter_mut() {
            if m.name == name {
                m.active = active;
            }
        }
        let _ = self.changes.send(());
    }

    fn follow(self: &Arc<Self>, tail: Option<usize>) -> Following {
        self.follow_with(tail, PathBuf::from("journalctl"))
    }

    fn follow_with(self: &Arc<Self>, tail: Option<usize>, journalctl: PathBuf) -> Following {
        let containers = self.members.lock().unwrap().len();
        follow(
            Watch(self.clone()),
            self.changes.subscribe(),
            FollowOptions {
                since_ns: None,
                until_ns: None,
                tail,
                window: Duration::from_millis(60),
                journalctl,
                containers,
            },
        )
    }
}

/// What tells the members of the pod.
struct Watch(Arc<Pod>);

impl Observe for Watch {
    async fn members(&self) -> Option<Vec<Member>> {
        Some(self.0.members.lock().unwrap().clone())
    }
}

impl Drop for Pod {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn limits() -> Limits {
    Limits {
        max_files: 1,
        ..Default::default()
    }
}

async fn next(f: &mut Following) -> Option<Entry> {
    tokio::time::timeout(WAIT, f.rx.recv())
        .await
        .expect("a line within the time")
}

async fn lines(f: &mut Following, n: usize) -> Vec<String> {
    let mut out = Vec::new();
    while out.len() < n {
        let e = next(f).await.expect("the stream ended early");
        out.push(format!("{}:{}", e.container, e.message));
    }
    out
}

fn tick() {
    // (the logs have the time of the write, in nanoseconds: lines written in
    // turn have increasing times once the clock has moved: until it did, which
    // is its resolution, not a guess of it)
    let before = std::time::SystemTime::now();
    while std::time::SystemTime::now() <= before {
        std::hint::spin_loop();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lines_written_while_following_are_merged_and_the_end_comes_with_the_exits() {
    let pod = Pod::new("merge");
    let (mut a, mut b) = (pod.writer("a", limits()), pod.writer("b", limits()));
    a.write(Stream::Stdout, b"a-old\n").unwrap();
    tick();
    b.write(Stream::Stderr, b"b-old\n").unwrap();
    pod.add("a", true);
    pod.add("b", true);
    pod.add("infra", true);
    let mut f = pod.follow(None);
    assert_eq!(lines(&mut f, 2).await, ["a:a-old", "b:b-old"]);
    for i in 0..4 {
        tick();
        a.write(Stream::Stdout, format!("a{i}\n").as_bytes())
            .unwrap();
        tick();
        b.write(Stream::Stdout, format!("b{i}\n").as_bytes())
            .unwrap();
    }
    assert_eq!(
        lines(&mut f, 8).await,
        ["a:a0", "b:b0", "a:a1", "b:b1", "a:a2", "b:b2", "a:a3", "b:b3"]
    );
    pod.set_active("a", false);
    pod.set_active("b", true);
    tick();
    b.write(Stream::Stdout, b"b-last\n").unwrap();
    assert_eq!(lines(&mut f, 1).await, ["b:b-last"]);
    // the infra container runs on, as long as the pod does: so does the
    // following (podman's)
    pod.set_active("b", false);
    assert!(
        tokio::time::timeout(Duration::from_millis(400), f.rx.recv())
            .await
            .is_err(),
        "the infra container keeps the following going"
    );
    pod.set_active("infra", false);
    assert!(next(&mut f).await.is_none(), "the stream ends");
    assert!(f.watchers.wait_idle(WAIT), "no reader is left");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lines_of_one_container_stay_in_order_with_a_partial_line_at_the_end() {
    let pod = Pod::new("partial");
    let mut a = pod.writer("a", limits());
    pod.add("a", true);
    let mut f = pod.follow(None);
    a.write(Stream::Stdout, b"one\ntwo\nthr").unwrap();
    assert_eq!(lines(&mut f, 2).await, ["a:one", "a:two"]);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), f.rx.recv())
            .await
            .is_err()
    );
    a.write(Stream::Stdout, b"ee\nfour (no newline)").unwrap();
    assert_eq!(lines(&mut f, 1).await, ["a:three"]);
    // a monitor that dies leaves the line open: it is given at the end
    pod.set_active("a", false);
    assert_eq!(lines(&mut f, 1).await, ["a:four (no newline)"]);
    assert!(next(&mut f).await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_containers_of_the_pod_when_it_starts_are_followed() {
    let pod = Pod::new("late");
    let mut a = pod.writer("a", limits());
    pod.add("a", true);
    // b is in the pod and was never started: it has no log, and as with
    // podman it is not followed when it starts
    pod.add("b", false);
    // c runs and has no log yet: it is a matter of moments
    pod.add("c", true);
    let mut f = pod.follow(None);
    a.write(Stream::Stdout, b"a1\n").unwrap();
    assert_eq!(lines(&mut f, 1).await, ["a:a1"]);
    let mut b = pod.writer("b", limits());
    pod.set_active("b", true);
    tick();
    b.write(Stream::Stdout, b"b1\n").unwrap();
    let mut c = pod.writer("c", limits());
    pod.set_active("c", true);
    tick();
    c.write(Stream::Stdout, b"c1\n").unwrap();
    assert_eq!(lines(&mut f, 1).await, ["c:c1"]);
    // d joins the pod: it is not followed
    let mut d = pod.writer("d", limits());
    pod.add("d", true);
    tick();
    d.write(Stream::Stdout, b"d1\n").unwrap();
    tick();
    a.write(Stream::Stdout, b"a2\n").unwrap();
    assert_eq!(lines(&mut f, 1).await, ["a:a2"]);
    // c exits and starts again (its log goes on): still followed
    pod.set_active("c", false);
    pod.set_active("c", true);
    tick();
    c.write(Stream::Stdout, b"c2\n").unwrap();
    assert_eq!(lines(&mut f, 1).await, ["c:c2"]);
    pod.set_active("a", false);
    pod.set_active("c", false);
    assert!(next(&mut f).await.is_none());
    assert!(f.watchers.wait_idle(WAIT));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pod_that_has_exited_gives_its_logs_and_ends() {
    let pod = Pod::new("exited");
    let (mut a, mut b) = (pod.writer("a", limits()), pod.writer("b", limits()));
    for i in 0..3 {
        a.write(Stream::Stdout, format!("a{i}\n").as_bytes())
            .unwrap();
        tick();
        b.write(Stream::Stdout, format!("b{i}\n").as_bytes())
            .unwrap();
        tick();
    }
    pod.add("a", false);
    pod.add("b", false);
    let mut f = pod.follow(None);
    assert_eq!(
        lines(&mut f, 6).await,
        ["a:a0", "b:b0", "a:a1", "b:b1", "a:a2", "b:b2"]
    );
    assert!(next(&mut f).await.is_none());
    assert!(f.watchers.wait_idle(WAIT));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tail_is_of_each_container() {
    let pod = Pod::new("tail");
    let (mut a, mut b) = (pod.writer("a", limits()), pod.writer("b", limits()));
    for i in 0..5 {
        a.write(Stream::Stdout, format!("a{i}\n").as_bytes())
            .unwrap();
        tick();
        b.write(Stream::Stdout, format!("b{i}\n").as_bytes())
            .unwrap();
        tick();
    }
    pod.add("a", true);
    pod.add("b", true);
    let mut f = pod.follow(Some(2));
    assert_eq!(lines(&mut f, 4).await, ["a:a3", "b:b3", "a:a4", "b:b4"]);
    a.write(Stream::Stdout, b"new\n").unwrap();
    assert_eq!(lines(&mut f, 1).await, ["a:new"]);
    // 0: no history, the lines to come.  Nothing tells when the readers
    // are at the end of the logs (on a loaded machine it takes more than a
    // tick): the line is written again until one comes, and what comes
    // first is one of them, not the history.
    let mut f = pod.follow(Some(0));
    let mut tries = 0;
    let first = loop {
        b.write(Stream::Stdout, b"newer\n").unwrap();
        if let Ok(e) = tokio::time::timeout(Duration::from_millis(200), f.rx.recv()).await {
            break e.expect("the stream ended early");
        }
        tries += 1;
        assert!(tries < 150, "no line followed in 30 s");
    };
    assert_eq!(format!("{}:{}", first.container, first.message), "b:newer");
    assert_eq!(f.containers, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rotated_log_is_followed_across_the_rotation() {
    let pod = Pod::new("rotate");
    let mut a = pod.writer(
        "a",
        Limits {
            max_size: 600,
            max_files: 20,
            ..Default::default()
        },
    );
    pod.add("a", true);
    let mut f = pod.follow(None);
    let total = 100;
    let reader = tokio::spawn(async move {
        let got = lines(&mut f, total).await;
        (got, f)
    });
    for i in 0..total {
        a.write(Stream::Stdout, format!("line {i:03}\n").as_bytes())
            .unwrap();
        if i % 7 == 0 {
            tick();
        }
    }
    let (got, _f) = reader.await.unwrap();
    let want: Vec<String> = (0..total).map(|i| format!("a:line {i:03}")).collect();
    assert_eq!(got, want);
    assert!(Path::new(&pod.path("a")).with_extension("log.1").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_huge_line_comes_in_pieces() {
    let pod = Pod::new("huge");
    let mut a = pod.writer("a", limits());
    pod.add("a", true);
    let mut f = pod.follow(None);
    let huge = vec![b'x'; 3 * 1024 * 1024];
    a.write(Stream::Stdout, &huge).unwrap();
    a.write(Stream::Stdout, b"\nafter\n").unwrap();
    let mut total = 0;
    loop {
        let e = next(&mut f).await.unwrap();
        if e.message == "after" {
            break;
        }
        assert!(e.message.len() <= velarx_core::services::podlogs::MAX_LINE);
        total += e.message.len();
    }
    assert_eq!(total, huge.len());
}

/// A `journalctl` that gives two entries and waits when it follows, and the
/// one after the cursor of the second when it is asked for the rest (after
/// a `--sync`).
fn stub_journalctl(pod: &Pod) -> PathBuf {
    let path = pod.dir.join("journalctl");
    let entry = |msg: &str, us: u64, cursor: &str, prio: u8| {
        format!(
            r#"{{"MESSAGE":"{msg}","PRIORITY":"{prio}","__REALTIME_TIMESTAMP":"{us}","__CURSOR":"{cursor}"}}"#
        )
    };
    let script = format!(
        r#"case "$*" in
  --sync) exit 0 ;;
  *CONTAINER_ID_FULL=id-j*) ;;
  *) echo "wrong match: $*" >&2; exit 2 ;;
esac
case "$*" in
  *--follow*)
    echo '{}'
    echo '{}'
    exec sleep 300 ;;
  *--after-cursor=c2*)
    echo '{}' ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
"#,
        entry("j1", 1_700_000_000_000_001, "c1", 6),
        entry("j2", 1_700_000_000_000_002, "c2", 3),
        entry("j3", 1_700_000_000_000_003, "c3", 6),
    );
    velarx_base::testing::write_script(&path, &script);
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn a_container_that_logs_to_the_journal_is_followed_through_journalctl() {
    let pod = Pod::new("journal");
    let mut a = pod.writer("a", limits());
    pod.add("a", true);
    pod.add_journal("j", true);
    let mut f = pod.follow_with(None, stub_journalctl(&pod));
    // (the entries of the journal are of 2023: before the line of a)
    a.write(Stream::Stdout, b"a1\n").unwrap();
    let mut got = lines(&mut f, 3).await;
    // (the entries of the journal wait for the window)
    got.sort();
    assert_eq!(got, ["a:a1", "j:j1", "j:j2"]);
    // the container exits: what the journal got after the last entry read
    // comes before the end
    pod.set_active("j", false);
    pod.set_active("a", false);
    assert_eq!(lines(&mut f, 1).await, ["j:j3"]);
    assert!(next(&mut f).await.is_none());
    assert!(f.watchers.wait_idle(WAIT));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_entries_say_their_container_and_its_place() {
    let pod = Pod::new("who");
    let (mut a, mut b) = (pod.writer("a", limits()), pod.writer("b", limits()));
    a.write(Stream::Stdout, b"a1\n").unwrap();
    tick();
    b.write(Stream::Stderr, b"b1\n").unwrap();
    pod.add("a", false);
    pod.add("b", false);
    let mut f = pod.follow(None);
    let first = next(&mut f).await.unwrap();
    assert_eq!(
        (
            first.container.as_str(),
            first.container_id.as_str(),
            first.index
        ),
        ("a", "id-a", 0)
    );
    let second = next(&mut f).await.unwrap();
    assert_eq!((second.container_id.as_str(), second.index), ("id-b", 1));
    assert_eq!(f.containers, 2);
}

mod http {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// The lines as an NDJSON body, as a frontend writes them.
    fn pod_log_stream(
        lines: impl futures::Stream<Item = velarx_wire::wire::PodLogEntry> + Send + 'static,
    ) -> axum::response::Response {
        use futures::StreamExt;
        let body = lines.map(|e| {
            let mut line = serde_json::to_vec(&e).unwrap_or_default();
            line.push(b'\n');
            Ok::<_, std::io::Error>(axum::body::Bytes::from(line))
        });
        axum::response::Response::new(axum::body::Body::from_stream(body))
    }

    /// A server with the route's response, over a pod; the watchers of the
    /// last request.
    async fn serve(pod: &Arc<Pod>) -> (std::net::SocketAddr, Arc<Mutex<Option<Arc<Watchers>>>>) {
        let seen = Arc::new(Mutex::new(None));
        let (pod, last) = (pod.clone(), seen.clone());
        let app = axum::Router::new().route(
            "/logs",
            axum::routing::get(move || {
                let following = pod.follow(None);
                *last.lock().unwrap() = Some(following.watchers.clone());
                async move { pod_log_stream(velarx::api::ops::pod::lines(following)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, seen)
    }

    async fn request(addr: std::net::SocketAddr) -> BufReader<tokio::net::TcpStream> {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /logs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        BufReader::new(s)
    }

    /// The next document of the stream (the chunk framing is skipped).
    async fn document(r: &mut BufReader<tokio::net::TcpStream>) -> Option<serde_json::Value> {
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(WAIT, r.read_line(&mut line))
                .await
                .expect("a line within the time")
                .unwrap();
            if n == 0 {
                return None;
            }
            if line.starts_with('{') {
                return Some(serde_json::from_str(&line).unwrap());
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_route_streams_the_lines_and_ends_with_the_containers() {
        let pod = Pod::new("route");
        let (mut a, mut b) = (pod.writer("a", limits()), pod.writer("b", limits()));
        pod.add("a", true);
        pod.add("b", true);
        let (addr, _) = serve(&pod).await;
        let mut r = request(addr).await;
        // written after the request: its answer begins once the pod is followed
        let mut head = String::new();
        tokio::time::timeout(WAIT, r.read_line(&mut head))
            .await
            .expect("the head of the answer within the time")
            .unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        // (one line at a time: the order of the lines of two containers is
        // the order of their times only within the window, and a reader
        // that opens its log late reads a line written after the request
        // as history, given at once)
        a.write(Stream::Stdout, b"first\n").unwrap();
        let d = document(&mut r).await.unwrap();
        assert_eq!(d["container_name"], "a");
        assert_eq!(d["message"], "first");
        assert_eq!(d["stream"], "stdout");
        assert!(d["timestamp"].as_str().unwrap().ends_with('Z'));
        b.write(Stream::Stderr, b"second\n").unwrap();
        let d = document(&mut r).await.unwrap();
        assert_eq!(
            (d["container_name"].as_str(), d["stream"].as_str()),
            (Some("b"), Some("stderr"))
        );
        pod.set_active("a", false);
        pod.set_active("b", false);
        assert!(document(&mut r).await.is_none(), "the response ends");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_that_goes_away_stops_the_readers() {
        let pod = Pod::new("gone");
        let mut a = pod.writer("a", limits());
        pod.add("a", true);
        pod.add("b", true);
        let (addr, seen) = serve(&pod).await;
        let mut r = request(addr).await;
        a.write(Stream::Stdout, b"hello\n").unwrap();
        assert_eq!(document(&mut r).await.unwrap()["message"], "hello");
        let watchers = seen.lock().unwrap().clone().unwrap();
        assert_eq!(watchers.count(), 2);
        // the pod is idle: the daemon is told by the connection alone
        drop(r);
        let w = watchers.clone();
        let idle = tokio::task::spawn_blocking(move || w.wait_idle(WAIT))
            .await
            .unwrap();
        assert!(idle, "the readers were still there: {}", watchers.count());
    }
}
