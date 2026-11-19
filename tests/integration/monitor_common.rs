// SPDX-License-Identifier: Apache-2.0
//! A monitor driven by a fake OCI runtime: a shell script that keeps a
//! container as a background process released through a fifo.

#![allow(dead_code)]

use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use velarx_runtime::monitor::config::{LogConfig, LogDriver, MonitorConfig};
use velarx_wire::monitor::client;
use velarx_wire::monitor::iface::{self, Subscribed};
use velarx_wire::monitor::proto::{
    CheckpointRequest, Event, ExitInfo, Health, MonitorUpdate, RunState, Status,
};
use velarx_wire::varlink::Conn;

/// The `velarx-monitor` that cargo built (see `common::built_binary`).
pub fn monitor_binary() -> PathBuf {
    crate::common::built_binary("velarx-monitor")
        .expect("no velarx-monitor next to the test executable: cargo build --bins")
}

/// Send `signal` to the process `pid` (to the group `-pid` when negative);
/// whether it could be sent (with the signal 0: whether it exists).
pub fn kill(pid: i32, signal: i32) -> bool {
    use rustix::process::{
        kill_process, kill_process_group, test_kill_process, test_kill_process_group, Pid, Signal,
    };
    let (group, raw) = (pid < 0, pid.abs());
    let Some(pid) = Pid::from_raw(raw) else {
        return false;
    };
    match (Signal::from_named_raw(signal), group) {
        (Some(s), false) => kill_process(pid, s).is_ok(),
        (Some(s), true) => kill_process_group(pid, s).is_ok(),
        (None, false) => test_kill_process(pid).is_ok(),
        (None, true) => test_kill_process_group(pid).is_ok(),
    }
}

const FAKE_RUNTIME: &str = r#"# A minimal OCI runtime for the tests of the monitor.
root=""
while [ $# -gt 0 ]; do
    case "$1" in
        --root) root="$2"; shift 2 ;;
        --cgroup-manager) shift 2 ;;
        *) break ;;
    esac
done
cmd="$1"; shift
case "$cmd" in
    create)
        bundle=""; pidfile=""; createargs="$*"
        while [ $# -gt 1 ]; do
            case "$1" in
                --bundle) bundle="$2"; shift 2 ;;
                --pid-file) pidfile="$2"; shift 2 ;;
                --console-socket) shift 2 ;;
                --preserve-fds) preserve="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        id="$1"
        if [ -e "$bundle/fail" ]; then
            cat "$bundle/fail" >&2
            exit 1
        fi
        mkdir -p "$root"
        if [ -n "${preserve:-}" ]; then
            echo "$preserve $(readlink /proc/$$/fd/3)" > "$root/$id.preserved"
        fi
        echo "$createargs" > "$root/$id.createargs"
        mkfifo "$root/$id.fifo"
        echo "$NOTIFY_SOCKET" > "$root/$id.notifyenv"
        cp "$bundle/notify_path" "$root/$id.notify" 2> /dev/null || : > "$root/$id.notify"
        # An asynchronous command has no stdin: keep ours for the init.
        exec 3<&0
        # (bash, not sh: bash execs the last command of -c, so the init becomes
        # the command, "sleep" and not a shell around it; dash, the sh of
        # Debian and Ubuntu, keeps the shell)
        # The init and its start time (field 22 of its stat, after the comm):
        # the fixture ends it by that identity, which its exec keeps.
        ( read go < "$root/$id.fifo"; [ "$go" = go ] || exit 0; exec bash -c "$(cat "$bundle/cmd")" <&3 3<&- ) &
        init=$!
        echo "$init $(awk '{ sub(/.*\) /, ""); print $20 }' /proc/$init/stat)" >> "$root/pids"
        echo $init > "$pidfile"
        exit 0
        ;;
    start)
        echo go > "$root/$1.fifo"
        # What a container with sd_notify does at start.
        if [ -s "$root/$1.notify" ] && [ -e "$root/$1.sendready" ]; then
            python3 -I -c 'import os, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.sendto(sys.argv[2].encode(), sys.argv[1])' "$(cat "$root/$1.notify")" "READY=1
MAINPID=1
STATUS=from the container"
        fi
        ;;
    delete)
        [ "$1" = "--force" ] && shift
        # an init that was never started waits in the open of its fifo,
        # which no removal wakes: it is told to go away
        if [ -p "$root/$1.fifo" ]; then
            exec 4<> "$root/$1.fifo"
            echo stop >&4
            exec 4>&-
        fi
        rm -f "$root/$1.fifo"
        echo "$1" >> "$root/deleted"
        ;;
    pause|resume)
        echo "$cmd $1" >> "$root/calls"
        ;;
    update)
        # (a limit the kernel does not take is told as the runtime tells it)
        if grep -q refused "$2"; then
            echo "writing file cpuset.cpus: Invalid argument" >&2
            exit 1
        fi
        cp "$2" "$root/$3.resources"
        ;;
    checkpoint)
        # (the directories come as places in the monitor's table of
        # descriptors: what they are is what the runtime would write to; the
        # parent is relative to the images, as CRIU takes it)
        image=""; parent=""
        while [ $# -gt 1 ]; do
            case "$1" in
                --image-path) image="$(readlink -f "$2")"; shift 2 ;;
                --parent-path) parent="$2"; shift 2 ;;
                --work-path) shift 2 ;;
                *) shift ;;
            esac
        done
        [ -z "$parent" ] || parent="$(cd "$image" && readlink -f "$parent")"
        echo "image=$image parent=$parent" > "$root/checkpoint"
        ;;
    exec)
        pidfile=""; process=""; detach=""
        while [ $# -gt 1 ]; do
            case "$1" in
                --detach|-d) detach=1; shift ;;
                --pid-file) pidfile="$2"; shift 2 ;;
                --process|-p) process="$2"; shift 2 ;;
                --console-socket|--preserve-fds) shift 2 ;;
                --tty) shift ;;
                *) break ;;
            esac
        done
        shift  # the container id
        # The command, its environment and its directory: the process file.
        eval "$(python3 -I -c 'import json, shlex, sys
p = json.load(open(sys.argv[1]))
print("set -- " + " ".join(shlex.quote(a) for a in p["args"]))
print("envs=" + shlex.quote(" ".join(p.get("env", []))))
print("cwd=" + shlex.quote(p.get("cwd", "")))' "$process")"
        if [ "$1" = "/does/not/exist" ]; then
            echo "crun: executable file \`$1\` not found in \$PATH: No such file or directory" >&2
            exit 1
        fi
        # (a test may delay the start: it is an event the monitor waits for)
        [ -f "$root/exec.delay" ] && sleep "$(cat "$root/exec.delay")"
        # Like the real thing: the command is a session leader whose pid is
        # in the pid file; detached, the runtime exits once it started it
        # (the command keeps the input: not the /dev/null of a `&`).
        start () {
            exec setsid sh -c 'envs="$0"; cwd="$1"; shift; [ -n "$cwd" ] && cd "$cwd"; for e in $envs; do export "$e"; done; exec "$@"' "$envs" "$cwd" "$@"
        }
        [ -n "$detach" ] || { echo "fake runtime: exec without --detach" >&2; exit 2; }
        exec 3<&0
        # (a runtime that names a process that is nobody's child)
        if [ -f "$root/exec.badpid" ]; then
            echo 1 > "$pidfile"
            exit 0
        fi
        # Like crun when it joins a pid namespace: the command is handed to
        # the monitor (its subreaper) as the runtime's child goes away, and
        # may be gone before the pid file is written.  It starts only once
        # the child is gone (the end of the fifo only the child writes to),
        # so that no shell of the runtime ever reaps it.
        mkfifo "$pidfile.gone"
        (
            exec 4<> "$pidfile.gone" 5< "$pidfile.gone"
            ( exec 4>&-; read -r _ <&5; exec 5<&-; start "$@" ) <&3 3<&- &
            echo $! > "$pidfile.tmp"
        )
        rm -f "$pidfile.gone"
        if [ -f "$root/exec.early" ]; then
            # (the exit of a process that is not ours: its pidfd)
            python3 -I -c 'import os, select, sys
select.select([os.pidfd_open(int(sys.argv[1]))], [], [])' "$(cat "$pidfile.tmp")" 2> /dev/null || :
        fi
        mv "$pidfile.tmp" "$pidfile"
        exit 0
        ;;
    *) echo "fake runtime: $cmd" >&2; exit 2 ;;
esac
"#;

/// The store and the events of a container the monitor records into.
pub struct StoreFx {
    pub db: PathBuf,
    pub events: PathBuf,
}

impl StoreFx {
    /// Another container's row, in `state`.
    pub fn add_container(&self, id: &str, state: velarx_db::RecordState) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d = velarx_db::Database::open(&self.db).await.unwrap();
            d.insert_container(&velarx_db::ContainerRecord {
                id: id.into(),
                name: Some(id.into()),
                image_id: "-rootfs-".into(),
                config: "{}".into(),
                state,
                created_at: "2026-01-01T00:00:00Z".into(),
                ..Default::default()
            })
            .await
            .unwrap();
            d.close().await.unwrap();
        });
    }

    /// A container of the image `image`.
    pub fn add_container_of(&self, id: &str, image: &str) {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        conn.execute(
            "INSERT INTO containers (id, name, image_id, config, state, created_at)
             VALUES (?1, ?1, ?2, '{}', 'stopped', '2026-01-01T00:00:00Z')",
            [id, image],
        )
        .unwrap();
    }

    /// An image `id` with the names `names` (repository, tag).
    pub fn add_image(&self, id: &str, names: &[(&str, &str)]) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d = velarx_db::Database::open(&self.db).await.unwrap();
            let digest = |c: char| -> velarx_types::digest::Digest {
                format!("sha256:{}", c.to_string().repeat(64))
                    .parse()
                    .unwrap()
            };
            d.insert_image(&velarx_db::ImageRecord {
                id: id.into(),
                manifest_digest: digest('a'),
                config_digest: digest('b'),
                manifest: "{}".into(),
                config: "{}".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                is_lazy: false,
            })
            .await
            .unwrap();
            for (repository, tag) in names {
                d.insert_image_tag(&velarx_db::ImageTag {
                    repository: repository.to_string(),
                    tag: tag.to_string(),
                    image_id: id.into(),
                })
                .await
                .unwrap();
            }
            d.close().await.unwrap();
        });
    }

    /// The names the image `id` has, and whether the store says its layers
    /// are left to collect.
    pub fn image_names(&self, id: &str) -> (Vec<String>, bool) {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        let mut stmt = conn
            .prepare("SELECT repository || ':' || tag FROM image_tags WHERE image_id = ?1")
            .unwrap();
        let names = stmt
            .query_map([id], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<String>, _>>()
            .unwrap();
        let pending = conn
            .query_row(
                "SELECT 1 FROM store_settings WHERE key = 'gc_pending'",
                [],
                |_| Ok(()),
            )
            .is_ok();
        (names, pending)
    }

    /// Whether the image `id` is in the store.
    pub fn has_image(&self, id: &str) -> bool {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        conn.query_row("SELECT 1 FROM images WHERE id = ?1", [id], |_| Ok(()))
            .is_ok()
    }

    /// The state the pod `id` has in its record.
    pub fn pod_state(pods: &Path, id: &str) -> String {
        let pod: serde_json::Value =
            serde_json::from_slice(&std::fs::read(pods.join(format!("{id}.json"))).unwrap())
                .unwrap();
        pod["state"].as_str().unwrap().to_string()
    }

    /// The container's row: its state and exit code.
    pub fn row(&self) -> Option<(String, Option<i64>)> {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        conn.query_row(
            "SELECT state, exit_code FROM containers WHERE id = 'abcdef123456'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()
    }

    /// The events kept: `type/action` of each line, in order.
    pub fn events(&self) -> Vec<String> {
        std::fs::read_to_string(&self.events)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .map(|v| {
                format!(
                    "{}/{}",
                    v["Type"].as_str().unwrap(),
                    v["Status"].as_str().unwrap()
                )
            })
            .collect()
    }

    /// The health the row has.
    pub fn health(&self) -> Option<String> {
        let conn = rusqlite::Connection::open(&self.db).unwrap();
        conn.query_row(
            "SELECT health FROM container_ext WHERE container_id = 'abcdef123456'",
            [],
            |r| r.get(0),
        )
        .ok()
        .flatten()
    }
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub run_dir: PathBuf,
    pub bundle: PathBuf,
    pub runtime: PathBuf,
    pub root: PathBuf,
    pub log: PathBuf,
    pub config: MonitorConfig,
    /// The `NOTIFY_SOCKET` of the environment the monitor starts in.
    pub notify: Option<PathBuf>,
    /// The monitors started (pidfds): killed with the fixture, so that a
    /// test that fails or times out leaves none, nor what they started.
    pub monitors: Mutex<Vec<OwnedFd>>,
    /// The directory of a root file system the test mounts outside of
    /// `dir` (the command that checks it names its path before the
    /// fixture exists): removed with the fixture, after its monitors.
    pub mount_dir: Option<tempfile::TempDir>,
}

impl Drop for Fixture {
    /// Nothing the test started outlives it: its monitors, and the inits
    /// of the fake runtime (one never started waits for ever in the open of
    /// its fifo), whatever the test came to.
    fn drop(&mut self) {
        use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};
        for fd in self
            .monitors
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            let _ = pidfd_send_signal(&fd, Signal::KILL);
        }
        let inits = std::fs::read_to_string(self.root.join("pids")).unwrap_or_default();
        for (pid, started) in inits.lines().filter_map(parse_init) {
            let Some(pidfd) =
                Pid::from_raw(pid).and_then(|p| pidfd_open(p, PidfdFlags::empty()).ok())
            else {
                continue;
            };
            // Still the init the runtime made, checked after the pidfd is
            // open: the start time it recorded, which no `exec` changes and a
            // reused pid does not have. (Had the init gone and its pid been
            // reused between the two, the pidfd is of a dead process.)
            let ours = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| start_time(&s))
                == Some(started);
            if ours {
                let _ = pidfd_send_signal(&pidfd, Signal::KILL);
            }
        }
    }
}

/// A line of the `pids` file of the fake runtime: `pid` and the start time
/// it recorded of that init (`starttime`, field 22 of `/proc/<pid>/stat`).
pub fn parse_init(line: &str) -> Option<(i32, i64)> {
    let mut it = line.split_whitespace();
    let pid = it.next()?.parse().ok()?;
    let started = it.next()?.parse().ok()?;
    Some((pid, started))
}

/// `starttime` (field 22) of a `/proc/<pid>/stat` line: it is what the
/// kernel says of the process, after the comm that may hold a space.
pub fn start_time(stat: &str) -> Option<i64> {
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// What the tests ask a monitor (the methods of `org.velarx.Monitor`).
#[derive(Debug, Clone)]
pub enum Ctl {
    Status,
    Start {
        attach_wait_ms: u64,
    },
    Stop {
        signal: Option<i32>,
        timeout_ms: Option<u64>,
    },
    Kill(i32),
    Pause,
    Resume,
    Wait,
    CoreStatus,
    Quit,
    HealthRun,
    Checkpoint(CheckpointRequest, PathBuf, Option<PathBuf>),
    Update(MonitorUpdate),
}

/// What a call came to: the status or the health it answered, or the
/// reason of its error.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub ok: bool,
    pub error: Option<String>,
    pub status: Option<Status>,
    pub health: Option<Health>,
    pub core: Option<velarx_wire::monitor::proto::CoreStatus>,
    /// A `Stop` needed SIGKILL.
    pub killed: bool,
}

impl Reply {
    fn of<T>(r: std::io::Result<T>, f: impl FnOnce(T, &mut Reply)) -> Reply {
        let mut reply = Reply::default();
        match r {
            Ok(v) => {
                reply.ok = true;
                f(v, &mut reply);
            }
            Err(e) => reply.error = Some(e.to_string()),
        }
        reply
    }
}

/// The engine's connection of a monitor: its events.
pub struct Events {
    conn: Mutex<Conn>,
    /// A copy of the socket, to wait on.
    pub poll_fd: OwnedFd,
}

impl Events {
    pub fn new(conn: Conn) -> Self {
        let poll_fd = conn.socket().as_fd().try_clone_to_owned().unwrap();
        Self {
            conn: Mutex::new(conn),
            poll_fd,
        }
    }

    /// The reply of `Create`, the first one (20 s at most).
    pub fn created(
        &self,
    ) -> Result<velarx_wire::monitor::iface::StatusReply, velarx_wire::varlink::CallError> {
        let mut conn = self.conn.lock().unwrap();
        conn.set_deadline(Instant::now() + Duration::from_secs(20));
        conn.reply::<velarx_wire::monitor::iface::StatusReply>()
            .map(|r| r.parameters)
    }

    /// The next reply of the subscription (20 s at most).
    pub fn next(&self) -> Result<Subscribed, velarx_wire::varlink::CallError> {
        let mut conn = self.conn.lock().unwrap();
        conn.set_deadline(Instant::now() + Duration::from_secs(20));
        conn.reply::<Subscribed>().map(|r| r.parameters)
    }
}

/// The daemon's side of a started monitor.
pub struct Started {
    pub child: Child,
    pub events: Events,
    pub first: Reply,
}

impl Fixture {
    /// A container that runs the shell command `cmd`.
    pub fn new(cmd: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let run_dir = base.join("run");
        let bundle = base.join("bundle");
        let root = base.join("root");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("cmd"), cmd).unwrap();
        // (the process of an exec is the container's, with its command)
        std::fs::write(bundle.join("config.json"), r#"{"process": {}}"#).unwrap();
        let runtime = base.join("fake-runtime");
        velarx_base::testing::write_script(&runtime, FAKE_RUNTIME);
        let log = base.join("log").join("container.log");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        let config = MonitorConfig {
            public_rootfs: None,
            id: "abcdef123456".into(),
            runtime: runtime.clone(),
            runtime_args: vec![],
            runtime_root: root.clone(),
            open_files: None,
            no_new_keyring: false,
            create_config: false,
            bundle: bundle.clone(),
            tty: false,
            group_add: Vec::new(),
            groups_strict: false,
            env_has_home: false,
            stdin_open: false,
            console_socket: None,
            log: LogConfig {
                driver: LogDriver::K8sFile,
                path: log.clone(),
                ..Default::default()
            },
            drain_ms: 1000,
            client_stall_ms: 30_000,
            timeout_secs: None,
            health: None,
            stop_signal: 15,
            sdnotify: Default::default(),
            image: None,
            hold_ports: Vec::new(),
            stop_timeout_secs: 10,
            restart: Default::default(),
            settle: None,
            leave_parent: false,
            fds: Default::default(),
            preserve_holes: Vec::new(),
            notify_label: None,
            pid_file: None,
            monitor_pid_file: None,
            private_mounts: false,
            auto_remove: false,
        };
        Self {
            dir,
            run_dir,
            bundle,
            runtime,
            root,
            log,
            config,
            notify: None,
            monitors: Mutex::new(Vec::new()),
            mount_dir: None,
        }
    }

    /// A monitor this test started, killed with the fixture.
    /// A store of the test (one container row, running), the events file and
    /// the plan the monitor records and removes with.
    pub fn with_store(&mut self) -> StoreFx {
        use velarx_runtime::settle::{RemovalPlan, SettlePlan};
        let db = self.dir.path().join("db.sqlite");
        let id = self.config.id.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d = velarx_db::Database::open(&db).await.unwrap();
            d.insert_container(&velarx_db::ContainerRecord {
                id: id.clone(),
                name: Some("fx".into()),
                image_id: "-rootfs-".into(),
                config: "{}".into(),
                state: velarx_db::RecordState::Running,
                pid: Some(1),
                created_at: "2026-01-01T00:00:00Z".into(),
                started_at: Some("2026-01-01T00:00:01Z".into()),
                finished_at: None,
                exit_code: None,
            })
            .await
            .unwrap();
            d.close().await.unwrap();
        });
        let events = self.dir.path().join("events/events.log");
        std::fs::create_dir_all(events.parent().unwrap()).unwrap();
        let mon = self.dir.path().join("mon");
        self.config.settle = Some(SettlePlan {
            id: id.clone(),
            db: db.clone(),
            start_lock: mon.join(format!("{id}.lock")),
            storage_lock: self.dir.path().join("storage.lock"),
            events: velarx_wire::events::log::EventLog::File {
                path: events.clone(),
                max_size: 1 << 20,
            },
            network: None,
            image: None,
            cgroup: None,
            pod: None,
            removal: RemovalPlan {
                bundle: self.bundle.clone(),
                mon_dir: self.run_dir.clone(),
                log_dir: self.log.parent().unwrap().to_path_buf(),
                secrets_dir: self.dir.path().join("secrets"),
                public_rootfs: None,
                named_files: Vec::new(),
                api_record: None,
                volumes_dir: self.dir.path().join("volumes"),
                lock_files: Vec::new(),
                writable: velarx_graph::WritableRelease::InBundle { pin: None },
            },
        });
        StoreFx { db, events }
    }

    pub fn watch(&self, pid: u32) {
        let fd = rustix::process::Pid::from_raw(pid as i32).and_then(|p| {
            rustix::process::pidfd_open(p, rustix::process::PidfdFlags::empty()).ok()
        });
        if let Some(fd) = fd {
            self.monitors
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(fd);
        }
    }

    pub fn start_monitor(&self) -> Started {
        self.start_monitor_with(&[])
    }

    /// [`Self::start_monitor`], with `mounts` as the descriptors the engine
    /// passes after 3 (4, 5, ...): those of the root file system, as many as
    /// the configuration says.
    pub fn start_monitor_with(&self, mounts: &[std::os::fd::BorrowedFd<'_>]) -> Started {
        self.start_monitor_calling(mounts, |s| {
            client::write_boot_calls(s, None).unwrap();
        })
    }

    /// [`Self::start_monitor_with`], with the calls `boot` writes on the
    /// first connection before the monitor starts.
    pub fn start_monitor_calling(
        &self,
        mounts: &[std::os::fd::BorrowedFd<'_>],
        boot: impl FnOnce(&UnixStream),
    ) -> Started {
        self.config.write(&self.run_dir).unwrap();
        let (daemon_end, monitor_end) = UnixStream::pair().unwrap();
        boot(&daemon_end);
        let mut cmd = Command::new(monitor_binary());
        cmd.arg("--varlink-fd")
            .arg("3")
            .arg(&self.run_dir)
            .stdin(Stdio::null());
        match &self.notify {
            Some(t) => cmd.env("NOTIFY_SOCKET", t),
            None => cmd.env_remove("NOTIFY_SOCKET"),
        };
        let raw = monitor_end.as_raw_fd();
        let mut places = vec![(raw, 3)];
        places.extend(
            mounts
                .iter()
                .enumerate()
                .map(|(i, m)| (m.as_raw_fd(), 4 + i as i32)),
        );
        let first_closed = 4 + mounts.len() as u32;
        velarx_sys::exec::place_fds(&mut cmd, places);
        // Only descriptor 3 and the mounts, as the engine passes them
        // (`spawn::command`): nothing the test process inherited (the lock of
        // a build slot that runs it) reaches the monitor and the runtime it
        // forks.
        velarx_sys::spawn::pre_exec(&mut cmd, move |child| {
            child.cloexec_from(first_closed);
            Ok(())
        });
        let child = cmd.spawn().unwrap();
        self.watch(child.id());
        drop(monitor_end);
        let events = Events::new(Conn::from_stream(daemon_end));
        let first = match events.created() {
            Ok(s) => Reply {
                ok: true,
                status: Some(s.status),
                ..Reply::default()
            },
            Err(e) => Reply {
                error: Some(e.to_string()),
                ..Reply::default()
            },
        };
        Started {
            child,
            events,
            first,
        }
    }

    pub fn wait_for_exit(&self, started: &mut Started) -> ExitInfo {
        let ev = wait_event(&started.events, |e| matches!(e, Event::Exited(_)));
        let Event::Exited(info) = ev else {
            unreachable!()
        };
        let status = started.child.wait().unwrap();
        assert_eq!(
            status.code(),
            Some(info.code & 0xff),
            "monitor status {status:?}"
        );
        info
    }

    pub fn log_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        velarx_wire::monitor::logfmt::read_logs(&self.log, &Default::default(), None, &mut |r| {
            out.push(format!(
                "{} {} {}",
                if r.stream == velarx_wire::monitor::logfmt::Stream::Stdout {
                    "out"
                } else {
                    "err"
                },
                if r.partial { "P" } else { "F" },
                String::from_utf8_lossy(&r.content)
            ));
            Ok(())
        })
        .unwrap();
        out
    }
}

pub fn wait_event(events: &Events, want: impl Fn(&Event) -> bool) -> Event {
    loop {
        match events.next() {
            Ok(Subscribed { event: Some(e), .. }) => {
                let ev = e.into_event().expect("an event with what its kind needs");
                if want(&ev) {
                    return ev;
                }
            }
            Ok(_) => continue,
            Err(e) => panic!("the monitor hung up: {e}"),
        }
    }
}

pub fn ctl(dir: &Path, req: &Ctl) -> Reply {
    match req.clone() {
        Ctl::Status => Reply::of(client::status(dir), |s, r| r.status = Some(s)),
        Ctl::Start { attach_wait_ms } => {
            Reply::of(client::start(dir, attach_wait_ms), |s, r| r.status = s)
        }
        Ctl::Stop { signal, timeout_ms } => {
            Reply::of(client::stop(dir, signal, timeout_ms), |(s, killed), r| {
                r.core = Some(s);
                r.killed = killed;
            })
        }
        Ctl::Pause => Reply::of(client::pause(dir), |s, r| r.status = Some(s)),
        Ctl::Resume => Reply::of(client::resume(dir), |s, r| r.status = Some(s)),
        Ctl::Kill(signal) => Reply::of(client::kill(dir, signal), |_, _| {}),
        Ctl::Wait => Reply::of(client::wait(dir), |s, r| r.core = Some(s)),
        Ctl::CoreStatus => Reply::of(client::core_status(dir), |s, r| r.core = Some(s)),
        Ctl::Quit => Reply::of(client::quit(dir), |_, _| {}),
        Ctl::HealthRun => Reply::of(client::run_health_check(dir), |h, r| r.health = Some(h)),
        Ctl::Checkpoint(c, images, parent) => {
            let open = |p: &Path| std::fs::File::open(p).unwrap();
            let (images, parent) = (open(&images), parent.map(|p| open(&p)));
            Reply::of(
                client::checkpoint(dir, &c, images.as_fd(), parent.as_ref().map(|p| p.as_fd())),
                |s, r| r.status = Some(s),
            )
        }
        Ctl::Update(u) => Reply::of(client::update(dir, &u, None, None), |_, _| {}),
    }
}

/// An attach or exec session of a test: its connection and its pipes.
pub struct Session {
    pub conn: Conn,
    pub stdin: Option<std::fs::File>,
    pub stdout: Option<std::fs::File>,
    pub stderr: Option<std::fs::File>,
    exec: bool,
    /// The container had ended (an attach): its status.
    pub exit: Option<i32>,
}

fn file(fd: Option<OwnedFd>) -> Option<std::fs::File> {
    fd.map(std::fs::File::from)
}

/// Attach to the container of the monitor in `dir`.
pub fn attach_session(dir: &Path, want: &velarx_wire::monitor::proto::Attach) -> Session {
    let s = client::open_attach(dir, want).unwrap();
    Session {
        conn: s.conn,
        stdin: file(s.streams.stdin),
        stdout: file(s.streams.stdout),
        stderr: file(s.streams.stderr),
        exec: false,
        exit: s.exit,
    }
}

/// Run a command in the container of the monitor in `dir`.
pub fn exec_session(
    dir: &Path,
    req: &velarx_wire::monitor::proto::ExecRequest,
) -> std::io::Result<Session> {
    let s = client::open_exec(dir, req)?;
    Ok(Session {
        conn: s.conn,
        stdin: file(s.streams.stdin),
        stdout: file(s.streams.stdout),
        stderr: file(s.streams.stderr),
        exec: true,
        exit: None,
    })
}

/// How a session ended: its output, its errors, its status and why
/// (`exited`, `timed_out`, `cancelled`).
#[derive(Debug, PartialEq, Eq)]
pub struct Ended {
    pub out: String,
    pub err: String,
    pub code: i32,
    pub reason: iface::ExecReason,
}

impl Session {
    pub fn write(&mut self, data: &[u8]) {
        self.stdin.as_mut().unwrap().write_all(data).unwrap();
    }

    /// The input ends.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
        self.conn.oneway_method(&iface::CloseStdin {}).unwrap();
    }

    pub fn signal(&mut self, signal: i32) {
        self.conn
            .oneway_method(&iface::SignalParams { signal })
            .unwrap();
    }

    pub fn detach(&mut self) {
        self.conn.oneway_method(&iface::Detach {}).unwrap();
    }

    /// Read the output until it has `needle` (20 s at most): what was read.
    pub fn read_until(&mut self, needle: &str) -> String {
        use std::io::Read;
        let out = self.stdout.as_mut().unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(20);
        while !String::from_utf8_lossy(&seen).contains(needle) {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "no {needle:?} in {:?}",
                String::from_utf8_lossy(&seen)
            );
            velarx_wire::monitor::proto::wait_fd(
                &*out,
                rustix::event::PollFlags::IN,
                left.as_millis() as i32,
            )
            .unwrap();
            match out.read(&mut buf).unwrap() {
                0 => panic!("the output ended before {needle:?}"),
                n => seen.extend_from_slice(&buf[..n]),
            }
        }
        String::from_utf8(seen).unwrap()
    }

    /// Read the pipes to their end and the last reply.
    pub fn finish(mut self) -> Ended {
        use std::io::Read;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut buf = [0u8; 65536];
        while self.stdout.is_some() || self.stderr.is_some() {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "the pipes do not end");
            let mut fds: Vec<rustix::event::PollFd<'_>> = [&self.stdout, &self.stderr]
                .into_iter()
                .flatten()
                .map(|f| rustix::event::PollFd::new(f, rustix::event::PollFlags::IN))
                .collect();
            velarx_wire::monitor::proto::poll(&mut fds, left.as_millis() as i32).unwrap();
            drop(fds);
            for (slot, to) in [(&mut self.stdout, &mut out), (&mut self.stderr, &mut err)] {
                let Some(f) = slot.as_mut() else { continue };
                if !velarx_wire::monitor::proto::wait_fd(&*f, rustix::event::PollFlags::IN, 0)
                    .unwrap()
                {
                    continue;
                }
                match f.read(&mut buf) {
                    Ok(0) | Err(_) => *slot = None,
                    Ok(n) => to.extend_from_slice(&buf[..n]),
                }
            }
        }
        self.conn
            .set_deadline(Instant::now() + Duration::from_secs(20));
        let (code, reason) = match self.exit {
            Some(code) => (code, iface::ExecReason::Exited),
            None => loop {
                if self.exec {
                    let r = self.conn.reply::<iface::ExecReply>().unwrap();
                    if let Some(e) = r.parameters.exit {
                        break (e.code, e.reason);
                    }
                } else {
                    let r = self.conn.reply::<iface::AttachReply>().unwrap();
                    if let Some(c) = r.parameters.exit {
                        break (c, iface::ExecReason::Exited);
                    }
                }
            },
        };
        Ended {
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
            code,
            reason,
        }
    }
}

pub fn status_state(dir: &Path) -> RunState {
    ctl(dir, &Ctl::Status).status.unwrap().state
}

/// A user and mount namespace of this process (the test runs in a child
/// of the test binary), as root or as a user: the monitor it starts is in it,
/// and what it mounts is seen only here.  False where the kernel gives the
/// user none.
pub fn namespace() -> bool {
    use rustix::thread::UnshareFlags;
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let root = rustix::process::geteuid().is_root();
    let flags = if root {
        UnshareFlags::NEWNS
    } else {
        UnshareFlags::NEWNS | UnshareFlags::NEWUSER
    };
    if velarx_sys::ns::unshare(flags).is_err() {
        eprintln!("SKIPPED: no mount namespace for this user");
        return false;
    }
    if !root {
        std::fs::write("/proc/self/setgroups", "deny").unwrap();
        std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).unwrap();
        std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).unwrap();
    }
    rustix::mount::mount_change(
        "/",
        rustix::mount::MountPropagationFlags::PRIVATE | rustix::mount::MountPropagationFlags::REC,
    )
    .unwrap();
    true
}
