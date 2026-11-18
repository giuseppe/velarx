// SPDX-License-Identifier: Apache-2.0
//! The monitor of a container that a systemd unit runs: the monitor itself,
//! its exit status when a stop was asked for, and how it leaves the process
//! that started it.

use crate::monitor_common::*;
use std::time::{Duration, Instant};
use velarx_wire::monitor::client;
use velarx_wire::monitor::proto::Event;

/// The restarts and the exit of a container are in its row and its events,
/// in order, before the monitor exits: there is no engine.
#[test]
fn the_exit_is_in_the_store_before_the_monitor_exits() {
    let mut fx = Fixture::new("exit 4");
    let store = fx.with_store();
    let Started {
        mut child, events, ..
    } = fx.start_monitor();
    drop(events);
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    assert_eq!(child.wait().unwrap().code(), Some(4));
    assert_eq!(store.row(), Some(("stopped".into(), Some(4))));
    // (the container ends for good and stays: its cleanup follows the died)
    assert_eq!(store.events(), ["container/died", "container/cleanup"]);
}

#[test]
fn the_restarts_and_the_exit_are_recorded_in_order() {
    let mut fx = Fixture::new("exit 1");
    let store = fx.with_store();
    fx.config.restart.policy = Some(velarx_wire::monitor::proto::RestartSettings {
        policy: velarx_wire::monitor::proto::RestartPolicy::OnFailure,
        max_retries: 2,
    });
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    fx.wait_for_exit(&mut m);
    assert_eq!(store.row(), Some(("stopped".into(), Some(1))));
    // a died event for each exit, a restart event for each start again, and
    // one cleanup after the last exit
    let events = store.events();
    assert_eq!(events.iter().filter(|e| *e == "container/died").count(), 3);
    assert_eq!(
        events.iter().filter(|e| *e == "container/restart").count(),
        2
    );
    assert_eq!(
        events[events.len().saturating_sub(2)..],
        ["container/died", "container/cleanup"]
    );
}

#[test]
fn the_attached_clients_are_told_of_the_exit_once_it_is_recorded() {
    use std::os::fd::AsFd;
    use velarx_runtime::monitor::relay::{self, AttachEnd, AttachOptions};
    let mut fx = Fixture::new("exit 6");
    let store = fx.with_store();
    let m = fx.start_monitor();
    // (the monitor waits for the client to attach before it starts it)
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 10_000
            }
        )
        .ok
    );
    let (_out_r, out_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (_err_r, err_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (in_r, _in_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let dir = fx.run_dir.clone();
    let client = std::thread::spawn(move || {
        relay::attach(
            &dir,
            &AttachOptions {
                start: true,
                ..Default::default()
            },
            in_r.as_fd(),
            out_w.as_fd(),
            err_w.as_fd(),
        )
        .unwrap()
    });
    wait_event(&m.events, |e| matches!(e, Event::Exited(_)));
    assert_eq!(client.join().unwrap(), AttachEnd::Exited(6));
    // (the exit is in the store when the client hears of it)
    assert_eq!(store.row(), Some(("stopped".into(), Some(6))));
}

/// An `--rm` container is gone with its exit: the row, the bundle and the
/// log, before the clients are told.
#[test]
fn an_rm_container_is_removed_by_its_monitor() {
    let mut fx = Fixture::new("exit 0");
    let store = fx.with_store();
    fx.config.auto_remove = true;
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    fx.wait_for_exit(&mut m);
    assert_eq!(store.row(), None);
    assert!(!fx.bundle.exists());
    assert_eq!(store.events(), ["container/died", "container/remove"]);
}

/// The store is busy while the container exits: the exit lands once it is
/// free again, and the clients wait for it.
#[test]
fn a_busy_store_delays_the_exit_and_not_the_monitor() {
    let mut fx = Fixture::new("exit 0");
    let store = fx.with_store();
    let conn = rusqlite::Connection::open(&store.db).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    wait_event(&m.events, |e| matches!(e, Event::Exited(_)));
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(store.row().map(|r| r.0), Some("running".into()));
    conn.execute_batch("COMMIT").unwrap();
    assert_eq!(m.child.wait().unwrap().code(), Some(0));
    assert_eq!(store.row(), Some(("stopped".into(), Some(0))));
}

#[test]
fn a_stop_that_was_asked_for_is_a_clean_end_of_the_main_process_of_a_unit() {
    // A SIGTERM to the monitor (`systemctl stop` of its unit) stops the
    // container with its stop signal.
    let mut fx = Fixture::new("sleep 30");
    fx.notify = Some(fx.dir.path().join("no-manager-here"));
    let Started {
        mut child, events, ..
    } = fx.start_monitor();
    drop(events);
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    kill(child.id() as i32, libc::SIGTERM);
    assert_eq!(child.wait().unwrap().code(), Some(0));
    let info: velarx_wire::monitor::proto::ExitInfo = serde_json::from_slice(
        &std::fs::read(fx.run_dir.join(velarx_wire::monitor::proto::EXIT_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(info.code, 143);
    assert!(info.stop_requested);
}

#[test]
fn the_monitor_of_the_server_gives_the_status_of_a_stopped_container() {
    let fx = Fixture::new("sleep 30");
    let Started {
        mut child, events, ..
    } = fx.start_monitor();
    drop(events);
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    kill(child.id() as i32, libc::SIGTERM);
    assert_eq!(child.wait().unwrap().code(), Some(143));
}

#[test]
fn under_a_service_manager_the_monitor_leaves_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("systemd-notify");
    let server = std::os::unix::net::UnixDatagram::bind(&target).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut fx = Fixture::new("sleep 30");
    fx.config.sdnotify = velarx_runtime::monitor::notify::SdNotify::Conmon;
    fx.config.leave_parent = true;
    fx.notify = Some(target.clone());
    let mut m = fx.start_monitor();
    assert!(m.first.ok, "{:?}", m.first.error);
    // The process that was started is gone; the monitor goes on.
    let started = Instant::now();
    assert_eq!(m.child.wait().unwrap().code(), Some(0));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let mut buf = [0u8; 256];
    let n = server.recv(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    let pid: i32 = text
        .lines()
        .find_map(|l| l.strip_prefix("MAINPID="))
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no MAINPID in {text:?}"));
    assert_ne!(pid, m.child.id() as i32);
    // The main process is the monitor itself.
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap();
    assert_eq!(comm.trim(), "velarx-monitor");
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(pid).unwrap(),
        rustix::process::PidfdFlags::empty(),
    )
    .unwrap();
    kill(pid, libc::SIGTERM);
    wait_event(&m.events, |e| matches!(e, Event::Exited(_)));
    // The pidfd is readable once the monitor is gone.
    let mut pfd = [rustix::event::PollFd::new(
        &pidfd,
        rustix::event::PollFlags::IN,
    )];
    let timeout = rustix::event::Timespec {
        tv_sec: 10,
        tv_nsec: 0,
    };
    assert_eq!(rustix::event::poll(&mut pfd, Some(&timeout)).unwrap(), 1);
    assert!(fx
        .run_dir
        .join(velarx_wire::monitor::proto::EXIT_FILE)
        .exists());
    drop(m.events);
}

#[test]
fn the_sockets_of_a_socket_activation_reach_the_runtime_as_descriptor_3() {
    use std::os::fd::AsFd;
    let mut fx = Fixture::new("sleep 30");
    fx.config.fds = velarx_base::spawn::InheritedFds::layout(1, 0, false, false, false);
    fx.config.write(&fx.run_dir).unwrap();
    // A listening socket, as systemd passes it.
    let sock = std::os::unix::net::UnixListener::bind(fx.dir.path().join("l.sock")).unwrap();
    let ino = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&sock)
        ))
        .unwrap()
        .ino()
    };
    let (daemon_end, monitor_end) = std::os::unix::net::UnixStream::pair().unwrap();
    velarx_wire::monitor::client::write_boot_calls(&daemon_end, None).unwrap();
    let opts = velarx_base::spawn::SpawnOptions {
        preserve_fds: vec![std::sync::Arc::new(std::os::fd::OwnedFd::from(sock))],
        ..Default::default()
    };
    let mut cmd = velarx_base::spawn::command(
        &crate::monitor_common::monitor_binary(),
        &fx.run_dir,
        monitor_end.as_fd(),
        &opts,
    )
    .unwrap();
    let mut child = cmd.spawn().unwrap();
    fx.watch(child.id());
    drop(monitor_end);
    let events = Events::new(velarx_wire::varlink::Conn::from_stream(daemon_end));
    let first = events.created();
    assert!(first.is_ok(), "{:?}", first.err());
    let got = std::fs::read_to_string(fx.root.join("abcdef123456.preserved")).unwrap();
    assert_eq!(got.trim(), format!("1 socket:[{ino}]"));
    assert!(ctl(&fx.run_dir, &Ctl::Quit).ok);
    drop(events);
    let _ = child.wait();
}

#[test]
fn a_barrier_of_the_container_is_answered_and_not_forwarded() {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::os::fd::AsFd;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("systemd-notify");
    let manager = std::os::unix::net::UnixDatagram::bind(&target).unwrap();
    manager
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut fx = Fixture::new("sleep 30");
    fx.config.sdnotify = velarx_runtime::monitor::notify::SdNotify::Container;
    fx.notify = Some(target.clone());
    std::fs::write(
        fx.bundle.join("notify_path"),
        fx.run_dir
            .join("notify.d/notify.sock")
            .display()
            .to_string(),
    )
    .unwrap();
    let mut m = fx.start_monitor();
    assert!(m.first.ok, "{:?}", m.first.error);
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let mut buf = [0u8; 256];
    let n = manager.recv(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("MAINPID="));

    // What the container's sd_notify_barrier() does.
    let container = std::os::unix::net::UnixDatagram::unbound().unwrap();
    container
        .connect(fx.run_dir.join("notify.d/notify.sock"))
        .unwrap();
    container.send(b"STATUS=before the barrier").unwrap();
    let (r, w) = rustix::pipe::pipe().unwrap();
    let fds = [w.as_fd()];
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut anc = SendAncillaryBuffer::new(&mut space);
    assert!(anc.push(SendAncillaryMessage::ScmRights(&fds)));
    sendmsg(
        &container,
        &[std::io::IoSlice::new(b"BARRIER=1")],
        &mut anc,
        SendFlags::empty(),
    )
    .unwrap();
    drop(w);
    // The barrier is answered: the descriptor is closed once the monitor
    // took the message, after the ones before it.
    let mut pfd = [rustix::event::PollFd::new(&r, rustix::event::PollFlags::IN)];
    let timeout = rustix::event::Timespec {
        tv_sec: 5,
        tv_nsec: 0,
    };
    assert_eq!(rustix::event::poll(&mut pfd, Some(&timeout)).unwrap(), 1);
    assert_eq!(rustix::io::read(&r, &mut [0u8; 1]).unwrap(), 0);
    let n = manager.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"STATUS=before the barrier\n");
    // Nothing else came: BARRIER is the container's business.
    manager.set_nonblocking(true).unwrap();
    assert!(manager.recv(&mut buf).is_err());
    let pid = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    kill(pid, libc::SIGKILL);
    fx.wait_for_exit(&mut m);
}

/// A container with a regular check `regular` and a startup check
/// `startup` (shell commands), checked often.
fn startup_fixture(regular: &str, startup: &str, retries: u32, successes: u32) -> Fixture {
    use velarx_proto::health::{Healthcheck, OnFailure, StartupHealthcheck};
    let mut fx = Fixture::new("sleep 30");
    fx.config.health = Some(Healthcheck {
        test: vec!["CMD-SHELL".into(), regular.into()],
        interval_ns: 150_000_000,
        timeout_ns: 5_000_000_000,
        retries: 2,
        on_failure: OnFailure::None,
        startup: Some(StartupHealthcheck {
            test: vec!["CMD-SHELL".into(), startup.into()],
            interval_ns: 150_000_000,
            timeout_ns: 5_000_000_000,
            retries,
            successes,
        }),
        ..Default::default()
    });
    fx
}

fn health_of(ev: velarx_wire::monitor::proto::Event) -> velarx_wire::monitor::proto::Health {
    match ev {
        velarx_wire::monitor::proto::Event::Health(h) => h,
        _ => unreachable!(),
    }
}

#[test]
fn the_startup_check_runs_first_and_the_status_stays_starting() {
    use velarx_wire::monitor::proto::Event;
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("started");
    let count = dir.path().join("count");
    // fails twice (counting its runs), then passes
    let startup = format!(
        "echo x >> {c}; test $(wc -l < {c}) -ge 3",
        c = count.display()
    );
    let fx = startup_fixture(&format!("test -f {}", marker.display()), &startup, 0, 1);
    std::fs::write(&marker, "").unwrap();
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let mut seen = Vec::new();
    loop {
        let h = health_of(wait_event(&m.events, |e| matches!(e, Event::Health(_))));
        seen.push((
            h.status.word().to_string(),
            h.log.last().map(|r| r.exit_code),
        ));
        if h.status.word() != "starting" {
            break;
        }
    }
    // two failures and a success of the startup check, all `starting`,
    // then the regular check: healthy
    assert_eq!(
        seen,
        [
            ("starting".to_string(), Some(1)),
            ("starting".to_string(), Some(1)),
            ("starting".to_string(), Some(0)),
            ("healthy".to_string(), Some(0)),
        ]
    );
    let pid = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    kill(pid, libc::SIGKILL);
    fx.wait_for_exit(&mut m);
}

#[test]
fn a_startup_check_that_fails_its_retries_restarts_the_container() {
    use velarx_wire::monitor::proto::Event;
    let fx = startup_fixture("true", "false", 2, 1);
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let ev = wait_event(&m.events, |e| matches!(e, Event::Restarting { .. }));
    let Event::Restarting {
        exit,
        restart_count,
    } = ev
    else {
        unreachable!()
    };
    assert!(exit.health_restart);
    assert_eq!(restart_count, 1);
    // The new run starts with the startup check again: still starting.
    let h = health_of(wait_event(&m.events, |e| matches!(e, Event::Health(_))));
    assert_eq!(h.status.word(), "starting");
    assert!(ctl(&fx.run_dir, &Ctl::Kill(libc::SIGKILL)).ok);
    fx.wait_for_exit(&mut m);
}

#[test]
fn an_update_names_the_directory_of_the_health_log() {
    use velarx_proto::health::{Healthcheck, OnFailure};
    use velarx_wire::monitor::proto::{Event, HealthUpdate, MonitorUpdate};
    let dir = tempfile::tempdir().unwrap();
    let check = Healthcheck {
        test: vec!["CMD-SHELL".into(), "true".into()],
        interval_ns: 100_000_000,
        timeout_ns: 5_000_000_000,
        retries: 100,
        on_failure: OnFailure::None,
        startup: None,
        log_destination: dir.path().to_string_lossy().into_owned(),
        max_log_count: Some(2),
        max_log_size: Some(4),
        ..Default::default()
    };
    let fx = Fixture::new("sleep 30");
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let log_dir = std::fs::File::open(dir.path()).unwrap();
    client::update(
        &fx.run_dir,
        &MonitorUpdate {
            health: Some(HealthUpdate {
                check: Some(check),
                log_dir: None,
            }),
            ..Default::default()
        },
        None,
        Some(std::os::fd::AsFd::as_fd(&log_dir)),
    )
    .unwrap();
    wait_event(&m.events, |e| matches!(e, Event::Health(_)));
    let file = dir.path().join("abcdef123456-healthcheck.log");
    assert!(file.is_file(), "no results in the directory of the update");
    let pid = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    kill(pid, libc::SIGKILL);
    fx.wait_for_exit(&mut m);
}

#[test]
fn the_health_log_goes_to_a_directory_within_its_limits() {
    use velarx_proto::health::{Healthcheck, OnFailure};
    use velarx_wire::monitor::proto::Event;
    let dir = tempfile::tempdir().unwrap();
    let mut fx = Fixture::new("sleep 30");
    fx.config.health = Some(Healthcheck {
        test: vec!["CMD-SHELL".into(), "echo 0123456789; false".into()],
        interval_ns: 100_000_000,
        timeout_ns: 5_000_000_000,
        retries: 100,
        on_failure: OnFailure::None,
        startup: None,
        log_destination: dir.path().to_string_lossy().into_owned(),
        max_log_count: Some(2),
        max_log_size: Some(4),
        ..Default::default()
    });
    // (the engine opens the directory and passes it as the first descriptor
    // after the connection)
    let log_dir = std::fs::File::open(dir.path()).unwrap();
    fx.config.fds.health_log_dir = Some(4);
    let mut m = fx.start_monitor_with(&[std::os::fd::AsFd::as_fd(&log_dir)]);
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    for _ in 0..3 {
        wait_event(&m.events, |e| matches!(e, Event::Health(_)));
    }
    let file = dir.path().join("abcdef123456-healthcheck.log");
    let h: velarx_wire::monitor::proto::Health =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(h.log.len(), 2);
    assert!(h.log.iter().all(|r| r.output == "0123" && r.exit_code == 1));
    let pid = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    kill(pid, libc::SIGKILL);
    fx.wait_for_exit(&mut m);
}

#[test]
fn healthy_mode_says_ready_after_the_startup_and_the_first_regular_check() {
    use velarx_wire::monitor::proto::Event;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("systemd-notify");
    let manager = std::os::unix::net::UnixDatagram::bind(&target).unwrap();
    manager.set_nonblocking(true).unwrap();
    let marker = dir.path().join("started");
    let mut fx = startup_fixture("true", &format!("test -f {}", marker.display()), 0, 1);
    fx.config.sdnotify = velarx_runtime::monitor::notify::SdNotify::Healthy;
    fx.notify = Some(target.clone());
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    // The startup check fails a few times: no READY.
    for _ in 0..3 {
        let h = health_of(wait_event(&m.events, |e| matches!(e, Event::Health(_))));
        assert_eq!(h.status.word(), "starting");
    }
    let mut buf = [0u8; 256];
    let mut got = Vec::new();
    while let Ok(n) = manager.recv(&mut buf) {
        got.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    assert!(got.iter().all(|m| !m.contains("READY=1")), "{got:?}");
    std::fs::write(&marker, "").unwrap();
    loop {
        let h = health_of(wait_event(&m.events, |e| matches!(e, Event::Health(_))));
        if h.status.word() == "healthy" {
            break;
        }
    }
    manager.set_nonblocking(false).unwrap();
    manager
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut ready = false;
    while let Ok(n) = manager.recv(&mut buf) {
        if String::from_utf8_lossy(&buf[..n]).contains("READY=1") {
            ready = true;
            break;
        }
    }
    assert!(ready);
    let pid = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    kill(pid, libc::SIGKILL);
    fx.wait_for_exit(&mut m);
}

/// Whether process `pid` is gone (or a zombie) within `secs` (its pidfd).
fn gone_within(pid: i32, secs: u64) -> bool {
    velarx_base::testing::wait_exit(pid, std::time::Duration::from_secs(secs))
}

/// Whether the init `pid` that started at `started` runs `comm` (it has
/// gone through its `exec`) within `secs`.  (Polled: nothing tells another
/// process of an exec.)
fn runs_within(pid: i32, started: i64, comm: &str, secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let runs = stat
            .split_once(" (")
            .and_then(|(_, r)| r.rsplit_once(") "))
            .is_some_and(|(c, r)| c == comm && !r.starts_with('Z'));
        if runs && start_time(&stat) == Some(started) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// The inits of the fake runtime this fixture made, with their start times.
fn inits(fx: &Fixture) -> Vec<(i32, i64)> {
    std::fs::read_to_string(fx.root.join("pids"))
        .unwrap_or_default()
        .lines()
        .filter_map(parse_init)
        .collect()
}

#[test]
fn a_container_never_started_leaves_no_process_of_the_runtime() {
    // created, then the monitor told to quit: the runtime's init waited for
    // its start for ever (85 shells of earlier runs were found)
    let fx = Fixture::new("sleep 30");
    let Started {
        mut child, events, ..
    } = fx.start_monitor();
    let pids = inits(&fx);
    assert_eq!(pids.len(), 1);
    assert!(ctl(&fx.run_dir, &Ctl::Quit).ok);
    drop(events);
    let _ = child.wait();
    assert!(
        gone_within(pids[0].0, 10),
        "the init {} waits on",
        pids[0].0
    );
}

#[test]
fn a_fixture_ends_what_its_test_left_running() {
    // a test that fails (or times out) with its monitor and container
    // running: the fixture ends them when it goes
    let fx = Fixture::new("sleep 300");
    let Started { child, events, .. } = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let monitor = child.id() as i32;
    let pids = inits(&fx);
    assert_eq!(pids.len(), 1, "the runtime made no init");
    let (init, started) = pids[0];
    // the case that leaked: the init has exec'd into the command, so its
    // command line no longer names the runtime
    assert!(
        runs_within(init, started, "sleep", 10),
        "the container {init} did not come to run its command"
    );
    drop(fx);
    assert!(gone_within(monitor, 10), "the monitor runs on");
    assert!(gone_within(init, 10), "the container {init} runs on");
    drop(events);
    drop(child);
}

/// A container that lives a second, its health checked every 100 ms.
fn health_checked_fixture() -> Fixture {
    let mut fx = Fixture::new("sleep 1");
    fx.config.health = Some(velarx_proto::health::Healthcheck {
        test: vec!["CMD-SHELL".into(), "false".into()],
        interval_ns: 100_000_000,
        timeout_ns: 5_000_000_000,
        retries: 1000,
        on_failure: velarx_proto::health::OnFailure::None,
        startup: None,
        ..Default::default()
    });
    fx
}

#[test]
fn the_health_results_are_recorded_with_no_engine() {
    let mut fx = health_checked_fixture();
    let store = fx.with_store();
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    fx.wait_for_exit(&mut m);
    let health: serde_json::Value = serde_json::from_str(&store.health().unwrap()).unwrap();
    assert!(health["status"].is_string(), "{health}");
    assert!(
        store
            .events()
            .iter()
            .filter(|e| *e == "container/health_status")
            .count()
            >= 2
    );
}

/// An attach after the exit gets the exit once it is recorded: the client
/// finds the container as it ended.  (The store is busy meanwhile, so that
/// the monitor is still there to be asked.)
#[test]
fn an_attach_after_the_exit_gets_the_recorded_exit() {
    let mut fx = Fixture::new("exit 6");
    let store = fx.with_store();
    let busy = rusqlite::Connection::open(&store.db).unwrap();
    busy.execute_batch("BEGIN IMMEDIATE").unwrap();
    let m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    wait_event(&m.events, |e| matches!(e, Event::Exited(_)));
    let dir = fx.run_dir.clone();
    let attach = std::thread::spawn(move || {
        client::open_attach(
            &dir,
            &velarx_wire::monitor::proto::Attach {
                stdout: false,
                stderr: false,
                ..Default::default()
            },
        )
        .unwrap()
    });
    // (a call of a local socket takes far less: the exit is not recorded
    // yet, the attach waits for it)
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !attach.is_finished(),
        "the attach did not wait for the record"
    );
    busy.execute_batch("COMMIT").unwrap();
    assert_eq!(attach.join().unwrap().exit, Some(6));
    assert_eq!(store.row(), Some(("stopped".into(), Some(6))));
}

/// The reply of a stop comes when the exit is recorded.
#[test]
fn a_stop_is_answered_when_the_exit_is_recorded() {
    let mut fx = Fixture::new("sleep 30");
    let store = fx.with_store();
    let m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let reply = ctl(
        &fx.run_dir,
        &Ctl::Stop {
            signal: None,
            timeout_ms: None,
        },
    );
    assert!(reply.ok, "{:?}", reply.error);
    assert!(reply.core.unwrap().recorded);
    assert_eq!(store.row().map(|r| r.0), Some("stopped".into()));
    drop(m);
}

/// An update says whether the container goes with its exit: the row stays
/// when it does not.
#[test]
fn an_update_that_keeps_the_container_keeps_its_row() {
    use velarx_wire::monitor::proto::{ExitPlan, MonitorUpdate};
    let mut fx = Fixture::new("sleep 30");
    let store = fx.with_store();
    fx.config.auto_remove = true;
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    assert!(ctl(&fx.run_dir, &Ctl::Status).status.unwrap().plan.remove);
    let u = MonitorUpdate {
        plan: Some(ExitPlan {
            remove: false,
            volumes: false,
        }),
        ..Default::default()
    };
    assert!(ctl(&fx.run_dir, &Ctl::Update(u)).ok);
    assert!(ctl(&fx.run_dir, &Ctl::Kill(libc::SIGKILL)).ok);
    fx.wait_for_exit(&mut m);
    assert_eq!(store.row().map(|r| r.0), Some("stopped".into()));
    assert!(fx.bundle.exists());
}

/// A pod (`p0d1`) of the container under test, a second container and its
/// infra container, whose record is in `pods`; the exit policy is `policy`.
fn make_pod(
    fx: &mut Fixture,
    pods: &std::path::Path,
    policy: velarx_proto::pod::PodExitPolicy,
    infra: &str,
) {
    use velarx_runtime::pods::{exit::PodPlan, store::*};
    let spec = velarx_proto::pod::PodSpec {
        exit_policy: policy,
        ..Default::default()
    };
    PodStore {
        dir: pods.to_path_buf(),
    }
    .add(&Pod {
        id: "p0d1".into(),
        name: "pod".into(),
        state: PodState::Running,
        infra_container_id: Some(infra.into()),
        container_ids: vec![fx.config.id.clone()],
        spec,
        created_at: "2026-01-01T00:00:00Z".into(),
        started_at: None,
        exit_code: None,
        removing: false,
    })
    .unwrap();
    let mon_root = fx.dir.path().join("pods-mon");
    std::fs::create_dir_all(&mon_root).unwrap();
    fx.config.settle.as_mut().unwrap().pod = Some(PodPlan {
        id: "p0d1".into(),
        pods_dir: pods.to_path_buf(),
        slice: None,
        mon_root,
    });
}

/// With the exit policy `stop` the last container of a pod that exits has
/// the monitor of the pod's infra container stop it, with no engine alive.
#[test]
fn the_exit_of_the_last_container_of_a_pod_stops_its_infra_container() {
    let mut infra = Fixture::new("sleep 600");
    infra.config.id = "fffff0000001".into();
    let mut fx = Fixture::new("exit 0");
    let store = fx.with_store();
    store.add_container("fffff0000001", velarx_db::RecordState::Running);
    let pods = fx.dir.path().join("pods");
    make_pod(
        &mut fx,
        &pods,
        velarx_proto::pod::PodExitPolicy::Stop,
        "fffff0000001",
    );
    let mon_root = fx.dir.path().join("pods-mon");
    // (the monitor directory of the infra container is where the pod says)
    infra.run_dir = mon_root.join("fffff0000001");
    std::fs::create_dir_all(&infra.run_dir).unwrap();
    let mut infra_monitor = infra.start_monitor();
    assert!(ctl(&infra.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    fx.wait_for_exit(&mut m);
    // (the infra container's monitor ends with the container stopped)
    wait_event(&infra_monitor.events, |e| matches!(e, Event::Exited(_)));
    infra_monitor.child.wait().unwrap();
    let info: velarx_wire::monitor::proto::ExitInfo = serde_json::from_slice(
        &std::fs::read(infra.run_dir.join(velarx_wire::monitor::proto::EXIT_FILE)).unwrap(),
    )
    .unwrap();
    assert!(info.stop_requested);
}

/// A pod whose members have all exited is stopped by the monitor of the
/// last one; with the infra container still running it stays running (the
/// policy is the default).
#[test]
fn the_last_member_of_a_pod_that_exits_settles_it() {
    for (infra_state, want) in [
        (velarx_db::RecordState::Running, "running"),
        (velarx_db::RecordState::Stopped, "stopped"),
    ] {
        let mut fx = Fixture::new("exit 0");
        let store = fx.with_store();
        store.add_container("fffff0000001", infra_state);
        let pods = fx.dir.path().join("pods");
        make_pod(
            &mut fx,
            &pods,
            velarx_proto::pod::PodExitPolicy::Continue,
            "fffff0000001",
        );
        let mut m = fx.start_monitor();
        assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
        fx.wait_for_exit(&mut m);
        assert_eq!(StoreFx::pod_state(&pods, "p0d1"), want);
    }
}

/// A member whose monitor wrote the exit of its last run is not running,
/// even when that monitor, which ends, holds the connection of the question
/// unanswered (it no longer takes calls, and resets them when it exits): the
/// exit of the last other member settles the pod.
#[test]
fn a_member_whose_monitor_ends_is_not_running() {
    let mut fx = Fixture::new("exit 0");
    let store = fx.with_store();
    store.add_container("fffff0000001", velarx_db::RecordState::Stopped);
    let pods = fx.dir.path().join("pods");
    make_pod(
        &mut fx,
        &pods,
        velarx_proto::pod::PodExitPolicy::Continue,
        "fffff0000001",
    );
    // (the monitor of the infra container that ends: its exit written, its
    // socket listening, nothing taken)
    let ending = fx.dir.path().join("pods-mon/fffff0000001");
    std::fs::create_dir_all(&ending).unwrap();
    std::fs::write(ending.join(velarx_wire::monitor::proto::EXIT_FILE), b"{}").unwrap();
    let _listener =
        std::os::unix::net::UnixListener::bind(ending.join(velarx_wire::monitor::proto::SOCKET))
            .unwrap();
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    fx.wait_for_exit(&mut m);
    assert_eq!(StoreFx::pod_state(&pods, "p0d1"), "stopped");
}

/// `Remove` of a running container needs `force`; with it the container is
/// stopped and removed, and the reply says it is settled.
#[test]
fn a_remove_of_a_running_container_needs_force() {
    let mut fx = Fixture::new("sleep 600");
    let store = fx.with_store();
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let refused = client::remove(&fx.run_dir, false, None, true).unwrap_err();
    assert!(client::is_error(
        &refused,
        velarx_wire::monitor::iface::error::INVALID_STATE
    ));
    let status = client::remove(&fx.run_dir, true, Some(0), true).unwrap();
    let settled = status.settled.expect("settled");
    assert!(settled.recorded && settled.removed, "{settled:?}");
    assert_eq!(store.row(), None);
    assert!(!fx.bundle.exists());
    assert_eq!(store.events(), ["container/died", "container/remove"]);
    m.child.wait().unwrap();
}

/// A container that never ran is removed by its monitor: its row and files,
/// with no exit to record.
#[test]
fn a_remove_of_a_created_container_removes_it_with_no_exit() {
    let mut fx = Fixture::new("exit 0");
    let store = fx.with_store();
    let mut m = fx.start_monitor();
    let status = client::remove(&fx.run_dir, false, None, true).unwrap();
    assert!(status.settled.is_some_and(|s| s.removed));
    assert_eq!(store.row(), None);
    assert!(!fx.bundle.exists());
    assert_eq!(store.events(), ["container/remove"]);
    m.child.wait().unwrap();
}

/// `--rmi`: the image of an `--rm` container goes with it, its layers are
/// left to the next collection; a name of an image with other names only is
/// untagged.
#[test]
fn the_image_of_an_rm_container_goes_with_it() {
    for (names, goes) in [
        (vec![("localhost/rmi", "1")], true),
        (vec![("localhost/rmi", "1"), ("localhost/rmi", "2")], false),
    ] {
        let mut fx = Fixture::new("exit 0");
        let store = fx.with_store();
        store.add_image("img0", &names);
        {
            let plan = fx.config.settle.as_mut().unwrap();
            plan.image = Some(velarx_runtime::settle::ImageRef {
                id: "img0".into(),
                event_id: "cfg0".into(),
                name: Some(("localhost/rmi".into(), "1".into())),
            });
        }
        fx.config.auto_remove = true;
        let mut m = fx.start_monitor();
        assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
        fx.wait_for_exit(&mut m);
        assert_eq!(store.row(), None);
        let (left, pending) = store.image_names("img0");
        assert_eq!(store.has_image("img0"), !goes);
        assert_eq!(pending, goes);
        if goes {
            assert!(left.is_empty());
            assert!(store.events().contains(&"image/remove".to_string()));
        } else {
            assert_eq!(left, ["localhost/rmi:2"]);
            assert!(store.events().contains(&"image/untag".to_string()));
        }
    }
}

/// An image another container uses stays, whatever `--rmi` says.
#[test]
fn the_image_another_container_uses_stays() {
    let mut fx = Fixture::new("exit 0");
    let store = fx.with_store();
    store.add_image("img0", &[("localhost/rmi", "1")]);
    store.add_container_of("other0", "img0");
    fx.config.settle.as_mut().unwrap().image = Some(velarx_runtime::settle::ImageRef {
        id: "img0".into(),
        event_id: "cfg0".into(),
        name: Some(("localhost/rmi".into(), "1".into())),
    });
    fx.config.auto_remove = true;
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    fx.wait_for_exit(&mut m);
    assert_eq!(store.row(), None);
    assert!(store.has_image("img0"));
}
