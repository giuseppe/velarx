// SPDX-License-Identifier: Apache-2.0
//! The monitor process, with a fake OCI runtime.

use crate::monitor_common::*;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use velarx_runtime::monitor::relay::{self, AttachEnd, AttachOptions};
use velarx_wire::monitor::client;
use velarx_wire::monitor::iface::ExecReason;
use velarx_wire::monitor::logfmt::{read_logs, ReadOptions};
use velarx_wire::monitor::proto::{self, Event, RunState};

#[test]
fn the_exit_status_the_log_and_the_exit_file_are_recorded() {
    let fx = Fixture::new("echo out; echo err >&2; printf partial; exit 3");
    let mut m = fx.start_monitor();
    assert!(m.first.ok, "{:?}", m.first.error);
    let status = m.first.status.clone().unwrap();
    assert_eq!(status.state, RunState::Created);
    assert!(status.pid.unwrap() > 1);

    let started = ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 });
    assert!(started.ok, "{:?}", started.error);
    assert_eq!(started.status.unwrap().state, RunState::Running);

    let info = fx.wait_for_exit(&mut m);
    assert_eq!(info.code, 3);
    assert!(!info.oom && !info.stop_requested);
    let on_disk: proto::ExitInfo =
        serde_json::from_slice(&std::fs::read(fx.run_dir.join(proto::EXIT_FILE)).unwrap()).unwrap();
    assert_eq!(on_disk, info);
    // The order between the streams is the order they were read in.
    let lines = fx.log_lines();
    let stream = |prefix: &str| -> Vec<String> {
        lines
            .iter()
            .filter(|l| l.starts_with(prefix))
            .cloned()
            .collect()
    };
    assert_eq!(stream("out"), ["out F out", "out P partial", "out F "]);
    assert_eq!(stream("err"), ["err F err"]);
    // The runtime was told to forget the container, the socket is gone.
    assert!(std::fs::read_to_string(fx.root.join("deleted"))
        .unwrap()
        .contains("abcdef123456"));
    assert!(!fx.run_dir.join(proto::SOCKET).exists());
}

#[test]
fn a_container_killed_by_a_signal_exits_with_128_plus_the_signal() {
    let fx = Fixture::new("kill -KILL $$");
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    assert_eq!(fx.wait_for_exit(&mut m).code, 137);
}

/// How many times the process was scheduled out to wait: a loop with a
/// timer shows here, an event does not.
fn context_switches(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .filter(|l| l.contains("voluntary_ctxt_switches"))
        .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        .sum()
}

/// The descriptors of `pid` that are pidfds.
fn pidfds_of(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|l| l.to_string_lossy() == "anon_inode:[pidfd]")
        .count()
}

#[test]
fn the_kill_of_the_init_is_seen_at_once_by_its_pidfd() {
    let (fx, mut m) = running_fixture();
    let pid = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    let t = std::time::Instant::now();
    assert!(kill(pid, libc::SIGKILL));
    let info = fx.wait_for_exit(&mut m);
    let took = t.elapsed();
    assert_eq!(info.code, 137);
    eprintln!("exit seen {} ms after the kill", took.as_millis());
    assert!(took < std::time::Duration::from_millis(250), "{took:?}");
}

#[test]
fn an_idle_monitor_with_a_running_container_does_not_wake_up() {
    let (fx, m) = running_fixture();
    // (windows: the start settles, then the wake-ups of 2 s of idleness are counted)
    std::thread::sleep(std::time::Duration::from_millis(300));
    let before = context_switches(m.child.id());
    std::thread::sleep(std::time::Duration::from_secs(2));
    let woke = context_switches(m.child.id()) - before;
    assert!(woke <= 2, "{woke} wake-ups in 2 s of idleness");
    stop(&fx, m);
}

#[test]
fn the_start_of_a_command_is_an_event_not_a_poll() {
    let (fx, m) = running_fixture();
    // the runtime writes the pid file a second after it started
    std::fs::write(fx.root.join("exec.delay"), "1").unwrap();
    let mut req = exec_request(&["sleep", "30"]);
    req.notify_start = true;
    let before = context_switches(m.child.id());
    let t = std::time::Instant::now();
    let mut conn = open_exec(&fx, &req).unwrap();
    conn.conn
        .set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(20));
    let r = conn
        .conn
        .reply::<velarx_wire::monitor::iface::ExecReply>()
        .unwrap();
    assert_eq!(
        r.parameters.phase,
        velarx_wire::monitor::iface::SessionPhase::Started
    );
    let took = t.elapsed();
    let woke = context_switches(m.child.id()) - before;
    eprintln!("start told after {} ms, {woke} wake-ups", took.as_millis());
    assert!(took >= std::time::Duration::from_millis(1000));
    assert!(took < std::time::Duration::from_millis(1250), "{took:?}");
    // (the poll of 5 ms was 200 of them in that second)
    assert!(woke < 40, "{woke} wake-ups for a second of waiting");
    drop(conn);
    stop(&fx, m);
}

#[test]
fn a_command_that_exits_before_the_runtime_does_keeps_its_status() {
    let (fx, m) = running_fixture();
    // the command is an orphan of the monitor, already exited, when the
    // runtime writes its pid file
    std::fs::write(fx.root.join("exec.early"), "").unwrap();
    for code in [0, 3] {
        let conn = open_exec(
            &fx,
            &exec_request(&["sh", "-c", &format!("echo out; exit {code}")]),
        )
        .unwrap();
        let (out, _, got, reason) = finish_exec(conn);
        assert_eq!(out, "out\n");
        assert_eq!(reason, ExecReason::Exited);
        assert_eq!(got, code);
    }
    stop(&fx, m);
}

#[test]
fn a_status_that_cannot_be_had_is_an_error_not_a_code() {
    let (fx, m) = running_fixture();
    std::fs::write(fx.root.join("exec.badpid"), "").unwrap();
    let mut conn = open_exec(&fx, &exec_request(&["true"])).unwrap();
    conn.conn
        .set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(20));
    let why = loop {
        match conn.conn.reply::<velarx_wire::monitor::iface::ExecReply>() {
            Ok(r) => assert!(r.parameters.exit.is_none(), "an exit code was made up"),
            Err(e) => break e.to_string(),
        }
    };
    assert!(
        why.contains("exit status of the command is unknown"),
        "{why}"
    );
    drop(conn);
    stop(&fx, m);
}

#[test]
fn a_kill_that_comes_before_the_command_started_reaches_it_when_it_did() {
    let (fx, m) = running_fixture();
    std::fs::write(fx.root.join("exec.delay"), "0.6").unwrap();
    let mut req = exec_request(&["sh", "-c", "sleep 100 & echo $$; sleep 100"]);
    req.timeout_ms = Some(100);
    let conn = open_exec(&fx, &req).unwrap();
    let t = std::time::Instant::now();
    let (_, _, code, reason) = finish_exec(conn);
    assert_eq!(reason, ExecReason::TimedOut);
    assert_eq!(code, 137);
    // killed when its pid file appeared, not after the 5 s a runtime gets
    assert!(
        t.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        t.elapsed()
    );
    stop(&fx, m);
}

#[test]
fn the_pidfds_do_not_reach_the_container_or_its_commands() {
    let (fx, m) = running_fixture();
    let conn = open_exec(&fx, &exec_request(&["sh", "-c", "ls -l /proc/self/fd"])).unwrap();
    let (out, _, code, _) = finish_exec(conn);
    assert_eq!(code, 0, "{out}");
    assert!(
        !out.contains("anon_inode"),
        "a monitor descriptor reached the command:\n{out}"
    );
    stop(&fx, m);
    let fx = Fixture::new("ls -l /proc/self/fd");
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    fx.wait_for_exit(&mut m);
    let log = fx.log_lines().join("\n");
    assert!(log.contains("fd"), "{log}");
    assert!(!log.contains("anon_inode"), "{log}");
}

#[test]
fn a_restart_holds_one_pidfd_for_its_run() {
    let mut fx = Fixture::new("sleep 1; exit 3");
    fx.config.restart = restart_policy("on-failure", 2, 0);
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    for _ in 0..5 {
        let (what, ..) = next_run_event(&m.events);
        if what == "started" {
            assert_eq!(pidfds_of(m.child.id()), 1);
        }
    }
    fx.wait_for_exit(&mut m);
}

#[test]
fn a_failing_create_reports_the_message_of_the_runtime() {
    let fx = Fixture::new("true");
    std::fs::write(fx.bundle.join("fail"), "no such rootfs").unwrap();
    let mut m = fx.start_monitor();
    assert!(!m.first.ok);
    assert!(m.first.error.as_deref().unwrap().contains("no such rootfs"));
    assert!(!m.child.wait().unwrap().success());
}

#[test]
fn an_attached_client_gets_the_output_and_the_exit_status() {
    let fx = Fixture::new("echo hello; echo oops >&2; exit 5");
    let mut m = fx.start_monitor();
    // The container waits for the client (the attach starts it: the bound
    // is far longer than the 20 s the events are waited for).
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 3_600_000
            }
        )
        .ok
    );
    assert_eq!(status_state(&fx.run_dir), RunState::Created);

    let (out_r, out_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (err_r, err_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (in_r, _in_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let dir = fx.run_dir.clone();
    let t = std::thread::spawn(move || {
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
    let ev = wait_event(&m.events, |e| matches!(e, Event::Exited(_)));
    assert!(matches!(ev, Event::Exited(ref i) if i.code == 5));
    assert_eq!(t.join().unwrap(), AttachEnd::Exited(5));
    let mut out = String::new();
    std::fs::File::from(out_r).read_to_string(&mut out).unwrap();
    let mut err = String::new();
    std::fs::File::from(err_r).read_to_string(&mut err).unwrap();
    assert_eq!((out.as_str(), err.as_str()), ("hello\n", "oops\n"));
    assert_eq!(m.child.wait().unwrap().code(), Some(5));
}

#[test]
fn the_container_starts_by_itself_when_no_client_attaches() {
    let fx = Fixture::new("echo late");
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 200
            }
        )
        .ok
    );
    assert_eq!(fx.wait_for_exit(&mut m).code, 0);
    assert_eq!(fx.log_lines(), vec!["out F late".to_string()]);
}

#[test]
fn stdin_reaches_the_container_and_eof_ends_it() {
    let mut fx = Fixture::new("cat; echo done");
    fx.config.stdin_open = true;
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 20_000
            }
        )
        .ok
    );

    let mut session = attach_session(
        &fx.run_dir,
        &proto::Attach {
            stdin: true,
            start: true,
            ..Default::default()
        },
    );
    session.write(b"typed ");
    session.write(b"text\n");
    session.close_stdin();
    let ended = std::thread::scope(|scope| {
        let reader = scope.spawn(|| session.finish());
        wait_event(&m.events, |e| matches!(e, Event::Exited(_)));
        reader.join().unwrap()
    });
    assert_eq!(ended.code, 0);
    let got = ended.out.into_bytes();
    assert_eq!(String::from_utf8(got).unwrap(), "typed text\ndone\n");
    assert!(m.child.wait().unwrap().success());
}

#[test]
fn signals_from_a_client_reach_the_container() {
    let fx = Fixture::new("trap 'exit 42' TERM; echo ready; while true; do sleep 0.05; done");
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 20_000
            }
        )
        .ok
    );
    let mut session = attach_session(
        &fx.run_dir,
        &proto::Attach {
            start: true,
            ..Default::default()
        },
    );
    session.read_until("ready");
    // (a container gets Kill: an attach session has no signal of its own)
    client::kill(&fx.run_dir, libc::SIGTERM).unwrap();
    assert_eq!(fx.wait_for_exit(&mut m).code, 42);
    drop(session);
}

#[test]
fn a_new_daemon_finds_the_monitor_through_its_socket() {
    let fx = Fixture::new("sleep 0.3; exit 11");
    let m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let Started {
        mut child, events, ..
    } = m;
    drop(events);
    // (a moment for the monitor to see it go: nothing says it did, and the
    // test passes in either order)
    std::thread::sleep(std::time::Duration::from_millis(50));
    let (conn, status) = client::subscribe(&fx.run_dir).unwrap();
    assert_eq!(status.state, RunState::Running);
    let conn = Events::new(conn);
    let ev = wait_event(&conn, |e| matches!(e, Event::Exited(_)));
    let Event::Exited(info) = ev else {
        unreachable!()
    };
    assert_eq!(info.code, 11);
    assert_eq!(child.wait().unwrap().code(), Some(11));
}

/// The monitor is known alive by the lock it holds, with a pidfd of its
/// own process; a second monitor of the directory is refused while it
/// lives, and nothing is known alive once it ended (a killed one too).
#[test]
fn a_monitor_is_known_by_its_lock_and_only_while_it_lives() {
    use velarx_runtime::monitor::live_monitor;
    let fx = Fixture::new("sleep 30");
    let mut m = fx.start_monitor();
    let live = live_monitor(&fx.run_dir).expect("the monitor holds its lock");
    assert_eq!(live.pid, m.child.id());
    // the pidfd is of that process: it ends when the monitor is killed
    assert!(!velarx_sys::pidfd::has_exited(&live.pidfd));
    let (_daemon_end, monitor_end) = UnixStream::pair().unwrap();
    let mut cmd = Command::new(monitor_binary());
    cmd.arg("--varlink-fd")
        .arg("3")
        .arg(&fx.run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    velarx_sys::exec::place_fds(&mut cmd, vec![(monitor_end.as_raw_fd(), 3)]);
    let second = cmd.status().unwrap();
    assert!(!second.success());
    let said = std::fs::read_to_string(fx.run_dir.join(proto::LOG_FILE)).unwrap();
    assert!(said.contains("another monitor runs"), "{said}");
    // (the refused one did not take the lock away from the first)
    assert_eq!(live_monitor(&fx.run_dir).unwrap().pid, m.child.id());
    m.child.kill().unwrap();
    m.child.wait().unwrap();
    assert!(velarx_sys::pidfd::has_exited(&live.pidfd));
    assert!(live_monitor(&fx.run_dir).is_none());
    // the next monitor of the directory takes the lock the killed one left
    let mut next = fx.start_monitor();
    assert_eq!(live_monitor(&fx.run_dir).unwrap().pid, next.child.id());
    next.child.kill().unwrap();
    next.child.wait().unwrap();
}

/// A start that waits for its client is driven by the client: an attach
/// the monitor has to refuse starts the container at once too (no other
/// attach will come for it), not at the bound.
#[test]
fn an_attach_that_is_refused_starts_a_waiting_container_at_once() {
    let fx = Fixture::new("echo started");
    let mut m = fx.start_monitor();
    // (a bound far longer than the test takes)
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 3_600_000
            }
        )
        .ok
    );
    assert_eq!(status_state(&fx.run_dir), RunState::Created);
    // No descriptor left to the monitor but the one of the connection: the
    // pipes of the attach cannot be made.
    let pid = m.child.id() as i32;
    let open: std::collections::BTreeSet<i32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    let limit = (0..)
        .find(|l: &i32| (0..*l).filter(|fd| !open.contains(fd)).count() == 1)
        .unwrap();
    rustix::process::prlimit(
        rustix::process::Pid::from_raw(pid),
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(limit as u64),
            // (the hard limit as it is: the monitor's is the test's)
            maximum: rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum,
        },
    )
    .unwrap();
    let (_in_r, in_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (_out_r, out_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let refused = relay::attach(
        &fx.run_dir,
        &AttachOptions {
            start: true,
            ..Default::default()
        },
        in_w.as_fd(),
        out_w.as_fd(),
        out_w.as_fd(),
    );
    assert!(refused.is_err(), "{refused:?}");
    // The start comes at once (the events are waited for 20 s at most, the
    // bound is an hour); with no descriptor to run the runtime it fails,
    // and the container ends.
    fx.wait_for_exit(&mut m);
    let said = std::fs::read_to_string(fx.run_dir.join(proto::LOG_FILE)).unwrap();
    assert!(said.contains("start failed"), "{said}");
}

#[test]
fn a_monitor_without_a_daemon_ends_with_the_container() {
    let fx = Fixture::new("exit 2");
    let m = fx.start_monitor();
    let Started {
        mut child, events, ..
    } = m;
    drop(events);
    // (a moment for the monitor to see it go: nothing says it did, and the
    // test passes in either order)
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    assert_eq!(child.wait().unwrap().code(), Some(2));
    let on_disk: proto::ExitInfo =
        serde_json::from_slice(&std::fs::read(fx.run_dir.join(proto::EXIT_FILE)).unwrap()).unwrap();
    assert_eq!(on_disk.code, 2);
}

#[test]
fn the_log_is_rotated_by_size_and_reopened_on_request() {
    let mut fx =
        Fixture::new("i=0; while [ $i -lt 200 ]; do echo line $i; i=$((i+1)); done; sleep 0.3");
    fx.config.log.max_size = 1000;
    fx.config.log.max_files = 3;
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);

    // Somebody moves the log: the monitor writes to the new file after the
    // reopen request.  (Once the command has written to it.)
    wait_log_line(&fx.log, "line ");
    let moved = fx.log.with_extension("moved");
    let _ = std::fs::rename(&fx.log, &moved);
    client::reopen_log(&fx.run_dir).unwrap();
    fx.wait_for_exit(&mut m);
    let rotated = velarx_wire::monitor::logfmt::rotated_path(&fx.log, 1);
    assert!(fx.log.exists());
    assert!(rotated.exists() || moved.exists());
    assert!(!velarx_wire::monitor::logfmt::rotated_path(&fx.log, 3).exists());
    for f in [&fx.log, &rotated] {
        if let Ok(meta) = std::fs::metadata(f) {
            assert!(meta.len() <= 1000, "{f:?} {}", meta.len());
        }
    }
    let mut n = 0;
    read_logs(&fx.log, &ReadOptions::default(), None, &mut |_| {
        n += 1;
        Ok(())
    })
    .unwrap();
    assert!(n > 0);
}

#[test]
fn a_client_that_never_reads_does_not_stop_the_container_or_use_unbounded_memory() {
    let mut fx = Fixture::new("i=0; while [ $i -lt 20000 ]; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; i=$((i+1)); done; exit 4");
    fx.config.client_stall_ms = 500;
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 20_000
            }
        )
        .ok
    );
    let conn = attach_session(
        &fx.run_dir,
        &proto::Attach {
            start: true,
            ..Default::default()
        },
    );
    let started = std::time::Instant::now();
    let info = fx.wait_for_exit(&mut m);
    assert_eq!(info.code, 4);
    // The client was dropped after the stall limit and the container ran to
    // its end: the log has all of its output.
    let mut n = 0;
    read_logs(&fx.log, &ReadOptions::default(), None, &mut |r| {
        n += usize::from(!r.partial);
        Ok(())
    })
    .unwrap();
    assert_eq!(n, 20000, "in {:?}", started.elapsed());
    // Its streams ended early, its session went on: the last reply has the
    // status and says that the output was dropped.
    let mut conn = conn;
    let last = loop {
        match client::next_reply::<velarx_wire::monitor::iface::AttachReply>(&mut conn.conn) {
            Ok(Some(r)) if r.parameters.exit.is_some() => break r.parameters,
            Ok(Some(_)) => {}
            other => panic!("no last reply: {:?}", other.err()),
        }
    };
    assert_eq!(last.exit, Some(4));
    assert!(last.output_dropped);
}

#[test]
fn a_client_that_is_only_slow_gets_all_the_output_of_a_container_that_exited() {
    // (more than the socket of the client holds, less than that and what
    // the monitor holds for a client before it stops reading the container
    // and the pipe of the container: the container exits with its output
    // waiting for the client)
    const SIZE: usize = 600_000;
    let fx = Fixture::new(&format!("head -c {SIZE} /dev/zero | tr '\\0' x; exit 3"));
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 20_000
            }
        )
        .ok
    );
    let session = attach_session(
        &fx.run_dir,
        &proto::Attach {
            stdout: true,
            stderr: true,
            start: true,
            ..Default::default()
        },
    );
    // The client reads later than the monitor's drain of the output after
    // the exit (and its old wait for the clients, 2 s), within the time a
    // client may take (the stall limit).
    std::thread::sleep(std::time::Duration::from_secs(4));
    let ended = session.finish();
    assert_eq!((ended.out.len(), ended.code), (SIZE, 3));
    assert_eq!(m.child.wait().unwrap().code(), Some(3));
    let mut n = 0;
    read_logs(&fx.log, &ReadOptions::default(), None, &mut |r| {
        n += r.content.len();
        Ok(())
    })
    .unwrap();
    assert_eq!(n, SIZE);
}

#[test]
fn stdin_once_closes_the_input_when_the_client_goes() {
    let mut fx = Fixture::new("cat; echo eof-seen");
    fx.config.stdin_open = true;
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 20_000
            }
        )
        .ok
    );
    let mut session = attach_session(
        &fx.run_dir,
        &proto::Attach {
            stdin: true,
            start: true,
            stdin_once: true,
            ..Default::default()
        },
    );
    session.write(b"some input\n");
    session.read_until("some input");
    drop(session);
    assert_eq!(fx.wait_for_exit(&mut m).code, 0);
    assert!(fx.log_lines().iter().any(|l| l == "out F eof-seen"));
}

#[test]
fn a_client_that_stays_keeps_the_input_open_without_stdin_once() {
    let mut fx = Fixture::new("cat; echo eof-seen");
    fx.config.stdin_open = true;
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 20_000
            }
        )
        .ok
    );
    let mut session = attach_session(
        &fx.run_dir,
        &proto::Attach {
            stdin: true,
            start: true,
            ..Default::default()
        },
    );
    session.write(b"x\n");
    session.read_until("x");
    drop(session);
    // (a window: the client that went must not end the container)
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(status_state(&fx.run_dir), RunState::Running);
    let mut again = attach_session(
        &fx.run_dir,
        &proto::Attach {
            stdin: true,
            ..Default::default()
        },
    );
    again.close_stdin();
    assert_eq!(fx.wait_for_exit(&mut m).code, 0);
}

fn exec_request(cmd: &[&str]) -> proto::ExecRequest {
    proto::ExecRequest {
        command: cmd.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

/// Ask for `req`: the session, or the error of the monitor.
fn open_exec(fx: &Fixture, req: &proto::ExecRequest) -> std::io::Result<Session> {
    exec_session(&fx.run_dir, req)
}

/// The output and the end of a session: (stdout, stderr, status, reason).
fn finish_exec(session: Session) -> (String, String, i32, ExecReason) {
    let e = session.finish();
    (e.out, e.err, e.code, e.reason)
}

fn running_fixture() -> (Fixture, Started) {
    let fx = Fixture::new("sleep 30");
    let m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    (fx, m)
}

fn stop(fx: &Fixture, mut m: Started) {
    let pid = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    kill(pid, libc::SIGKILL);
    fx.wait_for_exit(&mut m);
}

/// `[containers] keyring = false` is `--no-new-keyring` of the runtime's
/// `create`, and only then.
#[test]
fn the_runtime_creates_without_a_keyring_when_asked() {
    for no_new_keyring in [false, true] {
        let mut fx = Fixture::new("sleep 30");
        fx.config.no_new_keyring = no_new_keyring;
        let m = fx.start_monitor();
        assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
        let args = std::fs::read_to_string(fx.root.join("abcdef123456.createargs")).unwrap();
        assert_eq!(
            args.split_whitespace().any(|a| a == "--no-new-keyring"),
            no_new_keyring,
            "{args}"
        );
        stop(&fx, m);
    }
}

#[test]
fn a_command_runs_with_its_streams_and_its_status() {
    let (fx, m) = running_fixture();
    let conn = open_exec(
        &fx,
        &exec_request(&["sh", "-c", "echo out; echo err >&2; exit 5"]),
    )
    .unwrap();
    assert_eq!(
        finish_exec(conn),
        ("out\n".into(), "err\n".into(), 5, ExecReason::Exited)
    );

    let mut req = exec_request(&["sh", "-c", "echo $FOO-$(pwd)"]);
    req.env = vec!["FOO=bar".into()];
    req.cwd = Some("/".into());
    let conn = open_exec(&fx, &req).unwrap();
    assert_eq!(finish_exec(conn).0, "bar-/\n");

    let conn = open_exec(&fx, &exec_request(&["/does/not/exist"])).unwrap();
    let (_, err, code, _) = finish_exec(conn);
    assert_eq!(code, 127, "{err}");
    stop(&fx, m);
}

#[test]
fn a_command_that_says_what_the_runtime_says_keeps_its_status() {
    let (fx, m) = running_fixture();
    let conn = open_exec(
        &fx,
        &exec_request(&[
            "sh",
            "-c",
            "echo 'the path `/x` is not a regular file' >&2; exit 3",
        ]),
    )
    .unwrap();
    let (_, err, code, _) = finish_exec(conn);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("is not a regular file"), "{err}");
    stop(&fx, m);
}

#[test]
fn the_start_of_a_command_is_told_to_a_client_that_asks() {
    let (fx, m) = running_fixture();
    let mut req = exec_request(&["sleep", "30"]);
    req.notify_start = true;
    let mut conn = open_exec(&fx, &req).unwrap();
    conn.conn
        .set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(20));
    let r = conn
        .conn
        .reply::<velarx_wire::monitor::iface::ExecReply>()
        .unwrap();
    assert!(
        r.parameters.phase == velarx_wire::monitor::iface::SessionPhase::Started && r.continues,
        "no start was told"
    );
    drop(conn);
    stop(&fx, m);
}

#[test]
fn a_command_reads_stdin_until_the_end_of_input() {
    let (fx, m) = running_fixture();
    let mut req = exec_request(&["cat"]);
    req.stdin = true;
    let mut conn = open_exec(&fx, &req).unwrap();
    conn.write(b"hello ");
    conn.write(b"world");
    conn.close_stdin();
    assert_eq!(
        finish_exec(conn),
        ("hello world".into(), "".into(), 0, ExecReason::Exited)
    );
    stop(&fx, m);
}

/// Waits (30 s at most) until the log at `path` has a line with `needle`.
fn wait_log_line(path: &std::path::Path, needle: &str) {
    assert!(
        velarx_base::testing::wait_file(path, std::time::Duration::from_secs(30), |s| s
            .contains(needle))
        .is_some(),
        "no line with {needle:?} in {} within 30 s",
        path.display()
    );
}

/// The live members (not zombies) of the process group `pgid`.
fn group_members(pgid: i32) -> Vec<i32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| {
            let pid: i32 = e.ok()?.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // (the name may hold spaces and parentheses: the fields follow the last one)
            let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
            let state = fields.next()?;
            let _ppid = fields.next()?;
            let group: i32 = fields.next()?.parse().ok()?;
            (group == pgid && state != "Z").then_some(pid)
        })
        .collect()
}

/// Whether the process group `pgid` has a live member.
fn group_alive(pgid: i32) -> bool {
    !group_members(pgid).is_empty()
}

/// Waits (30 s at most) until the process group `pgid` has no live member:
/// each member is waited for through its pidfd.
fn wait_group_gone(pgid: i32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let members = group_members(pgid);
        if members.is_empty() {
            return;
        }
        for pid in members {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                velarx_base::testing::wait_exit(pid, left),
                "the group {pgid} is still there"
            );
        }
    }
}

#[test]
fn the_timeout_kills_the_process_group() {
    let (fx, m) = running_fixture();
    let mut req = exec_request(&["sh", "-c", "sleep 100 & echo $$; sleep 100"]);
    req.timeout_ms = Some(300);
    let conn = open_exec(&fx, &req).unwrap();
    let started = std::time::Instant::now();
    let (out, _, code, reason) = finish_exec(conn);
    assert_eq!(reason, ExecReason::TimedOut);
    assert_eq!(code, 137);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let pgid: i32 = out.trim().parse().unwrap();
    wait_group_gone(pgid);
    assert!(!group_alive(pgid), "the group {pgid} is still there");
    stop(&fx, m);
}

/// A client that goes away leaves its command running, as podman's: the
/// command still writes (its output is dropped) and the monitor serves the
/// next clients.
#[test]
fn a_client_that_goes_away_leaves_its_command_running() {
    let (fx, m) = running_fixture();
    let mut conn = open_exec(
        &fx,
        &exec_request(&[
            "sh",
            "-c",
            "sleep 100 & echo $$; while :; do echo more; sleep 0.05; done",
        ]),
    )
    .unwrap();
    let pgid: i32 = conn
        .read_until("\n")
        .lines()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(group_alive(pgid));
    drop(conn);
    // (a window: a command that is cancelled is killed within a moment)
    std::thread::sleep(std::time::Duration::from_millis(1000));
    assert!(group_alive(pgid), "the group {pgid} was killed");
    let next = open_exec(&fx, &exec_request(&["echo", "next"])).unwrap();
    assert_eq!(
        finish_exec(next),
        ("next\n".into(), "".into(), 0, ExecReason::Exited)
    );
    kill(-pgid, libc::SIGKILL);
    assert_eq!(status_state(&fx.run_dir), RunState::Running);
    stop(&fx, m);
}

/// The owner of a session that closes the streams of the output (a
/// frontend had them, and its client left) but stays: the command goes on,
/// writing, and the owner gets its status.
#[test]
fn an_output_closed_by_its_reader_leaves_the_command_and_its_status() {
    let (fx, m) = running_fixture();
    let mut conn = open_exec(
        &fx,
        &exec_request(&[
            "sh",
            "-c",
            "echo ready; i=0; while [ $i -lt 40 ]; do echo more; echo err >&2; \
             i=$((i+1)); sleep 0.02; done; exit 7",
        ]),
    )
    .unwrap();
    conn.read_until("ready");
    conn.stdout = None;
    conn.stderr = None;
    let (_, _, code, reason) = finish_exec(conn);
    assert_eq!((code, reason), (7, ExecReason::Exited));
    stop(&fx, m);
}

/// A client that sends more than the request (the end of its input, as a
/// client with no input does at once) while a quick command ends still gets
/// the status: the monitor closing the connection with that packet unread
/// would reset it, and the reset comes before what was sent.
#[test]
fn a_quick_command_ends_with_its_status_whatever_the_client_sends() {
    let (fx, m) = running_fixture();
    for i in 0..300 {
        let mut conn = open_exec(&fx, &exec_request(&["echo", "quick"])).unwrap();
        // (about when the command ends)
        std::thread::sleep(std::time::Duration::from_micros(200 * (i % 20)));
        let _ = conn
            .conn
            .oneway_method(&velarx_wire::monitor::iface::CloseStdin {});
        assert_eq!(
            finish_exec(conn),
            ("quick\n".into(), "".into(), 0, ExecReason::Exited)
        );
    }
    stop(&fx, m);
}

/// A client that is gone before the answer to its request (the monitor
/// cannot write it) leaves its command running too, and the clients that
/// come right after are served.
#[test]
fn a_client_gone_before_the_answer_leaves_its_command_running() {
    let (fx, m) = running_fixture();
    let mut files = Vec::new();
    for i in 0..10 {
        let file = fx.run_dir.join(format!("pgid-{i}"));
        let mut conn = client::connect(&fx.run_dir).unwrap();
        let cmd = format!(
            "echo $$ > {}.tmp && mv {0}.tmp {0}; sleep 100",
            file.display()
        );
        conn.send_method(&exec_request(&["sh", "-c", &cmd]), &[])
            .unwrap();
        drop(conn);
        files.push(file);
        let next = open_exec(&fx, &exec_request(&["echo", "next"])).unwrap();
        assert_eq!(
            finish_exec(next),
            ("next\n".into(), "".into(), 0, ExecReason::Exited)
        );
    }
    for file in &files {
        let pgid: i32 =
            velarx_base::testing::wait_file(file, std::time::Duration::from_secs(30), |_| true)
                .expect("the command of a client gone before the answer did not start")
                .trim()
                .parse()
                .unwrap();
        assert!(group_alive(pgid), "the group {pgid} was killed");
        kill(-pgid, libc::SIGKILL);
    }
    assert_eq!(status_state(&fx.run_dir), RunState::Running);
    stop(&fx, m);
}

#[test]
fn a_client_that_detaches_leaves_its_command_running() {
    let (fx, m) = running_fixture();
    let mut conn = open_exec(
        &fx,
        &exec_request(&["sh", "-c", "sleep 100 & echo $$; sleep 100"]),
    )
    .unwrap();
    let pgid: i32 = conn.read_until("\n").trim().parse().unwrap();
    conn.detach();
    drop(conn);
    // (a window: a command that is cancelled is killed within a moment)
    std::thread::sleep(std::time::Duration::from_millis(1000));
    assert!(group_alive(pgid), "the group {pgid} was killed");
    kill(-pgid, libc::SIGKILL);
    assert_eq!(status_state(&fx.run_dir), RunState::Running);
    stop(&fx, m);
}

/// `exec -d`: a request with `detach` goes on when its client is gone at
/// once, even while its output (more than the connection takes) is still
/// coming: with no one to read it, it is dropped.
#[test]
fn a_detached_request_outlives_its_client_and_its_output() {
    let (fx, m) = running_fixture();
    let file = fx.run_dir.join("detached-pgid");
    let cmd = format!(
        "head -c 8000000 /dev/zero; head -c 8000000 /dev/zero >&2; \
         echo $$ > {0}.tmp && mv {0}.tmp {0}; sleep 100",
        file.display()
    );
    let mut conn = client::connect(&fx.run_dir).unwrap();
    let req = proto::ExecRequest {
        detach: true,
        ..exec_request(&["sh", "-c", &cmd])
    };
    conn.send_method(&req, &[]).unwrap();
    drop(conn);
    // (moved there whole once the output is written: a command that was
    // cancelled before its end never makes it)
    let pgid: i32 =
        velarx_base::testing::wait_file(&file, std::time::Duration::from_secs(30), |_| true)
            .expect("the detached command was cancelled before its end")
            .trim()
            .parse()
            .unwrap();
    // (a window: a command that is cancelled is killed within a moment)
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(group_alive(pgid), "the group {pgid} was killed");
    kill(-pgid, libc::SIGKILL);
    assert_eq!(status_state(&fx.run_dir), RunState::Running);
    stop(&fx, m);
}

#[test]
fn a_signal_from_the_client_reaches_the_command() {
    let (fx, m) = running_fixture();
    let mut conn = open_exec(
        &fx,
        &exec_request(&[
            "sh",
            "-c",
            "trap 'echo got; exit 9' TERM; echo ready; while :; do sleep 0.05; done",
        ]),
    )
    .unwrap();
    conn.read_until("ready");
    conn.signal(libc::SIGTERM);
    let (out, _, code, _) = finish_exec(conn);
    assert_eq!((out.as_str(), code), ("got\n", 9));
    stop(&fx, m);
}

#[test]
fn exec_in_a_container_that_is_not_running_is_refused() {
    let fx = Fixture::new("sleep 30");
    let mut m = fx.start_monitor();
    let e = open_exec(&fx, &exec_request(&["true"])).err().unwrap();
    assert!(
        client::is_error(&e, velarx_wire::monitor::iface::error::NOT_RUNNING),
        "{e}"
    );
    assert!(e.to_string().contains("not running"));
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let bad = open_exec(&fx, &exec_request(&[])).err().unwrap();
    assert!(
        client::is_error(&bad, velarx_wire::monitor::iface::error::INVALID_ARGUMENT),
        "{bad}"
    );
    let pid = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    kill(pid, libc::SIGKILL);
    fx.wait_for_exit(&mut m);
    assert!(client::connect(&fx.run_dir).is_err());
}

/// A command that cannot start (a user the container does not have) is
/// refused with the error `NotStarted`, which is the engine's condition of
/// that name: its client does not read the words.
#[test]
fn an_exec_that_cannot_start_is_refused_with_a_typed_error() {
    let (fx, m) = running_fixture();
    let req = proto::ExecRequest {
        user: Some("nosuchuser".into()),
        ..exec_request(&["true"])
    };
    let e = open_exec(&fx, &req).err().unwrap();
    assert!(
        client::is_error(&e, velarx_wire::monitor::iface::error::NOT_STARTED),
        "{e}"
    );
    assert_eq!(
        client::monitor_error(&e).and_then(|m| m.condition()),
        Some(velarx_proto::engine::Condition::NotStarted)
    );
    stop(&fx, m);
}

/// The init exited and a child of it still holds its output: the monitor
/// waits for the output (the drain) and says `running` until it ends, but
/// the container does not run any more, and a command is refused as in a
/// container that ended.
#[test]
fn exec_after_the_init_exited_is_refused_while_its_output_drains() {
    let held = tempfile::tempdir().unwrap();
    let pid_file = held.path().join("child");
    let mut fx = Fixture::new(&format!(
        "sleep 60 & echo $! > {}; exit 0",
        pid_file.display()
    ));
    fx.config.drain_ms = 60_000;
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let init = ctl(&fx.run_dir, &Ctl::Status).status.unwrap().pid.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while kill(init, 0) || !pid_file.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the init did not exit"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // (in the drain: the monitor still says running)
    assert_eq!(status_state(&fx.run_dir), RunState::Running);
    let e = open_exec(&fx, &exec_request(&["true"])).err().unwrap();
    assert!(
        client::is_error(&e, velarx_wire::monitor::iface::error::NOT_RUNNING),
        "{e}"
    );
    let child: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    kill(child, libc::SIGKILL);
    assert_eq!(fx.wait_for_exit(&mut m).code, 0);
}

/// `--preserve-fd`: the monitor opens the holes itself, so a client cannot
/// make it open more than the most a command gets, nor repeat a hole or
/// name one outside of them; the command gets a hole closed.
#[test]
fn the_holes_of_preserved_descriptors_are_bounded() {
    let (fx, m) = running_fixture();
    let refused = |req: proto::ExecRequest| {
        let e = open_exec(&fx, &req).err().unwrap();
        assert!(
            client::is_error(&e, velarx_wire::monitor::iface::error::INVALID_ARGUMENT),
            "{e}"
        );
    };
    let many = velarx_base::spawn::MAX_PRESERVED_FDS as u32 + 1;
    refused(proto::ExecRequest {
        preserve_fds: many,
        preserve_holes: (0..many).collect(),
        ..exec_request(&["true"])
    });
    refused(proto::ExecRequest {
        preserve_fds: 2,
        preserve_holes: vec![0, 0],
        ..exec_request(&["true"])
    });
    refused(proto::ExecRequest {
        preserve_fds: 1,
        preserve_holes: vec![1],
        ..exec_request(&["true"])
    });
    // (holes only: 3 and 4 are closed for the command)
    let conn = open_exec(
        &fx,
        &proto::ExecRequest {
            preserve_fds: 2,
            preserve_holes: vec![0, 1],
            ..exec_request(&[
                "sh",
                "-c",
                "test -e /proc/self/fd/3 || test -e /proc/self/fd/4 || echo closed",
            ])
        },
    )
    .unwrap();
    let (out, _, code, _) = finish_exec(conn);
    assert_eq!((out.as_str(), code), ("closed\n", 0));
    stop(&fx, m);
}

#[test]
fn many_commands_at_the_same_time() {
    let (fx, m) = running_fixture();
    let conns: Vec<Session> = (0..8)
        .map(|i| {
            open_exec(
                &fx,
                &exec_request(&["sh", "-c", &format!("sleep 0.2; echo n{i}; exit {i}")]),
            )
            .unwrap()
        })
        .collect();
    for (i, c) in conns.into_iter().enumerate() {
        let (out, _, code, _) = finish_exec(c);
        assert_eq!((out, code), (format!("n{i}\n"), i as i32));
    }
    stop(&fx, m);
}

#[test]
fn the_time_limit_kills_the_container() {
    let mut fx = Fixture::new("sleep 30");
    fx.config.timeout_secs = Some(1);
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let started = std::time::Instant::now();
    let info = fx.wait_for_exit(&mut m);
    // (podman's: no exit of the container, -1)
    assert_eq!((info.code, info.timed_out), (-1, true));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

fn health_fixture(
    marker: &std::path::Path,
    on_failure: velarx_proto::health::OnFailure,
) -> Fixture {
    let mut fx = Fixture::new("sleep 30");
    fx.config.health = Some(velarx_proto::health::Healthcheck {
        test: vec!["CMD-SHELL".into(), format!("test -f {}", marker.display())],
        interval_ns: 150_000_000,
        timeout_ns: 5_000_000_000,
        retries: 2,
        on_failure,
        startup: None,
        ..Default::default()
    });
    fx
}

fn next_health(conn: &Events) -> proto::Health {
    match wait_event(conn, |e| matches!(e, Event::Health(_))) {
        Event::Health(h) => h,
        _ => unreachable!(),
    }
}

#[test]
fn health_checks_run_at_their_interval_and_change_the_status() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ok");
    let fx = health_fixture(&marker, velarx_proto::health::OnFailure::None);
    let m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let h = next_health(&m.events);
    assert_eq!((h.status.word(), h.failing_streak), ("starting", 1));
    let h = next_health(&m.events);
    assert_eq!((h.status.word(), h.failing_streak), ("unhealthy", 2));
    std::fs::write(&marker, "").unwrap();
    let h = next_health(&m.events);
    assert_eq!((h.status.word(), h.failing_streak), ("healthy", 0));
    assert_eq!(h.log.last().unwrap().exit_code, 0);
    let status = ctl(&fx.run_dir, &Ctl::Status).status.unwrap();
    assert_eq!(status.health.unwrap().status.word(), "healthy");
    let reply = ctl(&fx.run_dir, &Ctl::HealthRun);
    assert!(reply.ok, "{:?}", reply.error);
    assert!(reply.health.unwrap().log.len() >= 4);
    stop(&fx, m);
}

#[test]
fn a_check_that_takes_too_long_fails_with_a_message() {
    let mut fx = Fixture::new("sleep 30");
    fx.config.health = Some(velarx_proto::health::Healthcheck {
        test: vec!["sleep".into(), "30".into()],
        interval_ns: 100_000_000,
        timeout_ns: 300_000_000,
        retries: 1,
        on_failure: velarx_proto::health::OnFailure::None,
        startup: None,
        ..Default::default()
    });
    let m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let h = next_health(&m.events);
    assert_eq!(h.status.word(), "unhealthy");
    assert_eq!(h.log[0].output, "healthcheck timed out");
    stop(&fx, m);
}

#[test]
fn an_unhealthy_container_is_killed_or_stopped() {
    use velarx_proto::health::OnFailure;
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("never");
    // `restart`: an_unhealthy_container_is_restarted_by_its_monitor
    for (action, restart, stopped) in [
        (OnFailure::Kill, false, false),
        (OnFailure::Stop, false, true),
    ] {
        let fx = health_fixture(&marker, action);
        let mut m = fx.start_monitor();
        assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
        let info = fx.wait_for_exit(&mut m);
        assert_eq!(
            (info.health_restart, info.stop_requested),
            (restart, stopped),
            "{action:?}"
        );
        if action == OnFailure::Stop {
            assert_eq!(info.code, 143);
        } else {
            assert_eq!(info.code, 137);
        }
    }
}

#[test]
fn the_sd_notify_messages_of_the_container_are_filtered_and_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("systemd-notify");
    let server = std::os::unix::net::UnixDatagram::bind(&target).unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut fx = Fixture::new("sleep 30");
    fx.config.sdnotify = velarx_runtime::monitor::notify::SdNotify::Container;
    fx.notify = Some(target.clone());
    std::fs::create_dir_all(&fx.root).unwrap();
    std::fs::write(fx.root.join("abcdef123456.sendready"), "").unwrap();
    // The spec of the container mounts the directory of the socket.
    std::fs::write(
        fx.bundle.join("notify_path"),
        fx.run_dir
            .join("notify.d/notify.sock")
            .display()
            .to_string(),
    )
    .unwrap();
    let m = fx.start_monitor();
    assert!(m.first.ok, "{:?}", m.first.error);
    assert!(fx.run_dir.join("notify.d/notify.sock").exists());
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let mut buf = [0u8; 256];
    // The unit's main process is the monitor.
    let n = server.recv(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert_eq!(text, format!("MAINPID={}\n", m.child.id()));
    let n = server.recv(&mut buf).unwrap();
    // MAINPID is not for a container to set.
    assert_eq!(&buf[..n], b"READY=1\nSTATUS=from the container\n");
    stop(&fx, m);
}

#[test]
fn in_conmon_mode_the_monitor_says_the_container_runs() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("systemd-notify");
    let server = std::os::unix::net::UnixDatagram::bind(&target).unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut fx = Fixture::new("sleep 30");
    fx.config.sdnotify = velarx_runtime::monitor::notify::SdNotify::Conmon;
    fx.notify = Some(target.clone());
    let m = fx.start_monitor();
    server.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 256];
    assert!(server.recv(&mut buf).is_err());
    server.set_nonblocking(false).unwrap();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let n = server.recv(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(text.starts_with("READY=1\nMAINPID="), "{text}");
    stop(&fx, m);
}

#[test]
fn without_sdnotify_nothing_is_forwarded_and_the_environment_is_not_leaked() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("systemd-notify");
    let server = std::os::unix::net::UnixDatagram::bind(&target).unwrap();
    server.set_nonblocking(true).unwrap();
    let mut fx = Fixture::new("sleep 30");
    std::fs::create_dir_all(&fx.root).unwrap();
    std::fs::write(fx.root.join("abcdef123456.sendready"), "").unwrap();
    fx.notify = Some(target.clone());
    let m = fx.start_monitor();
    let r = ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 });
    assert!(r.ok, "{:?}", r.error);
    // (a window: nothing may be forwarded)
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut buf = [0u8; 64];
    assert!(server.recv(&mut buf).is_err());
    let env = std::fs::read_to_string(fx.root.join("abcdef123456.notifyenv")).unwrap();
    assert_eq!(env.trim(), "", "the runtime saw {env}");
    stop(&fx, m);
}

#[test]
fn healthy_mode_says_ready_when_the_first_check_passes() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("systemd-notify");
    let server = std::os::unix::net::UnixDatagram::bind(&target).unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let marker = dir.path().join("ok");
    let mut fx = health_fixture(&marker, velarx_proto::health::OnFailure::None);
    fx.config.sdnotify = velarx_runtime::monitor::notify::SdNotify::Healthy;
    fx.notify = Some(target.clone());
    let m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    // While it is not healthy: the main process, and more time to start.
    let mut buf = [0u8; 128];
    let mut seen = Vec::new();
    for _ in 0..2 {
        let n = server.recv(&mut buf).unwrap();
        seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    // (a window: nothing more while the check fails)
    std::thread::sleep(std::time::Duration::from_millis(500));
    server.set_nonblocking(true).unwrap();
    while let Ok(n) = server.recv(&mut buf) {
        seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0], format!("MAINPID={}\n", m.child.id()));
    assert!(seen[1].starts_with("EXTEND_TIMEOUT_USEC="), "{seen:?}");
    server.set_nonblocking(false).unwrap();
    std::fs::write(&marker, "").unwrap();
    let n = server.recv(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("READY=1\nMAINPID="));
    stop(&fx, m);
}

#[test]
fn the_monitor_exits_with_the_status_of_the_container() {
    let fx = Fixture::new("exit 7");
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let info = fx.wait_for_exit(&mut m);
    assert_eq!(info.code, 7);
}

#[test]
fn sigterm_to_the_monitor_stops_the_container_with_its_stop_signal() {
    let mut fx = Fixture::new("trap 'exit 44' USR1; echo ready; while :; do sleep 0.05; done");
    fx.config.stop_signal = libc::SIGUSR1;
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    // (the trap is set once the command said so)
    wait_log_line(&fx.log, "ready");
    kill(m.child.id() as i32, libc::SIGTERM);
    let info = fx.wait_for_exit(&mut m);
    assert_eq!((info.code, info.stop_requested), (44, true));
}

#[test]
fn a_container_that_ignores_the_stop_signal_is_killed_after_the_stop_timeout() {
    let mut fx = Fixture::new("trap '' TERM; echo ready; while :; do sleep 0.05; done");
    fx.config.stop_timeout_secs = 1;
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    // (the trap is set once the command said so)
    wait_log_line(&fx.log, "ready");
    let started = std::time::Instant::now();
    kill(m.child.id() as i32, libc::SIGTERM);
    let info = fx.wait_for_exit(&mut m);
    assert_eq!(info.code, 137);
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));
}

fn restart_policy(
    name: &str,
    max: u32,
    count: u32,
) -> velarx_runtime::monitor::restart::RestartConfig {
    velarx_runtime::monitor::restart::RestartConfig {
        policy: Some(velarx_wire::monitor::proto::RestartSettings {
            policy: velarx_wire::monitor::proto::RestartPolicy::from_word(name).unwrap(),
            max_retries: max,
        }),
        count,
    }
}

/// The next `Started` or `Restarting` event: `(restarted or restarting, count)`.
fn next_run_event(conn: &Events) -> (&'static str, u32, bool) {
    match wait_event(conn, |e| {
        matches!(
            e,
            Event::Started { .. } | Event::Restarting { .. } | Event::Exited(_)
        )
    }) {
        Event::Started {
            restart_count,
            restarted,
            ..
        } => ("started", restart_count, restarted),
        Event::Restarting { restart_count, .. } => ("restarting", restart_count, false),
        Event::Exited(_) => ("exited", 0, false),
        _ => unreachable!(),
    }
}

#[test]
fn the_monitor_applies_the_restart_policy_without_a_daemon() {
    let mut fx = Fixture::new("echo run; exit 3");
    fx.config.restart = restart_policy("on-failure", 2, 0);
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let mut seen = Vec::new();
    for _ in 0..5 {
        seen.push(next_run_event(&m.events));
    }
    assert_eq!(
        seen,
        [
            ("started", 0, false),
            ("restarting", 1, false),
            ("started", 1, true),
            ("restarting", 2, false),
            ("started", 2, true),
        ]
    );
    let info = fx.wait_for_exit(&mut m);
    assert_eq!(info.code, 3);
    let runs = fx.log_lines().iter().filter(|l| *l == "out F run").count();
    assert_eq!(runs, 3);
    let deleted = std::fs::read_to_string(fx.root.join("deleted")).unwrap();
    assert_eq!(deleted.lines().count(), 3);
    let status: proto::ExitInfo =
        serde_json::from_slice(&std::fs::read(fx.run_dir.join(proto::EXIT_FILE)).unwrap()).unwrap();
    assert_eq!(status.code, 3);
}

#[test]
fn a_stop_while_a_restart_waits_ends_the_container() {
    let mut fx = Fixture::new("exit 0");
    // The sixth restart waits 3.2 s.
    fx.config.restart = restart_policy("always", 0, 5);
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    assert_eq!(next_run_event(&m.events), ("started", 5, false));
    assert_eq!(next_run_event(&m.events), ("restarting", 6, false));
    let status = ctl(&fx.run_dir, &Ctl::Status).status.unwrap();
    assert_eq!(status.state, RunState::Exited);
    assert_eq!(status.restarting.map(|e| e.code), Some(0));
    assert_eq!(status.restart_count, 6);
    let t = std::time::Instant::now();
    let reply = ctl(
        &fx.run_dir,
        &Ctl::Stop {
            signal: None,
            timeout_ms: None,
        },
    );
    assert!(reply.ok, "{:?}", reply.error);
    assert!(reply.core.unwrap().recorded);
    let info = fx.wait_for_exit(&mut m);
    assert!(info.stop_requested);
    assert!(t.elapsed() < std::time::Duration::from_secs(3));
}

#[test]
fn a_start_while_a_restart_waits_starts_the_container_now() {
    let mut fx = Fixture::new("sleep 0.2; exit 1");
    fx.config.restart = restart_policy("always", 0, 5);
    let m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    assert_eq!(next_run_event(&m.events), ("started", 5, false));
    assert_eq!(next_run_event(&m.events), ("restarting", 6, false));
    let t = std::time::Instant::now();
    let reply = ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 });
    assert!(reply.ok, "{:?}", reply.error);
    let status = reply.status.unwrap();
    assert_eq!(status.state, RunState::Running);
    assert!(status.restarting.is_none());
    assert!(t.elapsed() < std::time::Duration::from_secs(3));
    assert_eq!(next_run_event(&m.events), ("started", 6, true));
    let mut m = m;
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Stop {
                signal: None,
                timeout_ms: None
            }
        )
        .ok
    );
    let info = fx.wait_for_exit(&mut m);
    assert!(info.stop_requested);
}

#[test]
fn an_unhealthy_container_is_restarted_by_its_monitor() {
    use velarx_proto::health::OnFailure;
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("never");
    let fx = health_fixture(&marker, OnFailure::Restart);
    let m = fx.start_monitor();
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
    assert_eq!((exit.code, restart_count), (137, 1));
    assert_eq!(next_run_event(&m.events), ("started", 1, true));
    assert_eq!(next_health(&m.events).status.word(), "starting");
    let mut m = m;
    assert!(ctl(&fx.run_dir, &Ctl::Kill(libc::SIGKILL)).ok);
    let info = fx.wait_for_exit(&mut m);
    assert!(info.stop_requested);
}

/// The interface as varlink clients see it: its description, the
/// service's GetInfo, and the errors of calls the monitor cannot do.
#[test]
fn the_interface_is_served_and_bad_calls_are_answered() {
    use velarx_wire::monitor::iface::{self, error, service};
    use velarx_wire::varlink::CallError;
    let (fx, m) = running_fixture();
    let call = |name: &str, params: serde_json::Value, more: bool| {
        let mut c = client::connect(&fx.run_dir).unwrap();
        c.set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(20));
        c.call(name, &params, more, &[]).unwrap();
        c.reply::<serde_json::Value>()
    };
    let d = call(
        service::GET_INTERFACE_DESCRIPTION,
        serde_json::json!({"interface": iface::INTERFACE}),
        false,
    )
    .unwrap();
    assert_eq!(d.parameters["description"], iface::DEFINITION);
    let info = call(service::GET_INFO, serde_json::json!({}), false).unwrap();
    assert_eq!(info.parameters["interfaces"][1], iface::INTERFACE);
    let refused = |r: Result<velarx_wire::varlink::Reply<serde_json::Value>, CallError>| match r {
        Err(CallError::Remote { error, .. }) => error,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        refused(call(
            service::GET_INTERFACE_DESCRIPTION,
            serde_json::json!({"interface": "org.example.Nope"}),
            false
        )),
        error::INTERFACE_NOT_FOUND
    );
    assert_eq!(
        refused(call(
            "org.velarx.Monitor.Nope",
            serde_json::json!({}),
            false
        )),
        error::METHOD_NOT_FOUND
    );
    assert_eq!(
        refused(call(
            "org.velarx.Monitor.Attach",
            serde_json::json!({}),
            false
        )),
        error::EXPECTED_MORE
    );
    assert_eq!(
        refused(call(
            "org.velarx.Monitor.Signal",
            serde_json::json!({"signal": "TERM"}),
            false
        )),
        error::INVALID_PARAMETER
    );
    assert_eq!(
        refused(call(
            "org.velarx.Monitor.Signal",
            serde_json::json!({"signal": 99}),
            false
        )),
        error::INVALID_ARGUMENT
    );
    assert_eq!(
        refused(call(
            "org.velarx.Monitor.Detach",
            serde_json::json!({}),
            false
        )),
        error::INVALID_ARGUMENT
    );
    // a call that is not `oneway` while a stream is answered: its reply
    // would come after the stream, the connection ends
    let mut s = attach_session(&fx.run_dir, &proto::Attach::default());
    s.conn.send_method(&iface::GetStatus {}, &[]).unwrap();
    s.conn
        .set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(20));
    assert!(matches!(
        s.conn.reply::<serde_json::Value>(),
        Err(CallError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof
    ));
    // a call longer than the limit ends the connection, it is not cut
    let mut raw = std::os::unix::net::UnixStream::connect(fx.run_dir.join(proto::SOCKET)).unwrap();
    let big = vec![b' '; iface::MAX_CALL + 4096];
    use std::io::Write;
    let _ = raw.write_all(&big);
    raw.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    let mut b = [0u8; 16];
    assert!(matches!(raw.read(&mut b), Ok(0) | Err(_)));
    assert_eq!(status_state(&fx.run_dir), RunState::Running);
    stop(&fx, m);
}

/// The relay of the command line: the input of the client reaches the
/// command, its output and errors come back whole (more than the pipes
/// hold), then its status.
#[test]
fn the_exec_relay_passes_the_streams_and_the_status() {
    let (fx, m) = running_fixture();
    // (CLOEXEC: the monitors other tests start must not hold their ends)
    let pipe = || rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (in_r, in_w) = pipe();
    let (out_r, out_w) = pipe();
    let (err_r, err_w) = pipe();
    let dir = fx.run_dir.clone();
    let relay = std::thread::spawn(move || {
        relay::exec(
            &dir,
            &relay::ExecOptions {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "cat; head -c 3000000 /dev/zero >&2; exit 7".into(),
                ],
                stdin: true,
                ..Default::default()
            },
            in_r.as_fd(),
            out_w.as_fd(),
            err_w.as_fd(),
        )
        .unwrap()
    });
    let input = vec![b'x'; 2_000_000];
    let writer = std::thread::spawn(move || {
        std::io::Write::write_all(&mut std::fs::File::from(in_w), &input).unwrap();
    });
    let reader = std::thread::spawn(move || {
        let mut v = Vec::new();
        std::fs::File::from(err_r).read_to_end(&mut v).unwrap();
        v.len()
    });
    let mut out = Vec::new();
    std::fs::File::from(out_r).read_to_end(&mut out).unwrap();
    writer.join().unwrap();
    assert_eq!(relay.join().unwrap(), relay::ExecEnd::Exited(7));
    assert_eq!(out.len(), 2_000_000);
    assert!(out.iter().all(|&b| b == b'x'));
    assert_eq!(reader.join().unwrap(), 3_000_000);
    stop(&fx, m);
}

/// `OpenInit` passes a pidfd of the init: what is done through it (its
/// network namespace) is done to that process; a container that does not
/// run has none.
#[test]
fn the_pidfd_of_the_init_is_handed_over() {
    use std::os::unix::fs::MetadataExt;
    let fx = Fixture::new("sleep 30");
    let m = fx.start_monitor();
    let e = client::open_init(&fx.run_dir).err().unwrap();
    assert!(
        client::is_error(&e, velarx_wire::monitor::iface::error::NOT_RUNNING),
        "{e}"
    );
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let pidfd = client::open_init(&fx.run_dir).unwrap();
    // (the fake runtime's container is in the namespace of this process)
    match velarx_sys::ns::pidfd_net_namespace(pidfd.as_fd()) {
        Ok(ns) => {
            let own = std::fs::metadata("/proc/self/ns/net").unwrap();
            let got = std::fs::File::from(ns).metadata().unwrap();
            assert_eq!((own.dev(), own.ino()), (got.dev(), got.ino()));
        }
        Err(e) => assert!(matches!(
            e.raw_os_error(),
            Some(libc::ENOTTY | libc::EINVAL)
        )),
    }
    stop(&fx, m);
}

/// A container that ignores the stop signal is killed at the deadline of the
/// stop, which the monitor keeps; the reply comes with the recorded exit.
#[test]
fn a_stop_kills_a_container_that_ignores_its_signal_at_the_deadline() {
    let fx = Fixture::new("trap '' TERM; echo ready; sleep 30");
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 10_000
            }
        )
        .ok
    );
    // (the signal is ignored from here on)
    let mut session = attach_session(
        &fx.run_dir,
        &proto::Attach {
            start: true,
            ..Default::default()
        },
    );
    session.read_until("ready");
    drop(session);
    let t = std::time::Instant::now();
    let reply = ctl(
        &fx.run_dir,
        &Ctl::Stop {
            signal: None,
            timeout_ms: Some(500),
        },
    );
    assert!(reply.ok, "{:?}", reply.error);
    assert!(reply.killed);
    assert!(t.elapsed() >= std::time::Duration::from_millis(500));
    let core = reply.core.unwrap();
    assert!(core.recorded);
    assert_eq!(core.state, velarx_wire::monitor::proto::CoreState::Exited);
    assert_eq!(core.exit_code, Some(137));
    let info = fx.wait_for_exit(&mut m);
    assert!(info.stop_requested);
    // the monitor is gone with the recorded exit: a later stop reaches no
    // monitor (the engine reads the record then)
    let again = ctl(
        &fx.run_dir,
        &Ctl::Stop {
            signal: None,
            timeout_ms: None,
        },
    );
    assert!(!again.ok);
}

/// The deadline is the monitor's: the client that asked for the stop is gone
/// (the engine was killed) and the container is killed all the same.
#[test]
fn a_stop_is_finished_by_the_monitor_when_its_client_goes_away() {
    let fx = Fixture::new("trap '' TERM; echo ready; sleep 30");
    let mut m = fx.start_monitor();
    assert!(
        ctl(
            &fx.run_dir,
            &Ctl::Start {
                attach_wait_ms: 10_000
            }
        )
        .ok
    );
    // (the signal is ignored from here on)
    let mut session = attach_session(
        &fx.run_dir,
        &proto::Attach {
            start: true,
            ..Default::default()
        },
    );
    session.read_until("ready");
    drop(session);
    let t = std::time::Instant::now();
    let mut conn = client::connect(&fx.run_dir).unwrap();
    conn.send_method(
        &velarx_wire::monitor::iface::StopParams {
            signal: None,
            timeout_ms: Some(500),
        },
        &[],
    )
    .unwrap();
    drop(conn);
    let info = fx.wait_for_exit(&mut m);
    assert_eq!(info.code, 137);
    assert!(info.stop_requested);
    assert!(t.elapsed() >= std::time::Duration::from_millis(500));
    assert!(t.elapsed() < std::time::Duration::from_secs(8));
}

/// A kill is a stop: the restart policy does not start the container again.
#[test]
fn a_kill_is_not_restarted() {
    let mut fx = Fixture::new("sleep 30");
    fx.config.restart = restart_policy("always", 0, 0);
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    assert!(ctl(&fx.run_dir, &Ctl::Kill(libc::SIGKILL)).ok);
    let info = fx.wait_for_exit(&mut m);
    assert_eq!(info.code, 137);
    let status = ctl(&fx.run_dir, &Ctl::Status).status;
    assert!(status.is_none_or(|s| s.restart_count == 0));
    let again = ctl(&fx.run_dir, &Ctl::Kill(libc::SIGKILL));
    assert!(!again.ok);
}

/// `Wait` does not answer for a run that is restarted: the exit for good
/// is the one it tells.
#[test]
fn a_wait_across_restarts_answers_at_the_exit_for_good() {
    let mut fx = Fixture::new("exit 3");
    fx.config.restart = restart_policy("on-failure", 2, 0);
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let reply = ctl(&fx.run_dir, &Ctl::Wait);
    assert!(reply.ok, "{:?}", reply.error);
    let core = reply.core.unwrap();
    assert_eq!(core.exit_code, Some(3));
    assert!(core.recorded);
    let info = fx.wait_for_exit(&mut m);
    assert_eq!(info.code, 3);
}

/// The core is made by a client that speaks another definition; the rest is
/// not.
#[test]
fn the_core_is_made_whatever_the_digest_of_the_client() {
    let fx = Fixture::new("sleep 30");
    let mut m = fx.start_monitor();
    assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
    let other = velarx_wire::monitor::iface::digest(&format!(
        "{}# another version of this definition\n",
        velarx_wire::monitor::iface::DEFINITION
    ));
    let core = client::call_speaking(
        &fx.run_dir,
        &other,
        &velarx_wire::monitor::iface::GetCoreStatus {},
    )
    .unwrap()
    .status;
    assert_eq!(core.state, velarx_wire::monitor::proto::CoreState::Running);
    let refused = client::call_speaking(
        &fx.run_dir,
        &other,
        &velarx_wire::monitor::iface::GetStatus {},
    )
    .unwrap_err();
    assert!(matches!(
        client::monitor_error(&refused),
        Some(client::MonitorError::Version { .. })
    ));
    let (_, killed) = client::call_speaking(
        &fx.run_dir,
        &other,
        &velarx_wire::monitor::iface::StopParams {
            signal: None,
            timeout_ms: Some(0),
        },
    )
    .map(|r| (r.status, r.killed))
    .unwrap();
    assert!(killed);
    fx.wait_for_exit(&mut m);
}

/// A pause freezes the container with the runtime and says so; a resume
/// thaws it; neither is done twice.
#[test]
fn a_container_is_paused_and_resumed() {
    let (fx, m) = running_fixture();
    let calls = || std::fs::read_to_string(fx.root.join("calls")).unwrap_or_default();
    let reply = ctl(&fx.run_dir, &Ctl::Pause);
    assert!(reply.ok, "{:?}", reply.error);
    assert_eq!(reply.status.unwrap().state, RunState::Paused);
    assert_eq!(
        ctl(&fx.run_dir, &Ctl::CoreStatus).core.unwrap().state,
        velarx_wire::monitor::proto::CoreState::Paused
    );
    assert!(!ctl(&fx.run_dir, &Ctl::Pause).ok);
    let reply = ctl(&fx.run_dir, &Ctl::Resume);
    assert_eq!(reply.status.unwrap().state, RunState::Running);
    assert!(!ctl(&fx.run_dir, &Ctl::Resume).ok);
    assert_eq!(calls(), "pause abcdef123456\nresume abcdef123456\n");
    stop(&fx, m);
}

/// A stop thaws a frozen container first: it would not get the signal.
#[test]
fn a_stop_thaws_a_paused_container() {
    let (fx, mut m) = running_fixture();
    assert!(ctl(&fx.run_dir, &Ctl::Pause).ok);
    let reply = ctl(
        &fx.run_dir,
        &Ctl::Stop {
            signal: None,
            timeout_ms: None,
        },
    );
    assert!(reply.ok, "{:?}", reply.error);
    fx.wait_for_exit(&mut m);
    let calls = std::fs::read_to_string(fx.root.join("calls")).unwrap();
    assert_eq!(calls, "pause abcdef123456\nresume abcdef123456\n");
}

/// The directories of a checkpoint are descriptors of the call: the runtime
/// gets their places in the monitor's table, which are the directories.
#[test]
fn a_checkpoint_names_its_directories_by_descriptors() {
    let (fx, m) = running_fixture();
    let images = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let req = velarx_wire::monitor::proto::CheckpointRequest {
        leave_running: true,
        ..Default::default()
    };
    let r = ctl(
        &fx.run_dir,
        &Ctl::Checkpoint(
            req,
            images.path().to_path_buf(),
            Some(parent.path().to_path_buf()),
        ),
    );
    assert!(r.ok, "{:?}", r.error);
    let said = std::fs::read_to_string(fx.root.join("checkpoint")).unwrap();
    let canonical = |d: &tempfile::TempDir| std::fs::canonicalize(d.path()).unwrap();
    assert_eq!(
        said.trim(),
        format!(
            "image={} parent={}",
            canonical(&images).display(),
            canonical(&parent).display()
        )
    );
    stop(&fx, m);
}

/// The limits go to the runtime from a memory file of the call; what the
/// runtime refuses is an `InvalidArgument` with its words.
#[test]
fn the_resources_of_an_update_go_to_the_runtime() {
    use std::os::fd::AsFd;
    let (fx, m) = running_fixture();
    let update = |json: &str| {
        let file = velarx_base::sealed::sealed_memory(json.as_bytes()).unwrap();
        client::update(
            &fx.run_dir,
            &velarx_wire::monitor::proto::MonitorUpdate::default(),
            Some(file.as_fd()),
            None,
        )
    };
    update(r#"{"memory":{"limit":1048576}}"#).unwrap();
    let kept = std::fs::read_to_string(fx.root.join("abcdef123456.resources")).unwrap();
    assert_eq!(kept, r#"{"memory":{"limit":1048576}}"#);
    let e = update(r#"{"refused":true}"#).unwrap_err();
    assert!(
        client::is_error(&e, velarx_wire::monitor::iface::error::INVALID_ARGUMENT),
        "{e}"
    );
    assert!(e.to_string().contains("Invalid argument"), "{e}");
    stop(&fx, m);
}

/// The first call of the boot connection is `Create`: the container is made
/// by it, and not by anything else the connection asks.
#[test]
fn the_first_call_of_the_boot_connection_is_create() {
    use velarx_wire::monitor::iface;
    let fx = Fixture::new("sleep 30");
    let mut m = fx.start_monitor_calling(&[], |s| {
        let mut conn = velarx_wire::varlink::Conn::from_stream(s.try_clone().unwrap());
        conn.send_method(&iface::GetStatus {}, &[]).unwrap();
    });
    assert!(!m.first.ok, "created by a call that is not Create");
    assert!(
        m.first
            .error
            .as_deref()
            .is_some_and(|e| e.contains("first call")),
        "{:?}",
        m.first.error
    );
    // (the monitor ends without a container)
    assert!(m.child.wait().is_ok());
    assert!(!fx.run_dir.join(proto::PID_FILE).exists());
}

#[test]
fn calls_that_cannot_be_done_are_errors_not_silent_successes() {
    use velarx_wire::monitor::iface;
    let (fx, m) = running_fixture();
    // (Quit is for a container that was created and not started)
    let e = client::quit(&fx.run_dir).expect_err("quit of a running container");
    assert!(client::is_error(&e, iface::error::INVALID_STATE), "{e}");
    // (Signal is for the connection of an exec session: a container gets Kill)
    let e = client::call(
        &fx.run_dir,
        &iface::SignalParams {
            signal: libc::SIGTERM,
        },
    )
    .expect_err("signal outside a session");
    assert!(client::is_error(&e, iface::error::INVALID_STATE), "{e}");
    // (the fixture has no terminal)
    let e = client::resize(&fx.run_dir, 24, 80).expect_err("resize without a terminal");
    assert!(client::is_error(&e, iface::error::INVALID_STATE), "{e}");
    assert!(ctl(&fx.run_dir, &Ctl::Status).status.is_some());
    stop(&fx, m);
}

#[test]
fn a_session_says_where_it_is() {
    use velarx_wire::monitor::iface::{ExecReply, SessionPhase};
    let (fx, m) = running_fixture();
    let mut conn = open_exec(&fx, &exec_request(&["true"])).unwrap();
    conn.conn
        .set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(20));
    let mut last = None;
    while let Ok(r) = conn.conn.reply::<ExecReply>() {
        let done = r.parameters.exit.is_some();
        last = Some(r.parameters.phase);
        if done {
            break;
        }
    }
    assert_eq!(last, Some(SessionPhase::Ended));
    stop(&fx, m);
}

#[test]
fn create_is_called_once() {
    use velarx_wire::monitor::iface;
    let fx = Fixture::new("sleep 30");
    let m = fx.start_monitor();
    assert!(m.first.ok, "{:?}", m.first.error);
    let again = client::call(&fx.run_dir, &proto::CreateParams::default());
    let e = again.expect_err("created twice");
    assert!(client::is_error(&e, iface::error::INVALID_STATE), "{e}");
    assert!(ctl(&fx.run_dir, &Ctl::Quit).ok);
}

#[test]
fn a_restore_names_a_directory_among_the_descriptors() {
    use velarx_wire::monitor::iface;
    let fx = Fixture::new("sleep 30");
    let m = fx.start_monitor_calling(&[], |s| {
        let mut conn = velarx_wire::varlink::Conn::from_stream(s.try_clone().unwrap());
        // (no descriptor at all)
        conn.send_method(
            &proto::CreateParams {
                restore: Some(proto::RestoreRequest {
                    image_dir: 0,
                    ..Default::default()
                }),
            },
            &[],
        )
        .unwrap();
    });
    assert!(!m.first.ok);
    let why = m.first.error.clone().unwrap();
    assert!(why.contains("directory of the images"), "{why}");
    let _ = iface::INTERFACE;
}

/// What the engine's user gave is what the container sees, though the engine
/// raised its own limit of open files for the images it mounts and the
/// monitor was started with the raised one.
#[test]
fn a_container_has_the_limit_of_open_files_the_engine_user_gave() {
    velarx_base::testing::in_child(|| {
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(256),
                maximum: Some(4096),
            },
        )
        .unwrap();
        velarx_base::hardening::raise_open_files().unwrap();
        let mut fx = Fixture::new("echo limits $(ulimit -Sn) $(ulimit -Hn)");
        fx.config.open_files = velarx_base::hardening::original_open_files();
        let mut m = fx.start_monitor();
        assert!(ctl(&fx.run_dir, &Ctl::Start { attach_wait_ms: 0 }).ok);
        fx.wait_for_exit(&mut m);
        let lines = fx.log_lines();
        assert!(
            lines.iter().any(|l| l.ends_with("limits 256 4096")),
            "{lines:?}"
        );
    });
}
