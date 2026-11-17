// SPDX-License-Identifier: Apache-2.0
//! `velarx-kube` confines itself: the built binary, its `self-test`, which
//! confines the process as a command does and tries from inside what the
//! confinement forbids and what it allows.

use std::process::Command;

const KUBE: &str = env!("CARGO_BIN_EXE_velarx-kube");

/// What the confined process found, by the name of each probe.
fn self_test(connect_port: Option<u16>) -> Vec<(String, bool)> {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("existing"), "old").unwrap();
    // (a socket that listens in the directory the process may not look in,
    // and the one of the engine, which it reaches through its connector)
    let _outside_socket =
        std::os::unix::net::UnixListener::bind(outside.join("engine.sock")).unwrap();
    std::fs::create_dir(dir.path().join("engine")).unwrap();
    let _engine =
        std::os::unix::net::UnixListener::bind(dir.path().join("engine/engine.sock")).unwrap();
    let mut cmd = Command::new(KUBE);
    cmd.arg("--engine-socket")
        .arg(dir.path().join("engine/engine.sock"))
        .arg("self-test")
        .arg("--outside")
        .arg(&outside);
    if let Some(port) = connect_port {
        cmd.arg("--connect-port").arg(port.to_string());
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "the confinement failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // (what the confined process made, and could not remove, goes with the
    // directory)
    serde_json::from_slice(&out.stdout).unwrap()
}

fn failed(results: &[(String, bool)]) -> Vec<&str> {
    results
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(what, _)| what.as_str())
        .collect()
}

/// A play (or a down, a generate): the engine's socket, no file made, no TCP.
#[test]
fn a_play_reaches_the_engine_and_makes_no_file() {
    let results = self_test(None);
    assert_eq!(failed(&results), Vec::<&str>::new(), "{results:?}");
    for what in [
        "makes no file outside",
        "rewrites no existing file",
        "connects to no UNIX socket by name",
        "connects to the engine's socket through its connector",
        "connects to no TCP port it was not given",
        "executes nothing",
        "makes no process",
        "signals no process outside",
        "seccomp filter mode",
    ] {
        assert!(results.iter().any(|(w, _)| w == what), "no probe `{what}`");
    }
}

/// An apply: the port of the API server, and no other.
#[test]
fn an_apply_connects_to_the_port_of_the_api_server_only() {
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let results = self_test(Some(port));
    assert_eq!(failed(&results), Vec::<&str>::new(), "{results:?}");
    assert!(results
        .iter()
        .any(|(w, _)| w == "connects to the TCP port it was given"));
}

#[test]
fn the_version_is_printed() {
    let out = Command::new(KUBE).arg("--version").output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("velarx-kube "));
}
