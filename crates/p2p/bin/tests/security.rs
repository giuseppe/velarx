// SPDX-License-Identifier: Apache-2.0
//! The P2P service refuses to run in an unsafe configuration, and its socket
//! is private.  Runs the real `velarx-p2p` binary.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_velarx-p2p");

struct Node {
    dir: tempfile::TempDir,
    child: Option<Child>,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Node {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            child: None,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn key(&self, mode: u32) -> PathBuf {
        let key = self.path("swarm.key");
        let out = Command::new(BIN)
            .args(["generate-key"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        key
    }

    /// The configuration of the engine, with the lines `p2p` in the settings
    /// of the source `p2p`.
    fn config(&self, p2p: &str) -> PathBuf {
        let config = self.path("config.toml");
        let dir = self.dir.path().display();
        std::fs::write(
            &config,
            format!(
                "[server]\nsocket = \"{dir}/run/velarx.sock\"\n\
                 [[sources.external]]\nname = \"p2p\"\n\
                 socket = \"{dir}/run/services/p2p-fetcher.sock\"\n\
                 [sources.external.settings]\nmdns = false\n\
                 listen_addresses = [\"/ip4/127.0.0.1/tcp/0\"]\n{p2p}"
            ),
        )
        .unwrap();
        config
    }

    fn command(&self, config: &Path) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.arg("--config").arg(config);
        cmd.env_remove("VELARX_P2P_SWARM_KEY");
        cmd
    }

    fn services_dir(&self) -> PathBuf {
        self.path("run/services")
    }

    fn socket(&self) -> PathBuf {
        self.services_dir().join("p2p.sock")
    }

    fn start(&mut self, config: &Path) {
        let child = self
            .command(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.child = Some(child);
        if !velarx_base::testing::wait_path(&self.socket(), Duration::from_secs(20)) {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("the service exited: {status}");
            }
            panic!("the service did not start");
        }
    }
}

fn run(cmd: &mut Command) -> (bool, String) {
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn test_the_service_does_not_start_without_a_swarm_key() {
    let node = Node::new();
    let config = node.config("");
    let (ok, stderr) = run(&mut node.command(&config));
    assert!(!ok);
    assert!(stderr.contains("no swarm key"), "{stderr}");
    assert!(stderr.contains("generate-key"), "{stderr}");
    assert!(!node.socket().exists());
}

#[test]
fn test_the_service_does_not_start_with_a_key_others_can_read() {
    let node = Node::new();
    for mode in [0o644, 0o640, 0o604] {
        let key = node.key(0o600);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let config = node.config(&format!("private_key_path = \"{}\"\n", key.display()));
        let (ok, stderr) = run(&mut node.command(&config));
        assert!(!ok, "{mode:o}");
        assert!(stderr.contains("must not be accessible"), "{stderr}");
        std::fs::remove_file(&key).unwrap();
    }
}

#[test]
fn test_the_service_does_not_start_with_a_malformed_key() {
    let node = Node::new();
    let key = node.path("bad.key");
    std::fs::write(&key, "hello").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = node.config(&format!("private_key_path = \"{}\"\n", key.display()));
    let (ok, stderr) = run(&mut node.command(&config));
    assert!(!ok);
    assert!(stderr.contains("invalid swarm key"), "{stderr}");
}

#[test]
fn test_generate_key_makes_a_private_file_and_does_not_replace_one() {
    let node = Node::new();
    let key = node.key(0o600);
    assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o777, 0o600);
    let before = std::fs::read(&key).unwrap();
    let (ok, stderr) = run(Command::new(BIN).arg("generate-key").arg(&key));
    assert!(!ok);
    assert!(stderr.contains("exists"), "{stderr}");
    assert_eq!(std::fs::read(&key).unwrap(), before);
}

#[test]
fn test_the_swarm_key_may_come_from_the_environment() {
    let mut node = Node::new();
    let key = node.key(0o600);
    let content = std::fs::read_to_string(&key).unwrap();
    let config = node.config("");
    let child = node
        .command(&config)
        .env("VELARX_P2P_SWARM_KEY", content)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    node.child = Some(child);
    assert!(
        velarx_base::testing::wait_path(&node.socket(), Duration::from_secs(20)),
        "the service did not start"
    );
}

#[test]
fn test_the_socket_is_private_and_answers_its_owner() {
    let mut node = Node::new();
    let key = node.key(0o600);
    let config = node.config(&format!("private_key_path = \"{}\"\n", key.display()));
    node.start(&config);
    assert_eq!(
        std::fs::metadata(node.services_dir()).unwrap().mode() & 0o777,
        0o700
    );
    let meta = std::fs::metadata(node.socket()).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o600);
    assert_eq!(meta.uid(), rustix::process::geteuid().as_raw());

    let mut stream = std::os::unix::net::UnixStream::connect(node.socket()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // varlink: one JSON object, ended by a NUL, for the call and for the answer
    stream
        .write_all(b"{\"method\":\"org.velarx.P2p.Status\"}\0")
        .unwrap();
    let mut answer = Vec::new();
    std::io::BufRead::read_until(&mut std::io::BufReader::new(&stream), 0, &mut answer).unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.contains("peer_id"), "{answer}");
}

#[test]
fn test_a_socket_directory_others_can_enter_is_refused() {
    let node = Node::new();
    let key = node.key(0o600);
    let config = node.config(&format!("private_key_path = \"{}\"\n", key.display()));
    std::fs::create_dir_all(node.services_dir()).unwrap();
    std::fs::set_permissions(node.services_dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let (ok, stderr) = run(&mut node.command(&config));
    assert!(!ok, "the service runs with a socket others could reach");
    assert!(stderr.contains("chmod 700"), "{stderr}");
    assert!(!node.socket().exists());
}
