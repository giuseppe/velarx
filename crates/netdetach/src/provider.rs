// SPDX-License-Identifier: Apache-2.0
//! The network providers (`org.velarx.Network`) a container's networks name:
//! which they are, and the blocking `Stop` that undoes what one made for a
//! container that ended (the engine's client of the other calls is async and
//! in the runtime).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use velarx_wire::request::{NetworkMode, PROVIDER_PREFIX};
use velarx_wire::varlink::{CallError, Conn, Method};

/// The version of the protocol: a client refuses another one.
pub const PROTO: u32 = 1;

const INTERFACE: &str = "org.velarx.Network";

/// A provider of the configuration, by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRef {
    pub name: String,
    pub socket: PathBuf,
}

#[derive(Serialize)]
struct GetInfo {}

impl Method for GetInfo {
    const INTERFACE: &'static str = INTERFACE;
    const NAME: &'static str = "GetInfo";
    type Reply = velarx_proto::info::Info;
}

#[derive(Serialize)]
struct Stop<'a> {
    id: &'a str,
}

/// What a call that returns nothing answers.
#[derive(Deserialize)]
pub struct Ack {}

impl Method for Stop<'_> {
    const INTERFACE: &'static str = INTERFACE;
    const NAME: &'static str = "Stop";
    type Reply = Ack;
}

/// Why the provider could not be told to stop.
#[derive(Debug, thiserror::Error)]
pub enum ProviderStopError {
    #[error("the network provider does not answer on {}: {source}", .socket.display())]
    Unreachable {
        socket: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("network provider: {0}")]
    Call(#[from] CallError),
    #[error("network provider: {0}")]
    Protocol(String),
}

/// `Stop` of the provider on `socket` for the container `id`: a connection
/// checked to be served by a trusted user, its `GetInfo` checked, then the
/// call.  Idempotent on the provider's side.
pub fn stop_blocking(socket: &Path, id: &str) -> Result<(), ProviderStopError> {
    let unreachable = |source| ProviderStopError::Unreachable {
        socket: socket.to_path_buf(),
        source,
    };
    let stream = std::os::unix::net::UnixStream::connect(socket).map_err(unreachable)?;
    check_peer(&stream).map_err(unreachable)?;
    let mut conn = Conn::from_stream(stream);
    conn.set_deadline(std::time::Instant::now() + std::time::Duration::from_secs(30));
    let (info, _) = conn.call_method(&GetInfo {}, &[])?;
    velarx_proto::info::check(INTERFACE, &info, PROTO).map_err(|e| {
        ProviderStopError::Protocol(format!("the provider on {}: {e}", socket.display()))
    })?;
    conn.call_method(&Stop { id }, &[])?;
    Ok(())
}

/// The peer of `stream` is served by a trusted user.
pub fn check_peer(stream: &std::os::unix::net::UnixStream) -> std::io::Result<()> {
    let uid = rustix::net::sockopt::socket_peercred(stream)?.uid.as_raw();
    if velarx_base::ipc::trusted_uid(uid) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("the service is served by uid {uid}"),
        ))
    }
}

/// The providers a container asks for: the NAME of each `provider:NAME` of
/// its networks (`mode` when it has no list).
pub fn names_of<'a>(mode: &'a NetworkMode, networks: &'a [String]) -> Vec<&'a str> {
    let listed: Vec<&str> = if networks.is_empty() {
        mode.provider().into_iter().collect()
    } else {
        networks
            .iter()
            .filter_map(|n| n.strip_prefix(PROVIDER_PREFIX))
            .collect()
    };
    let mut names: Vec<&str> = Vec::new();
    for name in listed {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    /// A provider that answers `GetInfo` with `proto` and then `Stop`: the
    /// calls it got, in order.
    fn serve(socket: &Path, proto: u32) -> std::thread::JoinHandle<Vec<String>> {
        let listener = UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut pending = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = c.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    return seen;
                }
                pending.extend_from_slice(&buf[..n]);
                while let Some(end) = pending.iter().position(|b| *b == 0) {
                    let call: serde_json::Value = serde_json::from_slice(&pending[..end]).unwrap();
                    pending.drain(..=end);
                    let method = call["method"].as_str().unwrap().to_string();
                    let reply = if method.ends_with("GetInfo") {
                        serde_json::json!({"parameters": {"name": "test", "version": "t",
                            "proto": proto, "capabilities": [], "limits": {}}})
                    } else {
                        serde_json::json!({"parameters": {}})
                    };
                    seen.push(method);
                    let mut bytes = serde_json::to_vec(&reply).unwrap();
                    bytes.push(0);
                    c.write_all(&bytes).unwrap();
                }
            }
        })
    }

    #[test]
    fn a_provider_is_asked_for_its_info_then_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("p.sock");
        let server = serve(&socket, PROTO);
        stop_blocking(&socket, "c1").unwrap();
        assert_eq!(
            server.join().unwrap(),
            ["org.velarx.Network.GetInfo", "org.velarx.Network.Stop"]
        );
    }

    #[test]
    fn a_provider_of_another_protocol_is_refused_before_the_stop() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("p.sock");
        let server = serve(&socket, PROTO + 1);
        let err = stop_blocking(&socket, "c1").unwrap_err();
        assert!(matches!(err, ProviderStopError::Protocol(_)), "{err}");
        assert_eq!(server.join().unwrap(), ["org.velarx.Network.GetInfo"]);
    }

    #[test]
    fn a_provider_that_is_not_there_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let err = stop_blocking(&dir.path().join("none.sock"), "c1").unwrap_err();
        assert!(
            matches!(err, ProviderStopError::Unreachable { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_container_names_its_providers() {
        let n = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(names_of(&NetworkMode::Provider("a".into()), &[]), ["a"]);
        assert_eq!(
            names_of(
                &NetworkMode::Bridge(None),
                &n(&["pasta", "provider:a", "provider:b", "provider:a"])
            ),
            ["a", "b"]
        );
        assert!(names_of(&NetworkMode::Bridge(None), &[]).is_empty());
    }
}
