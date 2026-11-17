// SPDX-License-Identifier: Apache-2.0
//! The configuration of `velarx-api`: its own section of `config.toml`
//! (`[api]`), and the socket paths it shares with the engine
//! (`[server] socket`, `[engine] socket`).  It reads the file once, before
//! it confines itself, and ignores every other section.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use velarx_base::dirs::DefaultDirs;

/// The default port of `tcp` without one.
pub const DEFAULT_TCP_PORT: u16 = 8080;

#[derive(Debug, Default, Deserialize)]
struct File {
    #[serde(default)]
    api: Api,
    #[serde(default)]
    server: Server,
    #[serde(default)]
    engine: Engine,
}

#[derive(Debug, Default, Deserialize)]
struct Server {
    socket: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct Engine {
    socket: Option<PathBuf>,
}

/// `[api]`
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Api {
    /// The unix socket of the API when nothing passes one (default:
    /// `[server] socket`, else `velarx.sock` in the runtime directory)
    pub socket: Option<PathBuf>,
    /// Where else to listen: `tcp://HOST:PORT`, `tcp://:PORT` (the
    /// loopback addresses, both families) or `unix:///PATH`.  There is no
    /// TCP listener unless one is listed.
    pub listen: Vec<String>,
    /// A frontend that systemd started leaves after this many seconds with
    /// no connection (its socket starts it again); 0 keeps it.  A frontend
    /// that bound its sockets itself never leaves.
    pub idle_exit: Option<u64>,
    /// Start the engine (`velarx` next to this program) for as long as
    /// the frontend runs (default: when systemd did not start the
    /// frontend)
    pub start_engine: Option<bool>,
    /// The file with the token that the requests on a TCP listener carry as
    /// `Authorization: Bearer TOKEN` (at least 16 printable characters, mode
    /// 0600).  A TCP listener needs it or `allow_unauthenticated`.
    pub token_file: Option<PathBuf>,
    /// TLS for the TCP listeners (PEM files; podman's `--tls-cert` and
    /// `--tls-key`): the certificate chain of the server and its key
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Only clients whose certificate this CA (PEM) signed are served
    /// (podman's `--tls-client-ca`); the certificate is then what
    /// authenticates, and the token is not needed
    pub tls_client_ca: Option<PathBuf>,
    /// Serve the TCP listeners with no authentication: every local user
    /// that can connect controls the engine.
    pub allow_unauthenticated: bool,
    /// The engine's (the short names of the Docker API): taken, not read
    pub compat_api_enforce_docker_hub: Option<bool>,
}

/// What the frontend needs from the configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub api: Api,
    /// The socket of the engine
    pub engine_socket: PathBuf,
    /// The socket of the API when nothing passes one
    pub api_socket: PathBuf,
}

impl Config {
    /// Read `path`; a file that is not there is the defaults.
    pub fn load(path: &Path) -> Result<Self, String> {
        let file: File = match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let run = match file.server.socket.as_deref().and_then(Path::parent) {
            Some(dir) => dir.to_path_buf(),
            None => DefaultDirs::current().map_err(|e| e.to_string())?.run,
        };
        Ok(Self {
            engine_socket: file
                .engine
                .socket
                .unwrap_or_else(|| run.join("engine/engine.sock")),
            api_socket: file
                .api
                .socket
                .clone()
                .or(file.server.socket.clone())
                .unwrap_or_else(|| run.join("velarx.sock")),
            api: file.api,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sockets_follow_the_servers_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        std::fs::write(
            &file,
            "[server]\nsocket = \"/x/run/velarx.sock\"\n[storage]\nroot = \"/y\"\n\
             [api]\nlisten = [\"tcp://:9\"]\nidle_exit = 5\n",
        )
        .unwrap();
        let c = Config::load(&file).unwrap();
        assert_eq!(c.engine_socket, PathBuf::from("/x/run/engine/engine.sock"));
        // (the socket of the server's section is the API's)
        assert_eq!(c.api_socket, PathBuf::from("/x/run/velarx.sock"));
        assert_eq!(c.api.listen, ["tcp://:9"]);
        assert_eq!(c.api.idle_exit, Some(5));
        std::fs::write(
            &file,
            "[engine]\nsocket = \"/e.sock\"\n[api]\nsocket = \"/a.sock\"\n",
        )
        .unwrap();
        let c = Config::load(&file).unwrap();
        assert_eq!(c.engine_socket, PathBuf::from("/e.sock"));
        assert_eq!(c.api_socket, PathBuf::from("/a.sock"));
        // no file: the defaults
        let c = Config::load(&dir.path().join("none.toml")).unwrap();
        assert!(c.engine_socket.ends_with("engine.sock"));
        assert!(Config::load(dir.path()).is_err());
    }
}
