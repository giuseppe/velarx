// SPDX-License-Identifier: Apache-2.0
//! What the front of the registry fetcher (`velarx-registry`) and its worker
//! spawner may reach for the registries: the registries configuration, the
//! certificates, the auth files, the registry hints and the worker binary.
//! The confinement itself (Landlock, seccomp, capabilities, the roles) is
//! `velarx_sandbox::fetch`, which the directory fetcher (`velarx-dir`) uses
//! as well.

use std::path::{Path, PathBuf};
use velarx_config::Config;
use velarx_sandbox::fetch::{runtime_files, Reach, LOADERS};
use velarx_sys::spawner::Spawner;

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The files and directories of velarx's configuration directories that a
/// pull reads.
const REGISTRY_FILES: [&str; 7] = [
    "registries.conf",
    "registries.conf.d",
    "certs.d",
    "policy.json",
    "registries.d",
    "registries.rootless.d",
    "registries.rootful.d",
];

/// What the process that starts the workers needs: what a worker reads
/// (the runtime's files, the certificates a variable names) and the worker
/// and the loader it executes.  Not the configuration of the registries,
/// the auth files or the certificates of the hosts: the front reads those and
/// hands a worker what it needs.
pub fn spawner_reach(worker: &Path) -> Reach {
    let mut read = runtime_files();
    // (`/proc/self` of a worker is not this process' directory of /proc: all
    // of /proc is readable by the domain a worker inherits, and other
    // processes' memory and environment are not, Landlock refuses the access
    // to a process outside the domain)
    read.push("/proc".into());
    for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        read.extend(env_path(var));
    }
    let mut execute: Vec<PathBuf> = vec![worker.to_path_buf()];
    execute.extend(LOADERS.iter().map(PathBuf::from));
    Reach {
        read,
        execute,
        ..Reach::default()
    }
}

/// What the front process of a fetcher with this configuration needs.
/// `worker`: the binary of the pull workers; `services`: the directory of
/// the socket, where files may be removed (and nothing created) when this
/// process bound the socket itself (it takes it away as it leaves).
pub fn reach(
    config: &Config,
    worker: &Path,
    services: Option<&Path>,
) -> Result<Reach, velarx_base::ids::IdsError> {
    let mut read = runtime_files();
    // registries.conf, its drop-ins, the certificates and the policy (not
    // the rest of velarx's directories: config.toml, the API's token)
    let user = velarx_base::conf::user_config_dir()?.map(|d| d.join("velarx"));
    for dir in [Some(PathBuf::from("/etc/velarx")), user]
        .into_iter()
        .flatten()
    {
        read.extend(REGISTRY_FILES.iter().map(|f| dir.join(f)));
    }
    read.push("/etc/docker/certs.d".into());
    read.extend(env_path(velarx_registry::config::REGISTRIES_CONF_ENV));
    // the auth files, in the order the credentials are looked up: the file
    // `$REGISTRY_AUTH_FILE` names, the directories of the others (`login`
    // may make one later)
    let explicit = env_path("REGISTRY_AUTH_FILE");
    let mut auth_files = velarx_registry::auth::default_auth_files()?.into_iter();
    if let Some(file) = explicit {
        auth_files.next();
        read.push(file);
    }
    read.extend(auth_files.filter_map(|f| f.parent().map(Path::to_path_buf)));
    for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        read.extend(env_path(var));
    }
    let mut execute: Vec<PathBuf> = vec![worker.to_path_buf()];
    execute.extend(LOADERS.iter().map(PathBuf::from));
    let state = if config.pull.registry_hints {
        vec![velarx_registry::hints::HintStore::default_dir()?]
    } else {
        Vec::new()
    };
    Ok(Reach {
        read,
        execute,
        remove: services.map(Path::to_path_buf).into_iter().collect(),
        cgroups: None,
        state,
        staging: None,
        origin: None,
    })
}

/// The results of `pull-worker --self-test --connect-port 443`, started by
/// `spawner` and read as the front reads a worker's reply (a frame on its
/// socket).
fn worker_self_test(spawner: &std::sync::Arc<Spawner>) -> Result<Vec<(String, bool)>, String> {
    use std::io::Read;
    let (mut mine, theirs) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
    let (_names, names) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
    let args = ["pull-worker", "--self-test", "--connect-port", "443"]
        .map(String::from)
        .to_vec();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let mut worker = runtime
        .block_on(crate::net::pool::start_worker(
            spawner,
            args,
            Vec::new(),
            theirs.into(),
            names.into(),
        ))
        .map_err(|e| format!("cannot start a worker: {e}"))?;
    let mut reply = Vec::new();
    let read = mine.read_to_end(&mut reply);
    let status = runtime.block_on(worker.wait()).map_err(|e| e.to_string())?;
    read.map_err(|e| e.to_string())?;
    // (kind, 3 bytes, the length of the JSON, 16 bytes, the JSON)
    let body = reply.get(24..).ok_or("the worker sent no reply")?;
    if reply[0] != crate::net::proto::Kind::Reply as u8 {
        return Err(format!(
            "the worker refused ({status}): {}",
            String::from_utf8_lossy(body)
        ));
    }
    serde_json::from_slice(body).map_err(|e| e.to_string())
}

/// Try, in the confined front, what its confinement allows and refuses:
/// `(what, as it should be)`: those of [`velarx_sandbox::fetch::probes`] and
/// what `spawner` (which starts its workers) says of a worker's own
/// self-test, given one TCP port (the worker narrows the spawner's domain to
/// it).
pub fn probes(
    staging: &std::os::fd::OwnedFd,
    spawner: &std::sync::Arc<Spawner>,
    socket: Option<&Path>,
) -> Vec<(String, bool)> {
    let mut out = velarx_sandbox::fetch::probes(staging, socket);
    match worker_self_test(spawner) {
        Ok(results) => {
            // (`kill(2)` of itself is refused by the filter of the spawner,
            // which the worker inherits: the spawner signals by pidfd only)
            for (what, ok) in results.into_iter().filter(|(w, _)| w != "signal itself") {
                out.push((format!("worker: {what}"), ok));
            }
        }
        Err(e) => out.push((format!("starts a worker: {e}"), false)),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_sandbox::fetch::{enter, Role};

    /// What a test child may reach: the libraries, and a program it may
    /// execute.
    fn paths(dir: &Path) -> Reach {
        std::fs::create_dir_all(dir.join("state")).unwrap();
        Reach {
            read: velarx_sandbox::READABLE.iter().map(PathBuf::from).collect(),
            execute: LOADERS.iter().map(PathBuf::from).collect(),
            state: vec![dir.join("state")],
            ..Reach::default()
        }
    }

    /// The confined front cannot run a credential helper, and gets what one
    /// says through the runner it forked before the confinement.
    #[test]
    fn a_confined_front_gets_the_credentials_of_a_helper_from_its_runner() {
        use velarx_registry::helper::HelperRunner;
        use velarx_registry::AuthConfig;
        // (made and removed by the test process: the confined child that
        // uses it may not remove it)
        // (a rootful engine looks its helpers up in ROOT_PATH only, which a
        // test does not write to)
        if velarx_base::ids::rootful().unwrap() {
            return eprintln!("skipped: root looks for credential helpers in its own path");
        }
        let dir = tempfile::tempdir().unwrap();
        velarx_base::testing::in_child(|| {
            let mut access = paths(dir.path());
            let bin = dir.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            let helper = bin.join("docker-credential-fake");
            velarx_base::testing::write_script(
                &helper,
                "read s\necho \"{\\\"Username\\\":\\\"u\\\",\\\"Secret\\\":\\\"secret-of-$s\\\"}\"",
            );
            let config = dir.path().join("config.json");
            std::fs::write(&config, r#"{"credsStore": "fake"}"#).unwrap();
            // child-only
            std::env::set_var("PATH", format!("{}:/usr/bin:/bin", bin.display()));
            // child-only
            std::env::set_var("REGISTRY_AUTH_FILE", &config);
            access.read.push(config);
            let runner = std::sync::Arc::new(HelperRunner::start().unwrap());
            enter(&access, Role::Front).expect("the front process confines itself");
            let direct = std::process::Command::new(&helper).status();
            assert!(direct.is_err(), "the confined front runs a helper itself");
            let auth = AuthConfig::load().unwrap().with_helper_runner(runner);
            let c = auth.lookup("registry.test", "img").unwrap().unwrap();
            assert_eq!(c.username, "u");
            assert_eq!(c.password, "secret-of-registry.test");
        });
    }

    #[test]
    fn the_access_follows_the_environment_and_the_configuration() {
        let config = Config::default();
        let a = reach(&config, Path::new("/usr/bin/velarx"), None).unwrap();
        assert!(a.remove.is_empty());
        assert_eq!(
            a.state,
            vec![velarx_registry::hints::HintStore::default_dir().unwrap()]
        );
        let mut off = Config::default();
        off.pull.registry_hints = false;
        assert!(reach(&off, Path::new("/x"), None).unwrap().state.is_empty());
        assert!(a.execute.contains(&PathBuf::from("/usr/bin/velarx")));
        assert!(a
            .read
            .contains(&PathBuf::from("/etc/velarx/registries.conf")));
        assert!(!a.read.contains(&PathBuf::from("/etc/velarx")));
        // velarx's own directories (config.toml, the API's token, the state
        // of the containers) are not readable through an auth file's
        // directory either
        let mut own_dirs = vec![PathBuf::from("/etc/velarx"), PathBuf::from("/run/velarx")];
        own_dirs.extend(
            velarx_base::conf::user_config_dir()
                .unwrap()
                .map(|d| d.join("velarx")),
        );
        own_dirs.extend(env_path("XDG_RUNTIME_DIR").map(|d| d.join("velarx")));
        for dir in &own_dirs {
            assert!(
                !a.read.iter().any(|r| dir.starts_with(r)),
                "{} is readable: {:?}",
                dir.display(),
                a.read
            );
        }
        let own = reach(
            &config,
            Path::new("/x"),
            Some(Path::new("/run/velarx/services")),
        )
        .unwrap();
        assert_eq!(own.remove, vec![PathBuf::from("/run/velarx/services")]);
    }
}
