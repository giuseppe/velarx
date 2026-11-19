// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;
use velarx_config::Config;
use velarx_db::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub fuse_passthrough: bool,
    pub userns_support: bool,
    /// The user's systemd manager (rootless only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd: Option<SystemdInfo>,
    /// The CDI spec directories, the devices in them, the errors of the files
    pub cdi: crate::cdi::Info,
}

/// Whether a rootless user's units run, and run at boot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemdInfo {
    /// The user's manager answers (its private socket).
    pub user_manager: bool,
    /// Lingering is on: the manager, and the units it starts, run at boot
    /// without a session.
    pub linger: bool,
    /// What does not work because of it, as podman warns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl SystemdInfo {
    /// The state of the manager of `user`, from its runtime directory and
    /// the linger directory of logind.
    pub fn probe(
        user: &str,
        runtime_dir: Option<&std::path::Path>,
        linger_dir: &std::path::Path,
        systemd_cgroups: bool,
    ) -> Self {
        let user_manager = runtime_dir.is_some_and(|d| {
            std::os::unix::net::UnixStream::connect(d.join("systemd/private")).is_ok()
        });
        let linger = !user.is_empty() && linger_dir.join(user).exists();
        let warning = if !user_manager && systemd_cgroups {
            Some(format!(
                "no systemd user session available for {user}: the systemd cgroup manager \
                 cannot be used; try `loginctl enable-linger {user}`"
            ))
        } else if !linger {
            Some(format!(
                "lingering is off for {user}: the user units (velarx-engine.socket, \
                 velarx-restart.service) do not start at boot; `loginctl enable-linger {user}` \
                 turns it on"
            ))
        } else {
            None
        };
        Self {
            user_manager,
            linger,
            warning,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub overall: HealthStatus,
    pub components: Vec<ComponentHealth>,
}

pub struct ServerService {
    config: Arc<Config>,
    db: Database,
    /// A restart was asked (`velarx system restart`): the daemon stops
    /// and starts again, its socket kept
    restart: Arc<tokio::sync::Notify>,
    /// The restart executes the binary installed, not the one that runs
    upgrade: Arc<std::sync::atomic::AtomicBool>,
}

impl ServerService {
    pub fn new(config: Arc<Config>, db: Database) -> Self {
        Self {
            config,
            db,
            restart: Arc::new(tokio::sync::Notify::new()),
            upgrade: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub async fn info(&self) -> Result<ServerInfo, velarx_base::ids::IdsError> {
        Ok(ServerInfo {
            fuse_passthrough: check_fuse_passthrough()?,
            userns_support: check_userns_support().map_err(velarx_base::ids::IdsError)?,
            systemd: self.systemd_info()?,
            cdi: crate::cdi::info(&self.config.containers.cdi_spec_dirs),
        })
    }

    /// The user's manager, for a rootless daemon.
    fn systemd_info(&self) -> Result<Option<SystemdInfo>, velarx_base::ids::IdsError> {
        let uid = crate::userns::rootless::host_uid()?;
        if uid == 0 {
            return Ok(None);
        }
        let user = crate::userns::rootless::user_name(uid).unwrap_or_else(|| uid.to_string());
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from);
        Ok(Some(SystemdInfo::probe(
            &user,
            runtime.as_deref(),
            std::path::Path::new("/var/lib/systemd/linger"),
            matches!(
                self.config.server.cgroup_manager,
                velarx_config::CgroupDriver::Systemd
            ),
        )))
    }

    pub async fn health(&self) -> HealthResponse {
        let components = vec![
            check_database_health(&self.db).await,
            check_storage_health(&self.config.storage.root.to_string_lossy()),
            check_runtime_health(),
        ];

        let overall = if components.iter().all(|c| c.status == HealthStatus::Healthy) {
            HealthStatus::Healthy
        } else if components
            .iter()
            .any(|c| c.status == HealthStatus::Unhealthy)
        {
            HealthStatus::Unhealthy
        } else {
            HealthStatus::Degraded
        };

        HealthResponse {
            overall,
            components,
        }
    }

    /// Ask the daemon to start again (with its configuration read again);
    /// the containers go on.
    pub async fn restart(&self, timeout: u32) {
        info!("Restart asked ({}s for the requests in progress)", timeout);
        self.restart.notify_one();
    }

    /// Ask the daemon to start again from the binary installed, which is
    /// not the one that runs (an upgrade replaced it); the containers go on.
    pub fn restart_upgraded(&self) {
        info!("Restart into the binary installed asked");
        self.upgrade
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.restart.notify_one();
    }

    /// Whether the restart asked is into the binary installed.
    pub fn upgrading(&self) -> bool {
        self.upgrade.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// What the daemon waits on for a restart.
    pub fn restart_signal(&self) -> Arc<tokio::sync::Notify> {
        self.restart.clone()
    }
}

/// Whether the FUSE servers of this engine can hand the kernel the files
/// they serve: the kernel has FUSE passthrough (Linux 6.9, below the
/// minimum kernel), and it asks `CAP_SYS_ADMIN` in the initial user
/// namespace of the server for each backing file
/// (`FUSE_DEV_IOC_BACKING_OPEN`): never for a rootless engine.
fn check_fuse_passthrough() -> Result<bool, velarx_base::ids::IdsError> {
    Ok(velarx_base::ids::rootful()?
        && rustix::thread::capabilities(None).is_ok_and(|c| {
            c.effective
                .contains(rustix::thread::CapabilitySet::SYS_ADMIN)
        }))
}

/// Whether the sysctls let a user make a user namespace: the number of
/// them is above 0 and, where the kernel has Debian's switch, it is on.
/// A sysctl that is not there says nothing; one that cannot be read or
/// parsed is an error.
fn check_userns_support() -> std::io::Result<bool> {
    let read = |path: &str| match std::fs::read_to_string(path) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(std::io::Error::new(e.kind(), format!("{path}: {e}"))),
    };
    userns_allowed(
        read("/proc/sys/kernel/unprivileged_userns_clone")?.as_deref(),
        read("/proc/sys/user/max_user_namespaces")?.as_deref(),
    )
}

fn userns_allowed(clone: Option<&str>, max: Option<&str>) -> std::io::Result<bool> {
    let number = |name: &str, v: &str| {
        v.trim().parse::<u64>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the sysctl {name} is `{}`: {e}", v.trim()),
            )
        })
    };
    let clone = clone
        .map(|v| number("kernel.unprivileged_userns_clone", v))
        .transpose()?;
    let max = max
        .map(|v| number("user.max_user_namespaces", v))
        .transpose()?;
    Ok(clone != Some(0) && max.is_some_and(|n| n > 0))
}

/// The database answers a read of its schema; else the engine cannot do
/// anything.
async fn check_database_health(db: &Database) -> ComponentHealth {
    let (status, message) = match db.ping().await {
        Ok(()) => (HealthStatus::Healthy, None),
        Err(e) => (HealthStatus::Unhealthy, Some(e.to_string())),
    };
    ComponentHealth {
        name: "database".to_string(),
        status,
        message,
    }
}

fn check_storage_health(path: &str) -> ComponentHealth {
    if std::path::Path::new(path).exists() {
        ComponentHealth {
            name: "storage".to_string(),
            status: HealthStatus::Healthy,
            message: None,
        }
    } else {
        ComponentHealth {
            name: "storage".to_string(),
            status: HealthStatus::Degraded,
            message: Some("Storage directory not found".to_string()),
        }
    }
}

fn check_runtime_health() -> ComponentHealth {
    match crate::container::which_runtime() {
        Ok(_) => ComponentHealth {
            name: "oci_runtime".to_string(),
            status: HealthStatus::Healthy,
            message: Some(format!("Using {}", crate::container::runtime_name())),
        },
        Err(_) => ComponentHealth {
            name: "oci_runtime".to_string(),
            status: HealthStatus::Unhealthy,
            message: Some("No OCI runtime found".to_string()),
        },
    }
}

#[cfg(test)]
mod systemd_info_tests {
    use super::SystemdInfo;

    #[test]
    fn linger_and_the_user_manager() {
        let d = tempfile::tempdir().unwrap();
        let linger = d.path().join("linger");
        std::fs::create_dir(&linger).unwrap();
        let run = d.path().join("run");
        std::fs::create_dir_all(run.join("systemd")).unwrap();

        let i = SystemdInfo::probe("alice", Some(&run), &linger, false);
        assert!(!i.user_manager && !i.linger);
        assert!(i.warning.unwrap().contains("loginctl enable-linger alice"));
        let i = SystemdInfo::probe("alice", None, &linger, true);
        assert!(i.warning.unwrap().contains("no systemd user session"));

        std::fs::write(linger.join("alice"), "").unwrap();
        let _l = std::os::unix::net::UnixListener::bind(run.join("systemd/private")).unwrap();
        let i = SystemdInfo::probe("alice", Some(&run), &linger, true);
        assert_eq!(
            i,
            SystemdInfo {
                user_manager: true,
                linger: true,
                warning: None
            }
        );
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;

    /// A user namespace needs a number of them above 0 and, with Debian's
    /// switch, the switch on; an unreadable value is an error.
    #[test]
    fn user_namespaces_follow_the_values_of_the_sysctls() {
        assert!(userns_allowed(None, Some("1000\n")).unwrap());
        assert!(userns_allowed(Some("1\n"), Some("1000\n")).unwrap());
        assert!(!userns_allowed(Some("0\n"), Some("1000\n")).unwrap());
        assert!(!userns_allowed(None, Some("0\n")).unwrap());
        assert!(!userns_allowed(None, None).unwrap());
        assert!(userns_allowed(Some("x"), Some("1")).is_err());
        assert!(userns_allowed(None, Some("")).is_err());
    }

    /// A database that answers is healthy, one that does not is not.
    #[tokio::test]
    async fn the_database_is_asked() {
        let db = Database::open_in_memory().await.unwrap();
        let h = check_database_health(&db).await;
        assert_eq!((h.status, h.message), (HealthStatus::Healthy, None));
        db.stop().await.unwrap();
        let h = check_database_health(&db).await;
        assert_eq!(h.status, HealthStatus::Unhealthy);
        assert!(h.message.is_some());
    }
}
