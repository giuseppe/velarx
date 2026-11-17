// SPDX-License-Identifier: Apache-2.0
//! The init process of a container (`--init`): the binary of the host that
//! runs as PID 1 and starts the command, and the arguments it takes.

use std::path::{Path, PathBuf};

/// Available init systems
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitSystem {
    /// Use tini
    Tini,
    /// Use dumb-init
    DumbInit,
    /// Use catatonit (podman's default)
    Catatonit,
    /// Custom init binary
    Custom,
    /// No init (run directly as PID 1)
    None,
}

/// Where catatonit is installed: Fedora's package puts it in a directory
/// of its own (`/usr/libexec/catatonit/catatonit`), podman links it in
/// its libexec, others in a bin directory or as `/usr/libexec/catatonit`.
const CATATONIT: [&str; 5] = [
    "/usr/libexec/podman/catatonit",
    "/usr/libexec/catatonit/catatonit",
    "/usr/libexec/catatonit",
    "/usr/bin/catatonit",
    "/usr/local/bin/catatonit",
];

/// The first of `paths` that is a file (links followed): a directory of
/// the same name is no binary.
fn first_file(paths: &[&str]) -> Option<PathBuf> {
    paths
        .iter()
        .map(PathBuf::from)
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file()))
}

impl Default for InitSystem {
    fn default() -> Self {
        if Path::new("/usr/bin/tini").exists() || Path::new("/usr/local/bin/tini").exists() {
            Self::Tini
        } else if Path::new("/usr/bin/dumb-init").exists()
            || Path::new("/usr/local/bin/dumb-init").exists()
        {
            Self::DumbInit
        } else if first_file(&CATATONIT).is_some() {
            Self::Catatonit
        } else {
            Self::None
        }
    }
}

impl InitSystem {
    /// Get the path to the init binary
    pub fn path(&self) -> Option<PathBuf> {
        match self {
            Self::Tini => {
                for path in &["/usr/bin/tini", "/usr/local/bin/tini", "/sbin/tini"] {
                    if Path::new(path).exists() {
                        return Some(PathBuf::from(path));
                    }
                }
                None
            }
            Self::DumbInit => {
                for path in &["/usr/bin/dumb-init", "/usr/local/bin/dumb-init"] {
                    if Path::new(path).exists() {
                        return Some(PathBuf::from(path));
                    }
                }
                None
            }
            Self::Catatonit => first_file(&CATATONIT),
            Self::Custom | Self::None => None,
        }
    }
}

/// Configuration for init process
#[derive(Clone, Debug)]
pub struct InitConfig {
    /// Init system to use
    pub system: InitSystem,
    /// Custom init binary path (if system is Custom)
    pub custom_path: Option<PathBuf>,
    /// Additional arguments for init
    pub args: Vec<String>,
    /// Enable signal forwarding
    pub forward_signals: bool,
    /// Verbose logging from init
    pub verbose: bool,
}

impl Default for InitConfig {
    fn default() -> Self {
        Self {
            system: InitSystem::default(),
            custom_path: None,
            args: Vec::new(),
            forward_signals: true,
            verbose: false,
        }
    }
}

impl InitConfig {
    /// Check if init is enabled
    pub fn is_enabled(&self) -> bool {
        self.system != InitSystem::None
    }

    /// Get the init binary path
    pub fn init_path(&self) -> Option<PathBuf> {
        match &self.system {
            InitSystem::Custom => self.custom_path.clone(),
            InitSystem::None => None,
            _ => self.system.path(),
        }
    }
}

/// Init process manager
pub struct InitManager {
    config: InitConfig,
}

impl InitManager {
    pub fn new(config: InitConfig) -> Self {
        Self { config }
    }

    /// Build command line arguments for init
    pub fn build_args(&self, container_cmd: &[String]) -> Vec<String> {
        let mut args = Vec::new();

        match self.config.system {
            InitSystem::Tini => {
                if self.config.verbose {
                    args.push("-v".to_string());
                }
                if self.config.forward_signals {
                    args.push("-g".to_string()); // Forward signals to process group
                }
                args.push("--".to_string());
            }
            InitSystem::DumbInit => {
                if self.config.verbose {
                    args.push("-v".to_string());
                }
                args.push("--".to_string());
            }
            InitSystem::Catatonit => {
                // as podman runs it: `-P` would be its pause mode, which ignores the
                // command
                args.push("--".to_string());
            }
            InitSystem::Custom => {
                args.extend(self.config.args.clone());
            }
            InitSystem::None => {
                return container_cmd.to_vec();
            }
        }

        args.extend(container_cmd.iter().cloned());

        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_config_default() {
        let config = InitConfig::default();
        assert!(config.forward_signals);
    }

    #[test]
    fn test_build_args_tini() {
        let config = InitConfig {
            system: InitSystem::Tini,
            ..Default::default()
        };
        let manager = InitManager::new(config);

        let args =
            manager.build_args(&["sh".to_string(), "-c".to_string(), "echo hello".to_string()]);

        // (tini as the init of the container reaps what is left by itself:
        // `-s` is for a tini that is not process 1)
        assert_eq!(args, ["-g", "--", "sh", "-c", "echo hello"]);
    }

    #[test]
    fn test_build_args_none() {
        let config = InitConfig {
            system: InitSystem::None,
            ..Default::default()
        };
        let manager = InitManager::new(config);

        let cmd = vec!["sh".to_string(), "-c".to_string(), "echo hello".to_string()];
        let args = manager.build_args(&cmd);

        assert_eq!(args, cmd);
    }

    #[test]
    fn a_directory_is_not_the_binary() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("catatonit");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("catatonit"), "").unwrap();
        let as_dir = dir.to_str().unwrap();
        let inside = dir.join("catatonit");
        assert_eq!(
            first_file(&[as_dir, inside.to_str().unwrap()]),
            Some(inside.clone())
        );
        assert_eq!(first_file(&[as_dir]), None);
    }
}
