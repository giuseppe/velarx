// SPDX-License-Identifier: Apache-2.0
//! The `[containers]` section: defaults for the life of the containers.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A size with an optional suffix: `4096`, `10k`, `10m`, `1g` (also `kb`,
/// `mb`, `gb`, `kib`, `mib`, `gib`; powers of 1024).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let digits = s
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b'.')
        .count();
    let mult: u64 = match s[digits..].trim() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        _ => return None,
    };
    let num = &s[..digits];
    if num.contains('.') {
        // a fraction, as podman's (go-units) take it: 1.5m
        let f: f64 = num
            .parse()
            .ok()
            .filter(|f: &f64| f.is_finite() && *f >= 0.0)?;
        let v = f * mult as f64;
        return (v < u64::MAX as f64).then_some(v as u64);
    }
    num.parse::<u64>().ok()?.checked_mul(mult)
}

/// The size of the log option `max-size` as podman reads it (go-units
/// `FromHumanSize`): a number, decimals allowed, and an optional unit
/// (`k`, `m`, `g`, `t`, `p`, with an optional `i` and `b`) in powers of 1000.
pub fn log_opt_size(v: &str) -> Option<u64> {
    let t = v.trim().to_ascii_lowercase();
    let digits = t
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(digits);
    if num.is_empty() || num.starts_with('.') || num.ends_with('.') || num.matches('.').count() > 1
    {
        return None;
    }
    let unit = unit.strip_prefix(' ').unwrap_or(unit);
    let unit = unit.strip_suffix('b').unwrap_or(unit);
    let unit = unit.strip_suffix('i').unwrap_or(unit);
    let power = match unit {
        "" => 0,
        "k" => 1,
        "m" => 2,
        "g" => 3,
        "t" => 4,
        "p" => 5,
        _ => return None,
    };
    let bytes = num.parse::<f64>().ok()? * 1000f64.powi(power);
    (bytes.is_finite() && bytes < u64::MAX as f64).then_some(bytes as u64)
}

fn default_image_signature() -> String {
    "policy".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainersConfig {
    /// The log driver of containers that do not choose one: `k8s-file`,
    /// `journald`, `none` or `passthrough` (empty: `journald` when the host
    /// runs systemd with a journal the user can read, else `k8s-file`, as
    /// podman's)
    #[serde(default)]
    pub log_driver: String,
    /// Rotate the log of a container when it grows past this (0: never)
    #[serde(default = "default_zero")]
    pub log_max_size: String,
    /// Log files kept for a container, the current one included
    #[serde(default = "default_log_max_files")]
    pub log_max_files: u32,
    /// The most all the log files of a container may take (0: no limit)
    #[serde(default = "default_zero")]
    pub log_global_size_max: String,
    /// Compress the rotated log files (gzip; the newest stays plain)
    #[serde(default)]
    pub log_compress: bool,
    /// The directories a `--log-opt path` must be in (empty: any); the
    /// monitor opens the file below one without following symbolic links
    #[serde(default)]
    pub log_path_allowlist: Vec<std::path::PathBuf>,
    /// After a container exits, how long its monitor waits for the rest of
    /// its output, in milliseconds
    #[serde(default = "default_output_drain_ms")]
    pub output_drain_ms: u64,
    /// How long an attached client may refuse the output of a container
    /// before it is disconnected, in seconds
    #[serde(default = "default_client_stall_secs")]
    pub client_stall_secs: u64,
    /// When the logs of the containers of a pod are followed, the longest a
    /// line is held back to be put in order with the lines of the other
    /// containers, in milliseconds; a line of another container that arrives
    /// later than that comes out of order (after lines with a later time)
    #[serde(default = "default_log_follow_window_ms")]
    pub log_follow_window_ms: u64,
    /// The image of the infra containers of pods (pulled when it is
    /// missing); none: a local pause image made from the host's catatonit
    #[serde(default)]
    pub infra_image: Option<String>,
    /// What the infra container of a configured infra image runs; none:
    /// the image's entrypoint and command
    #[serde(default)]
    pub infra_command: Option<Vec<String>>,
    /// The network mode of a container that asks for none (`bridge`,
    /// `host`, `none`, `pasta`, `private`, `ns:PATH`...); empty: the
    /// default one (a bridge for root, pasta rootless)
    #[serde(default)]
    pub netns: String,
    /// No /etc/hosts is made for the containers (`--no-hosts`)
    #[serde(default)]
    pub no_hosts: bool,
    /// The file the /etc/hosts of the containers starts from (empty: the
    /// host's /etc/hosts; `none`: an empty one)
    #[serde(default)]
    pub base_hosts_file: String,
    /// The `--cgroups` mode of a container that asks for none (`run`,
    /// `create`, the infra containers of pods): `enabled`,
    /// `scope`, `unit` (enabled, the containers of the engine service are a
    /// systemd scope of their own, or below the engine's unit), `disabled`,
    /// `no-conmon` or `split`; empty: `enabled`, which is `scope` where the
    /// engine can make one.  The
    /// containers of the CRI and the RUN steps of a build do not take it
    #[serde(default)]
    pub cgroups: String,
    /// What the signature policy must say of the image of a container:
    /// `policy` (judged at create only: the signedBy and sigstoreSigned
    /// rules of policy.json must accept a signature stored with the image,
    /// and an image they do not cover runs; `reject` refuses pulls only;
    /// `--security-opt signature=check` judges the whole policy, `reject`
    /// too, at create and at every start)
    /// or `require` (checked at create and at every start: a signedBy or
    /// sigstoreSigned requirement must have accepted a signature for every
    /// name of the image)
    #[serde(default = "default_image_signature")]
    pub image_signature: String,
    /// The keys that detach from a container or an exec session with a
    /// terminal when the command names none ("": none; unset:
    /// ctrl-p,ctrl-q)
    #[serde(default)]
    pub detach_keys: Option<String>,
    /// The directories of the OCI hooks (`--hooks-dir` takes their place;
    /// empty: /usr/share/velarx/oci/hooks.d and
    /// /etc/velarx/oci/hooks.d for root, none rootless)
    #[serde(default)]
    pub hooks_dir: Vec<String>,
    /// The directories of the CDI spec files, the later ones with priority
    /// (empty: /etc/cdi and /var/run/cdi)
    #[serde(default)]
    pub cdi_spec_dirs: Vec<String>,
    /// Whether the runtime gives each container a session keyring of its
    /// own (podman's `keyring`); false starts the containers with
    /// `--no-new-keyring`, and they share the session keyring of their
    /// monitor.  A user is capped by the kernel on the keys it owns
    /// (`kernel.keys.maxkeys`, `maxbytes`): about 190 containers rootless
    #[serde(default = "default_true")]
    pub keyring: bool,
    /// The pids limit of a container that asks for none (podman's
    /// `pids_limit`, 2048); 0 or less: no limit.  Not applied to a
    /// container that has no cgroup of its own (`--cgroups=disabled`)
    #[serde(default = "default_pids_limit")]
    pub pids_limit: i64,
}

/// The values of `[containers] cgroups` (podman's `--cgroups`, and `scope`:
/// a systemd scope per container of the engine service; `split`, its default,
/// puts them next to the engine in its delegated cgroup).
pub const CGROUPS_MODES: &[&str] = &["enabled", "scope", "disabled", "no-conmon", "split"];

fn default_true() -> bool {
    true
}

fn default_pids_limit() -> i64 {
    2048
}

fn default_zero() -> String {
    "0".to_string()
}

fn default_log_max_files() -> u32 {
    1
}

fn default_output_drain_ms() -> u64 {
    1000
}

fn default_log_follow_window_ms() -> u64 {
    100
}

fn default_client_stall_secs() -> u64 {
    30
}

/// Whether the host runs systemd and the journal has a directory of a
/// machine that the user can list: what podman's default log driver and
/// events logger look at.
fn journal_readable() -> bool {
    static READABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *READABLE.get_or_init(|| {
        if !Path::new("/run/systemd/system").is_dir() {
            return false;
        }
        ["/run/log/journal", "/var/log/journal"].iter().any(|root| {
            std::fs::read_dir(root).is_ok_and(|dirs| {
                // (a directory itself, not a link to one, as Go's DirEntry)
                dirs.flatten().any(|d| {
                    d.file_type().is_ok_and(|t| t.is_dir()) && std::fs::read_dir(d.path()).is_ok()
                })
            })
        })
    })
}

impl ContainersConfig {
    /// The log driver of a container that did not choose one: `log_driver`,
    /// else `journald` when the journal is readable, else `k8s-file`.
    pub fn effective_log_driver(&self) -> &str {
        match self.log_driver.as_str() {
            "" if journal_readable() => "journald",
            "" => "k8s-file",
            d => d,
        }
    }
}

impl Default for ContainersConfig {
    fn default() -> Self {
        Self {
            log_driver: String::new(),
            log_max_size: default_zero(),
            log_max_files: default_log_max_files(),
            log_global_size_max: default_zero(),
            log_compress: false,
            log_path_allowlist: Vec::new(),
            output_drain_ms: default_output_drain_ms(),
            client_stall_secs: default_client_stall_secs(),
            log_follow_window_ms: default_log_follow_window_ms(),
            infra_image: None,
            infra_command: None,
            netns: String::new(),
            no_hosts: false,
            base_hosts_file: String::new(),
            cgroups: String::new(),
            image_signature: default_image_signature(),
            detach_keys: None,
            hooks_dir: Vec::new(),
            cdi_spec_dirs: Vec::new(),
            keyring: true,
            pids_limit: default_pids_limit(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_size_of_a_log_option_is_in_powers_of_1000() {
        assert_eq!(log_opt_size("7.069m"), Some(7_069_000));
        assert_eq!(log_opt_size("10"), Some(10));
        assert_eq!(log_opt_size("1 KB"), Some(1000));
        assert_eq!(log_opt_size("2gib"), Some(2_000_000_000));
        assert_eq!(log_opt_size("1.2.3m"), None);
        assert_eq!(log_opt_size("5x"), None);
        assert_eq!(log_opt_size(""), None);
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("10k"), Some(10 * 1024));
        assert_eq!(parse_size("10KB"), Some(10 * 1024));
        assert_eq!(parse_size(" 2m "), Some(2 << 20));
        assert_eq!(parse_size("1g"), Some(1 << 30));
        assert_eq!(parse_size("1.5m"), Some(3 << 19));
        assert_eq!(parse_size("1.085m"), Some(1_137_704));
        assert_eq!(parse_size("1.2.3m"), None);
        assert_eq!(parse_size(".m"), None);
        assert_eq!(parse_size("0"), Some(0));
        for bad in [
            "",
            "m",
            "1x",
            "-1",
            "99999999999999999999",
            "18446744073709551615g",
        ] {
            assert_eq!(parse_size(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_section_has_defaults() {
        let c: ContainersConfig = toml::from_str("").unwrap();
        assert_eq!(c.log_driver, "");
        assert!(matches!(c.effective_log_driver(), "journald" | "k8s-file"));
        let c: ContainersConfig = toml::from_str("log_driver = \"none\"").unwrap();
        assert_eq!(c.effective_log_driver(), "none");
        let c: ContainersConfig = toml::from_str("").unwrap();
        assert_eq!(c.log_max_files, 1);
        let c: ContainersConfig =
            toml::from_str("log_max_size = \"10m\"\nlog_max_files = 3").unwrap();
        assert_eq!(parse_size(&c.log_max_size), Some(10 << 20));
        assert_eq!(c.log_max_files, 3);
        assert!(!c.log_compress);
        let c: ContainersConfig = toml::from_str("log_compress = true").unwrap();
        assert!(c.log_compress);
    }

    #[test]
    fn the_keyring_is_on_unless_turned_off() {
        let c: ContainersConfig = toml::from_str("").unwrap();
        assert!(c.keyring);
        assert!(ContainersConfig::default().keyring);
        let c: ContainersConfig = toml::from_str("keyring = false").unwrap();
        assert!(!c.keyring);
        assert!(toml::from_str::<ContainersConfig>("keyring = \"no\"").is_err());
        assert!(toml::from_str::<ContainersConfig>("no_new_keyring = true").is_err());
    }

    #[test]
    fn the_pids_limit_is_podmans_unless_set() {
        let c: ContainersConfig = toml::from_str("").unwrap();
        assert_eq!(c.pids_limit, 2048);
        assert_eq!(ContainersConfig::default().pids_limit, 2048);
        let c: ContainersConfig = toml::from_str("pids_limit = 0").unwrap();
        assert_eq!(c.pids_limit, 0);
    }
}
