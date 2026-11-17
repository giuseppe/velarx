// SPDX-License-Identifier: Apache-2.0
//! AppArmor profiles of containers, as podman sets them.
//!
//! When AppArmor is enabled a confined container runs with the default
//! profile `velarx-default` (the profile of containers/common, generated
//! and loaded with `apparmor_parser -Kr` by a root daemon the first time),
//! or with `--security-opt apparmor=PROFILE`, which must be loaded.
//! `apparmor=unconfined` and `--privileged` run without a profile.  Without
//! AppArmor the default is nothing and a named profile is an error.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

pub const DEFAULT_PROFILE: &str = "velarx-default";
const ENABLED_FILE: &str = "/sys/module/apparmor/parameters/enabled";
const PROFILES_FILE: &str = "/sys/kernel/security/apparmor/profiles";

pub fn enabled() -> bool {
    std::fs::read(ENABLED_FILE).is_ok_and(|c| c.first() == Some(&b'Y'))
}

// The text of the profile, apparmor-profile.txt, is that of containers-common
// (Apache-2.0, NOTICE; REUSE.toml annotates it).
const PROFILE: &str = include_str!("apparmor-profile.txt");

/// The default profile named `name`; `daemon` is the profile of the
/// engine.
pub fn generate_default(name: &str, daemon: &str) -> String {
    let daemon = if daemon.is_empty() {
        "unconfined"
    } else {
        daemon
    };
    PROFILE.replace("@NAME@", name).replace("@DAEMON@", daemon)
}

/// Whether the profiles file lists `name` (`name (enforce)`).
pub fn profile_listed(profiles: &str, name: &str) -> bool {
    profiles
        .lines()
        .any(|l| l.strip_prefix(name).is_some_and(|r| r.starts_with(" (")))
}

/// The profile for `--security-opt apparmor=VALUE` (`None`: the default
/// when confined); `Ok(None)` is no profile.
pub fn select(
    value: Option<&str>,
    enabled: bool,
    privileged: bool,
    loaded: Option<&str>,
) -> Result<Option<String>, String> {
    let value = match value {
        None if privileged => return Ok(None),
        None => "runtime/default",
        Some(v) => v,
    };
    match value {
        "" => Err("empty AppArmor profile".into()),
        "unconfined" => Ok(None),
        "runtime/default" | "default" => Ok(enabled.then(|| DEFAULT_PROFILE.to_string())),
        v if v.contains(['/', ' ', '\n']) => Err(format!("invalid AppArmor profile name `{v}`")),
        v if !enabled => Err(format!(
            "the AppArmor profile `{v}` needs AppArmor, which is not enabled"
        )),
        v if loaded.is_some_and(|l| !profile_listed(l, v)) => {
            Err(format!("the AppArmor profile `{v}` is not loaded"))
        }
        v => Ok(Some(v.to_string())),
    }
}

fn run_parser(args: &[&str], input: Option<&str>) -> Result<String, String> {
    let mut child = Command::new("apparmor_parser")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("apparmor_parser: {e}"))?;
    if let (Some(mut stdin), Some(text)) = (child.stdin.take(), input) {
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| format!("apparmor_parser: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("apparmor_parser: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    match out.status.success() {
        true => Ok(text),
        false => Err(format!("apparmor_parser failed: {text}")),
    }
}

/// AppArmor applies: it is enabled and the engine is root of the host (a
/// rootless engine cannot load profiles, podman leaves AppArmor out).
pub fn usable() -> Result<bool, velarx_base::ids::IdsError> {
    Ok(enabled()
        && rustix::process::geteuid().is_root()
        && !crate::userns::rootless::in_user_namespace()?)
}

/// Load the default profile when it is not; the kernel forgets the
/// profiles at a reboot, so this runs when the daemon starts and before a
/// container that uses it starts.
pub fn ensure_default_loaded() -> Result<(), String> {
    if !usable().map_err(|e| e.to_string())? {
        return Ok(());
    }
    let loaded = std::fs::read_to_string(PROFILES_FILE).unwrap_or_default();
    if profile_listed(&loaded, DEFAULT_PROFILE) {
        return Ok(());
    }
    let mut current = String::new();
    let _ = std::fs::File::open("/proc/self/attr/current")
        .and_then(|mut f| f.read_to_string(&mut current));
    let daemon = current.split([' ', '\n']).next().unwrap_or("");
    run_parser(&["-Kr"], Some(&generate_default(DEFAULT_PROFILE, daemon))).map(|_| ())
}

/// The profile of a container (none without AppArmor, or rootless); the
/// default profile is loaded when it is not.
pub fn resolve(value: Option<&str>, privileged: bool) -> Result<Option<String>, String> {
    if !usable().map_err(|e| e.to_string())? {
        if let Some(v) =
            value.filter(|v| !matches!(*v, "unconfined" | "default" | "runtime/default"))
        {
            if enabled() {
                tracing::warn!("the AppArmor profile `{v}` is ignored: the engine is rootless");
            } else {
                return Err(format!(
                    "the AppArmor profile `{v}` needs AppArmor, which is not enabled"
                ));
            }
        }
        return Ok(None);
    }
    let loaded = std::fs::read_to_string(PROFILES_FILE).ok();
    let profile = select(value, true, privileged, loaded.as_deref())?;
    if profile.as_deref() == Some(DEFAULT_PROFILE) {
        ensure_default_loaded()?;
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile() {
        let p = generate_default("p", "");
        assert!(p.contains("profile p flags=(attach_disconnected,mediate_deleted) {"));
        assert!(p.contains("signal (receive) peer=unconfined,\n  # runc"));
        assert!(p.contains("signal (send,receive) peer=p,"));
        assert!(p.contains("ptrace (trace,read,tracedby,readby) peer=p,"));
        assert!(p.ends_with("}\n"));
        assert!(!p.contains("@NAME@") && !p.contains("@DAEMON@"));
        assert!(generate_default("p", "d").contains("peer=d,"));
    }

    #[test]
    fn listing() {
        let l = "velarx-default (enforce)\nother (complain)\n";
        assert!(profile_listed(l, "velarx-default") && profile_listed(l, "other"));
        assert!(!profile_listed(l, "velarx") && !profile_listed(l, "oth"));
    }

    #[test]
    fn without_apparmor() {
        if enabled() {
            return;
        }
        assert_eq!(resolve(None, false), Ok(None));
        assert_eq!(resolve(Some("unconfined"), false), Ok(None));
        assert!(resolve(Some("mine"), false).is_err());
        assert_eq!(ensure_default_loaded(), Ok(()));
    }

    #[test]
    fn selection() {
        let l = Some("mine (enforce)\n");
        assert_eq!(
            select(None, true, false, l),
            Ok(Some(DEFAULT_PROFILE.into()))
        );
        assert_eq!(select(None, false, false, l), Ok(None));
        assert_eq!(select(None, true, true, l), Ok(None));
        assert_eq!(select(Some("unconfined"), true, false, l), Ok(None));
        assert_eq!(select(Some("mine"), true, true, l), Ok(Some("mine".into())));
        assert!(select(Some("theirs"), true, false, l).is_err());
        assert!(select(Some("mine"), false, false, l).is_err());
        assert!(select(Some("a/b"), true, false, l).is_err());
        assert!(select(Some(""), true, false, l).is_err());
    }
}
