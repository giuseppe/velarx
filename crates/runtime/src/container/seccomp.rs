// SPDX-License-Identifier: Apache-2.0
//! Seccomp filters of containers.
//!
//! Profiles are in the Docker/podman format: `defaultAction`,
//! `defaultErrnoRet`, `archMap` (or `architectures`), `flags`,
//! `listenerPath`, `listenerMetadata` and `syscalls` whose rules may have
//! `includes`/`excludes` by architecture, capability and kernel version.  A
//! profile is converted to the OCI `linux.seccomp` of a container: only the
//! native architecture (and its sub-architectures) and the rules that apply
//! to it, to the bounding capabilities of the container and to the running
//! kernel are kept.
//!
//! The default profile (`seccomp.json`) is the allow-list of
//! containers-common (Apache-2.0), the one podman uses.
//!
//! `--security-opt seccomp=`: empty for the default, `unconfined`, a JSON
//! profile or the path of one.  A profile that cannot be read or converted
//! fails the create.

use oci_spec::runtime::LinuxSeccomp;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

/// The default profile.
pub const DEFAULT_PROFILE: &str = include_str!("seccomp.json");

/// The largest profile that is read.
pub const MAX_PROFILE_SIZE: u64 = 4 << 20;

#[derive(Error, Debug)]
pub enum SeccompError {
    #[error("cannot read the seccomp profile `{0}`: {1}")]
    Read(String, std::io::Error),
    #[error("the seccomp profile `{0}` is larger than 4 MiB")]
    TooLarge(String),
    #[error("cannot parse the seccomp profile: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid seccomp profile: {0}")]
    InvalidProfile(String),
}

pub type SeccompResult<T> = Result<T, SeccompError>;

/// The seccomp filter asked for a container.
#[derive(Debug, Clone, PartialEq)]
pub enum SeccompMode {
    /// The default profile
    Default,
    /// No filter
    Unconfined,
    /// A profile (its JSON)
    Custom(String),
}

impl SeccompMode {
    /// `--security-opt seccomp=VALUE`: empty, `unconfined`, a JSON profile or
    /// the path of one (read now).
    pub fn from_security_opt(value: &str) -> SeccompResult<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(Self::Default);
        }
        if value.eq_ignore_ascii_case("unconfined") {
            return Ok(Self::Unconfined);
        }
        let json = if value.starts_with('{') {
            value.to_string()
        } else {
            read_profile(Path::new(value))?
        };
        // fail now on a profile that does not parse
        profile_object(&serde_json::from_str(&json)?)?;
        Ok(Self::Custom(json))
    }

    /// The filter for a process whose bounding set is `caps` (`CAP_NAME`s);
    /// none when unconfined.
    pub fn to_oci(&self, caps: &HashSet<String>) -> SeccompResult<Option<LinuxSeccomp>> {
        match self {
            Self::Unconfined => Ok(None),
            Self::Default => convert(DEFAULT_PROFILE, caps).map(Some),
            Self::Custom(json) => convert(json, caps).map(Some),
        }
    }
}

/// Read a profile file, at most [`MAX_PROFILE_SIZE`] bytes.
pub fn read_profile(path: &Path) -> SeccompResult<String> {
    let name = path.display().to_string();
    let data = read_regular_file(path, MAX_PROFILE_SIZE).map_err(|e| match e.kind() {
        std::io::ErrorKind::FileTooLarge => SeccompError::TooLarge(name.clone()),
        _ => SeccompError::Read(name.clone(), e),
    })?;
    String::from_utf8(data).map_err(|e| SeccompError::InvalidProfile(e.to_string()))
}

/// The content of the regular file `path`, at most `max` bytes: no link
/// is followed in its last component, a fifo or a device does not block or
/// get read.
pub fn read_regular_file(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    use rustix::fs::{fstat, FileType, Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let st = fstat(&fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut data = Vec::new();
    std::fs::File::from(fd)
        .take(max + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("larger than {max} bytes"),
        ));
    }
    Ok(data)
}

/// The architecture of the engine: its name in `includes`/`excludes` and
/// its libseccomp name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeArch {
    pub name: &'static str,
    pub scmp: &'static str,
}

pub fn native_arch() -> Option<NativeArch> {
    let (name, scmp) = match std::env::consts::ARCH {
        "x86_64" => ("amd64", "SCMP_ARCH_X86_64"),
        "aarch64" => ("arm64", "SCMP_ARCH_AARCH64"),
        "s390x" => ("s390x", "SCMP_ARCH_S390X"),
        "powerpc64" if cfg!(target_endian = "little") => ("ppc64le", "SCMP_ARCH_PPC64LE"),
        "riscv64" => ("riscv64", "SCMP_ARCH_RISCV64"),
        "loongarch64" => ("loong64", "SCMP_ARCH_LOONGARCH64"),
        "x86" => ("x86", "SCMP_ARCH_X86"),
        "arm" => ("arm", "SCMP_ARCH_ARM"),
        _ => return None,
    };
    Some(NativeArch { name, scmp })
}

/// `major.minor` of the running kernel.
pub fn kernel_version() -> Option<(u32, u32)> {
    parse_version(
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()?
            .trim(),
    )
}

fn parse_version(s: &str) -> Option<(u32, u32)> {
    let mut it = s.split(['.', '-']);
    let major = it.next()?.parse().ok()?;
    let minor = it
        .next()
        .map(|m| {
            m.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|m| m.parse().ok())
        .unwrap_or(0);
    Some((major, minor))
}

/// Convert `profile` for the native architecture and the running kernel.
pub fn convert(profile: &str, caps: &HashSet<String>) -> SeccompResult<LinuxSeccomp> {
    let v: Value = serde_json::from_str(profile)?;
    let oci = convert_for(&v, caps, native_arch(), kernel_version())?;
    serde_json::from_value(oci).map_err(|e| SeccompError::InvalidProfile(e.to_string()))
}

fn profile_object(v: &Value) -> SeccompResult<&Map<String, Value>> {
    let o = v
        .as_object()
        .ok_or_else(|| SeccompError::InvalidProfile("not a JSON object".into()))?;
    if !o.get("defaultAction").is_some_and(Value::is_string) {
        return Err(SeccompError::InvalidProfile(
            "missing `defaultAction`".into(),
        ));
    }
    Ok(o)
}

fn strings(v: Option<&Value>) -> SeccompResult<Vec<&str>> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .ok_or_else(|| SeccompError::InvalidProfile(format!("`{x}` is not a string")))
            })
            .collect(),
        Some(x) => Err(SeccompError::InvalidProfile(format!(
            "`{x}` is not an array"
        ))),
    }
}

fn at_least(have: Option<(u32, u32)>, min: &str) -> SeccompResult<bool> {
    let want = parse_version(min)
        .ok_or_else(|| SeccompError::InvalidProfile(format!("invalid minKernel `{min}`")))?;
    // an unknown kernel is assumed recent
    Ok(have.is_none_or(|h| h >= want))
}

/// Whether a rule applies to the architecture, capabilities and kernel.
fn applies(
    rule: &Map<String, Value>,
    arch: Option<NativeArch>,
    caps: &HashSet<String>,
    kernel: Option<(u32, u32)>,
) -> SeccompResult<bool> {
    let arch_in = |arches: &[&str]| arch.is_some_and(|a| arches.contains(&a.name));
    if let Some(inc) = rule.get("includes").filter(|v| !v.is_null()) {
        let inc = inc
            .as_object()
            .ok_or_else(|| SeccompError::InvalidProfile("`includes` is not an object".into()))?;
        let arches = strings(inc.get("arches"))?;
        if !arches.is_empty() && !arch_in(&arches) {
            return Ok(false);
        }
        if !strings(inc.get("caps"))?.iter().all(|c| caps.contains(*c)) {
            return Ok(false);
        }
        if let Some(min) = inc.get("minKernel").and_then(Value::as_str) {
            if !at_least(kernel, min)? {
                return Ok(false);
            }
        }
    }
    if let Some(exc) = rule.get("excludes").filter(|v| !v.is_null()) {
        let exc = exc
            .as_object()
            .ok_or_else(|| SeccompError::InvalidProfile("`excludes` is not an object".into()))?;
        if arch_in(&strings(exc.get("arches"))?) {
            return Ok(false);
        }
        if strings(exc.get("caps"))?.iter().any(|c| caps.contains(*c)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The OCI form of the Docker profile `v`.
pub fn convert_for(
    v: &Value,
    caps: &HashSet<String>,
    arch: Option<NativeArch>,
    kernel: Option<(u32, u32)>,
) -> SeccompResult<Value> {
    let p = profile_object(v)?;
    let mut out = Map::new();
    for k in [
        "defaultAction",
        "defaultErrnoRet",
        "flags",
        "listenerPath",
        "listenerMetadata",
    ] {
        if let Some(x) = p.get(k).filter(|x| !x.is_null()) {
            out.insert(k.to_string(), x.clone());
        }
    }

    let mut archs: Vec<Value> = Vec::new();
    match (p.get("archMap").filter(|x| !x.is_null()), arch) {
        (Some(Value::Array(map)), Some(native)) => {
            for entry in map {
                if entry.get("architecture").and_then(Value::as_str) != Some(native.scmp) {
                    continue;
                }
                archs.push(Value::from(native.scmp));
                for sub in strings(entry.get("subArchitectures"))? {
                    archs.push(Value::from(sub));
                }
            }
        }
        (Some(Value::Array(_)), None) => {}
        (Some(_), _) => {
            return Err(SeccompError::InvalidProfile(
                "`archMap` is not an array".into(),
            ))
        }
        (None, _) => {
            for a in strings(p.get("architectures"))? {
                archs.push(Value::from(a));
            }
        }
    }
    if !archs.is_empty() {
        out.insert("architectures".into(), Value::Array(archs));
    }

    let mut syscalls = Vec::new();
    let rules = match p.get("syscalls") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(a)) => a.as_slice(),
        Some(_) => {
            return Err(SeccompError::InvalidProfile(
                "`syscalls` is not an array".into(),
            ))
        }
    };
    for rule in rules {
        let rule = rule
            .as_object()
            .ok_or_else(|| SeccompError::InvalidProfile("a rule is not an object".into()))?;
        if !applies(rule, arch, caps, kernel)? {
            continue;
        }
        let mut names: Vec<Value> = strings(rule.get("names"))?
            .into_iter()
            .map(Value::from)
            .collect();
        match rule.get("name") {
            None | Some(Value::Null) => {}
            Some(Value::String(n)) => names.push(Value::from(n.as_str())),
            // dropped, the rule would name fewer calls than it says
            Some(_) => {
                return Err(SeccompError::InvalidProfile(
                    "`name` is not a string".into(),
                ))
            }
        }
        if names.is_empty() {
            return Err(SeccompError::InvalidProfile("a rule without names".into()));
        }
        let mut o = Map::new();
        o.insert("names".into(), Value::Array(names));
        for k in ["action", "errnoRet"] {
            if let Some(x) = rule.get(k).filter(|x| !x.is_null()) {
                o.insert(k.into(), x.clone());
            }
        }
        match rule.get("args") {
            None | Some(Value::Null) => {}
            Some(args @ Value::Array(a)) => {
                if !a.is_empty() {
                    o.insert("args".into(), args.clone());
                }
            }
            // dropped, the rule would apply to every call
            Some(_) => {
                return Err(SeccompError::InvalidProfile(
                    "`args` is not an array".into(),
                ))
            }
        }
        syscalls.push(Value::Object(o));
    }
    out.insert("syscalls".into(), Value::Array(syscalls));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{Arch, LinuxSeccompAction};

    const AMD64: Option<NativeArch> = Some(NativeArch {
        name: "amd64",
        scmp: "SCMP_ARCH_X86_64",
    });

    fn caps(v: &[&str]) -> HashSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn names(v: &Value) -> Vec<String> {
        v["syscalls"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|r| r["names"].as_array().unwrap().iter())
            .map(|n| n.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn default_profile_is_an_allow_list() {
        let v: Value = serde_json::from_str(DEFAULT_PROFILE).unwrap();
        let oci = convert_for(&v, &caps(&[]), AMD64, Some((6, 1))).unwrap();
        assert_eq!(oci["defaultAction"], "SCMP_ACT_ERRNO");
        assert_eq!(oci["defaultErrnoRet"], 38);
        assert_eq!(
            oci["architectures"],
            serde_json::json!(["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"])
        );
        let n = names(&oci);
        for allowed in ["read", "write", "openat", "clone3", "execve", "arch_prctl"] {
            assert!(n.iter().any(|x| x == allowed), "{allowed}");
        }
        // only allowed with CAP_SYS_MODULE
        let allows = |o: &Value, name: &str| {
            o["syscalls"].as_array().unwrap().iter().any(|r| {
                r["action"] == "SCMP_ACT_ALLOW"
                    && r["names"].as_array().unwrap().iter().any(|n| n == name)
            })
        };
        assert!(!allows(&oci, "init_module"));
        let m = convert_for(&v, &caps(&["CAP_SYS_MODULE"]), AMD64, Some((6, 1))).unwrap();
        assert!(allows(&m, "init_module"));
        // arm64 has no x86 only calls
        let arm = Some(NativeArch {
            name: "arm64",
            scmp: "SCMP_ARCH_AARCH64",
        });
        let a = convert_for(&v, &caps(&[]), arm, Some((6, 1))).unwrap();
        assert!(!names(&a).iter().any(|x| x == "arch_prctl"));
        assert_eq!(
            a["architectures"],
            serde_json::json!(["SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"])
        );
        // the native conversion is a valid OCI filter
        let s = convert(DEFAULT_PROFILE, &caps(&[])).unwrap();
        assert_eq!(s.default_action(), LinuxSeccompAction::ScmpActErrno);
    }

    #[test]
    fn includes_and_excludes() {
        let p = serde_json::json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "defaultErrnoRet": 1,
            "flags": ["SECCOMP_FILTER_FLAG_LOG"],
            "listenerPath": "/run/l.sock",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [
                {"names": ["a"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1, "comment": "x"},
                {"name": "b", "action": "SCMP_ACT_ERRNO", "includes": {"arches": ["arm64"]}},
                {"names": ["c"], "action": "SCMP_ACT_ERRNO", "includes": {"caps": ["CAP_BPF"]}},
                {"names": ["d"], "action": "SCMP_ACT_ERRNO", "excludes": {"caps": ["CAP_BPF"]}},
                {"names": ["e"], "action": "SCMP_ACT_ERRNO", "excludes": {"arches": ["amd64"]}},
                {"names": ["f"], "action": "SCMP_ACT_ERRNO", "includes": {"minKernel": "5.8"}},
                {"names": ["g"], "action": "SCMP_ACT_ERRNO", "args": [
                    {"index": 0, "value": 1, "valueTwo": 0, "op": "SCMP_CMP_EQ"}]},
            ]
        });
        let o = convert_for(&p, &caps(&[]), AMD64, Some((5, 4))).unwrap();
        assert_eq!(names(&o), ["a", "d", "g"]);
        assert_eq!(o["flags"], serde_json::json!(["SECCOMP_FILTER_FLAG_LOG"]));
        assert_eq!(o["listenerPath"], "/run/l.sock");
        assert_eq!(o["defaultErrnoRet"], 1);
        assert!(o["syscalls"][0].get("comment").is_none());
        let o = convert_for(&p, &caps(&["CAP_BPF"]), AMD64, Some((5, 10))).unwrap();
        assert_eq!(names(&o), ["a", "c", "f", "g"]);
        let s: LinuxSeccomp = serde_json::from_value(o).unwrap();
        assert_eq!(
            s.architectures().as_deref(),
            Some(&[Arch::ScmpArchX86_64][..])
        );
        // an unknown kernel is assumed recent
        let o = convert_for(&p, &caps(&[]), AMD64, None).unwrap();
        assert!(names(&o).contains(&"f".to_string()));
    }

    #[test]
    fn invalid_profiles() {
        for bad in [
            serde_json::json!([]),
            serde_json::json!({"syscalls": []}),
            serde_json::json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": {}}),
            serde_json::json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"action": "SCMP_ACT_ALLOW"}]}),
            serde_json::json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
                {"names": ["a"], "action": "SCMP_ACT_ALLOW", "includes": {"minKernel": "x"}}]}),
            serde_json::json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
                {"names": [1], "action": "SCMP_ACT_ALLOW"}]}),
            serde_json::json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
                {"names": ["a"], "action": "SCMP_ACT_ERRNO", "args": {"index": 0}}]}),
            serde_json::json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
                {"names": ["a"], "name": 1, "action": "SCMP_ACT_ERRNO"}]}),
        ] {
            assert!(convert_for(&bad, &caps(&[]), AMD64, None).is_err(), "{bad}");
        }
        // no arguments to compare: the rule is as it says
        for args in [serde_json::json!(null), serde_json::json!([])] {
            let ok = serde_json::json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
                {"names": ["a"], "action": "SCMP_ACT_ERRNO", "args": args}]});
            let v = convert_for(&ok, &caps(&[]), AMD64, None).unwrap();
            assert!(v["syscalls"][0].get("args").is_none(), "{ok}");
        }
        // what the OCI types refuse
        assert!(convert(r#"{"defaultAction": "SCMP_ACT_NOPE"}"#, &caps(&[])).is_err());
        assert!(convert(
            r#"{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["a"], "action": "SCMP_ACT_ERRNO", "args": [{"index": 0, "value": 1, "op": "SCMP_CMP_NOPE"}]}]}"#,
            &caps(&[])
        )
        .is_err());
        assert!(convert("{", &caps(&[])).is_err());
    }

    #[test]
    fn modes() {
        assert_eq!(
            SeccompMode::from_security_opt("").unwrap(),
            SeccompMode::Default
        );
        assert_eq!(
            SeccompMode::from_security_opt("Unconfined").unwrap(),
            SeccompMode::Unconfined
        );
        assert_eq!(SeccompMode::Unconfined.to_oci(&caps(&[])).unwrap(), None);
        let inline = r#"{"defaultAction": "SCMP_ACT_LOG"}"#;
        let m = SeccompMode::from_security_opt(inline).unwrap();
        let s = m.to_oci(&caps(&[])).unwrap().unwrap();
        assert_eq!(s.default_action(), LinuxSeccompAction::ScmpActLog);
        assert!(SeccompMode::from_security_opt("{nope").is_err());
        assert!(SeccompMode::from_security_opt("/nonexistent/profile.json").is_err());

        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p.json");
        std::fs::write(&p, inline).unwrap();
        assert_eq!(
            SeccompMode::from_security_opt(p.to_str().unwrap()).unwrap(),
            SeccompMode::Custom(inline.to_string())
        );
        // a link and a fifo are refused
        let link = d.path().join("l.json");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(SeccompMode::from_security_opt(link.to_str().unwrap()).is_err());
        let fifo = d.path().join("f.json");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        assert!(SeccompMode::from_security_opt(fifo.to_str().unwrap()).is_err());
        let big = d.path().join("big.json");
        std::fs::write(&big, vec![b' '; MAX_PROFILE_SIZE as usize + 1]).unwrap();
        assert!(matches!(
            SeccompMode::from_security_opt(big.to_str().unwrap()),
            Err(SeccompError::TooLarge(_))
        ));
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("6.1.0-13-amd64"), Some((6, 1)));
        assert_eq!(parse_version("7.2.9-200.fc44.x86_64"), Some((7, 2)));
        assert_eq!(parse_version("5.8"), Some((5, 8)));
        assert_eq!(parse_version("5"), Some((5, 0)));
        assert_eq!(parse_version("4.19rc1"), Some((4, 19)));
        assert_eq!(parse_version("x"), None);
    }
}
