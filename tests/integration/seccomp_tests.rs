// SPDX-License-Identifier: Apache-2.0
//! Seccomp profiles: the default allow-list and custom profiles, converted
//! to the OCI filter of a container.

use oci_spec::runtime::{Arch, LinuxSeccompAction, LinuxSeccompOperator};
use std::collections::HashSet;
use std::io::Write;
use velarx_runtime::container::seccomp::{
    convert, convert_for, native_arch, NativeArch, SeccompError, SeccompMode, DEFAULT_PROFILE,
};

fn caps(v: &[&str]) -> HashSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn allowed(f: &oci_spec::runtime::LinuxSeccomp) -> HashSet<String> {
    f.syscalls()
        .iter()
        .flatten()
        .filter(|r| r.action() == LinuxSeccompAction::ScmpActAllow && r.args().is_none())
        .flat_map(|r| r.names().iter().cloned())
        .collect()
}

#[test]
fn the_default_profile_denies_what_it_does_not_list() {
    let f = convert(DEFAULT_PROFILE, &caps(&[])).unwrap();
    assert_eq!(f.default_action(), LinuxSeccompAction::ScmpActErrno);
    assert_eq!(f.default_errno_ret(), Some(38));
    let a = allowed(&f);
    for name in [
        "read",
        "write",
        "openat",
        "execve",
        "exit_group",
        "futex",
        "mmap",
    ] {
        assert!(a.contains(name), "{name}");
    }
    // io_uring would let a process bypass the filter
    for name in [
        "kexec_load",
        "init_module",
        "finit_module",
        "bpf",
        "swapon",
        "acct",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
    ] {
        assert!(!a.contains(name), "{name}");
    }
    if let Some(n) = native_arch() {
        let archs = f.architectures().clone().unwrap_or_default();
        assert_eq!(
            archs.first().map(|a| a.to_string()).as_deref(),
            Some(n.scmp)
        );
    }
}

#[test]
fn capabilities_open_the_calls_they_guard() {
    let base = allowed(&convert(DEFAULT_PROFILE, &caps(&[])).unwrap());
    let module = allowed(&convert(DEFAULT_PROFILE, &caps(&["CAP_SYS_MODULE"])).unwrap());
    for name in ["init_module", "finit_module", "delete_module"] {
        assert!(!base.contains(name) && module.contains(name), "{name}");
    }
    let admin = allowed(&convert(DEFAULT_PROFILE, &caps(&["CAP_SYS_ADMIN"])).unwrap());
    assert!(admin.contains("bpf") && admin.contains("lookup_dcookie"));
    let bpf = allowed(&convert(DEFAULT_PROFILE, &caps(&["CAP_BPF"])).unwrap());
    assert!(bpf.contains("bpf") && !base.contains("bpf"));
}

#[test]
fn a_profile_for_another_architecture_is_filtered() {
    let v: serde_json::Value = serde_json::from_str(DEFAULT_PROFILE).unwrap();
    let s390 = Some(NativeArch {
        name: "s390x",
        scmp: "SCMP_ARCH_S390X",
    });
    let o = convert_for(&v, &caps(&[]), s390, Some((6, 0))).unwrap();
    assert_eq!(
        o["architectures"],
        serde_json::json!(["SCMP_ARCH_S390X", "SCMP_ARCH_S390"])
    );
    let names: Vec<&str> = o["syscalls"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|r| r["names"].as_array().unwrap())
        .filter_map(|n| n.as_str())
        .collect();
    assert!(names.contains(&"s390_pci_mmio_read"));
    assert!(!names.contains(&"arch_prctl"));
}

#[test]
fn custom_profiles() {
    let json = r#"{
        "defaultAction": "SCMP_ACT_ALLOW",
        "defaultErrnoRet": 1,
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
        "flags": ["SECCOMP_FILTER_FLAG_LOG"],
        "syscalls": [
            {"names": ["chmod"], "action": "SCMP_ACT_ERRNO", "errnoRet": 13},
            {"name": "personality", "action": "SCMP_ACT_ERRNO",
             "args": [{"index": 0, "value": 8, "valueTwo": 0, "op": "SCMP_CMP_NE"}]},
            {"names": ["kill"], "action": "SCMP_ACT_KILL_PROCESS", "excludes": {"caps": ["CAP_KILL"]}}
        ]
    }"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(json.as_bytes()).unwrap();
    let mode = SeccompMode::from_security_opt(file.path().to_str().unwrap()).unwrap();
    assert_eq!(mode, SeccompMode::Custom(json.to_string()));
    let f = mode.to_oci(&caps(&["CAP_KILL"])).unwrap().unwrap();
    assert_eq!(f.default_action(), LinuxSeccompAction::ScmpActAllow);
    assert_eq!(f.default_errno_ret(), Some(1));
    assert_eq!(
        f.architectures().clone().unwrap(),
        [Arch::ScmpArchX86_64, Arch::ScmpArchAarch64]
    );
    assert_eq!(f.flags().as_ref().map(Vec::len), Some(1));
    let rules = f.syscalls().clone().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].errno_ret(), Some(13));
    assert_eq!(rules[1].names(), &["personality"]);
    let arg = &rules[1].args().clone().unwrap()[0];
    assert_eq!(
        (arg.index(), arg.value(), arg.op()),
        (0, 8, LinuxSeccompOperator::ScmpCmpNe)
    );
    // without CAP_KILL the rule is kept
    let f = mode.to_oci(&caps(&[])).unwrap().unwrap();
    assert_eq!(f.syscalls().as_ref().map(Vec::len), Some(3));
}

#[test]
fn bad_profiles_fail() {
    assert!(matches!(
        SeccompMode::from_security_opt("/nonexistent/profile.json"),
        Err(SeccompError::Read(..))
    ));
    assert!(SeccompMode::from_security_opt("{\"syscalls\": []}").is_err());
    assert!(SeccompMode::from_security_opt("{not json").is_err());
    let m = SeccompMode::from_security_opt(r#"{"defaultAction": "SCMP_ACT_WHAT"}"#).unwrap();
    assert!(m.to_oci(&caps(&[])).is_err());
}

#[test]
fn unconfined_and_default() {
    for v in ["unconfined", "UNCONFINED", " unconfined "] {
        assert_eq!(
            SeccompMode::from_security_opt(v).unwrap(),
            SeccompMode::Unconfined
        );
    }
    assert_eq!(
        SeccompMode::from_security_opt("").unwrap(),
        SeccompMode::Default
    );
    assert!(SeccompMode::Unconfined
        .to_oci(&caps(&[]))
        .unwrap()
        .is_none());
    assert!(SeccompMode::Default.to_oci(&caps(&[])).unwrap().is_some());
}
