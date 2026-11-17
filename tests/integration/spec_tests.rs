// SPDX-License-Identifier: Apache-2.0
//! The OCI spec that `generate_spec` writes for a container configuration.

use std::path::Path;
use velarx_runtime::container::userspec::{resolve_user_in_root, ResolvedUser};
use velarx_runtime::container::{ContainerConfig, OciRuntime};
use velarx_wire::request::NetworkMode;

const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\n";
const GROUP: &str = "root:x:0:root\nbin:x:1:root,bin\nwheel:x:10:root\naudio:x:18:\n";

fn rootfs() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("etc")).unwrap();
    std::fs::write(d.path().join("etc/passwd"), PASSWD).unwrap();
    std::fs::write(d.path().join("etc/group"), GROUP).unwrap();
    d
}

fn spec(config: &ContainerConfig, root: &Path) -> serde_json::Value {
    let state = tempfile::tempdir().unwrap();
    let rt = OciRuntime::new(state.path().to_path_buf()).unwrap();
    let spec = rt.generate_spec(config, root).unwrap();
    serde_json::to_value(&spec).unwrap()
}

fn config(user: &str) -> ContainerConfig {
    ContainerConfig {
        id: "c1".into(),
        user: user.into(),
        ..Default::default()
    }
}

fn env<'a>(s: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    s["process"]["env"]
        .as_array()?
        .iter()
        .filter_map(|e| e.as_str())
        .find_map(|e| e.strip_prefix(key)?.strip_prefix('='))
}

#[test]
fn the_user_is_resolved_in_the_root_file_system() {
    let root = rootfs();
    let s = spec(&config("bin"), root.path());
    let u = &s["process"]["user"];
    assert_eq!((u["uid"].as_u64(), u["gid"].as_u64()), (Some(1), Some(1)));
    assert_eq!(u["additionalGids"], serde_json::json!([1]));
    assert_eq!(u["umask"], 0o022);
    assert_eq!(env(&s, "HOME"), Some("/bin"));

    let mut c = config("");
    c.group_add = vec!["audio".into(), "4242".into()];
    c.umask = Some(0o077);
    let s = spec(&c, root.path());
    let u = &s["process"]["user"];
    assert_eq!(u["uid"], 0);
    assert_eq!(u["additionalGids"], serde_json::json!([0, 18, 4242, 1, 10]));
    assert_eq!(u["umask"], 0o077);
    assert_eq!(env(&s, "HOME"), Some("/root"));
}

#[test]
fn a_resolved_user_is_used_as_is() {
    let root = rootfs();
    let mut c = config("nosuch");
    c.working_dir = "/srv".into();
    c.process_user = Some(ResolvedUser {
        uid: 7,
        gid: 8,
        additional_gids: vec![8, 9],
        home: None,
        keep_groups: true,
    });
    let s = spec(&c, root.path());
    assert_eq!(s["process"]["user"]["uid"], 7);
    assert_eq!(
        s["process"]["user"]["additionalGids"],
        serde_json::json!([8, 9])
    );
    // the home of a user that the image lacks is the working directory
    assert_eq!(env(&s, "HOME"), Some("/srv"));
    assert_eq!(s["annotations"]["run.oci.keep_original_groups"], "1");
}

#[test]
fn an_explicit_home_is_kept() {
    let root = rootfs();
    let mut c = config("bin");
    c.env = vec!["HOME=/h".into()];
    assert_eq!(env(&spec(&c, root.path()), "HOME"), Some("/h"));
}

#[test]
fn an_unknown_user_fails_the_spec() {
    let root = rootfs();
    let state = tempfile::tempdir().unwrap();
    let rt = OciRuntime::new(state.path().to_path_buf()).unwrap();
    let err = rt
        .generate_spec(&config("nosuch"), root.path())
        .unwrap_err();
    assert!(err.to_string().contains("nosuch"), "{err}");
}

#[test]
fn the_files_of_the_host_are_not_read() {
    let root = rootfs();
    std::fs::remove_file(root.path().join("etc/passwd")).unwrap();
    // absolute and relative links that would reach the passwd of the host
    std::os::unix::fs::symlink(
        "/../../../../etc/shadow/../passwd",
        root.path().join("etc/passwd"),
    )
    .unwrap();
    // root exists on the host, not in this root file system
    assert!(resolve_user_in_root(root.path(), "root", &[], false).is_err());
    assert_eq!(
        resolve_user_in_root(root.path(), "0", &[], false)
            .unwrap()
            .uid,
        0
    );
}

#[test]
fn security_defaults() {
    use velarx_runtime::container::{default_masked_paths, default_readonly_paths};
    let root = rootfs();
    let s = spec(&config(""), root.path());
    assert_eq!(s["process"]["noNewPrivileges"], false);
    let caps = &s["process"]["capabilities"];
    assert_eq!(caps["bounding"].as_array().unwrap().len(), 11);
    assert_eq!(caps["ambient"], serde_json::json!([]));
    assert_eq!(caps["inheritable"], serde_json::json!([]));
    assert_eq!(s["linux"]["seccomp"]["defaultAction"], "SCMP_ACT_ERRNO");
    assert_eq!(
        s["linux"]["maskedPaths"],
        serde_json::to_value(default_masked_paths()).unwrap()
    );
    assert_eq!(
        s["linux"]["readonlyPaths"],
        serde_json::to_value(default_readonly_paths()).unwrap()
    );
    assert_eq!(s["linux"]["sysctl"]["net.ipv4.ping_group_range"], "0 0");
    let sys = s["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["destination"] == "/sys")
        .unwrap();
    assert!(sys["options"].as_array().unwrap().contains(&"ro".into()));

    // a user gets no capabilities, no-new-privileges when asked
    let mut c = config("bin");
    c.security_opt.no_new_privileges = true;
    let s = spec(&c, root.path());
    assert_eq!(
        s["process"]["capabilities"]["effective"],
        serde_json::json!([])
    );
    assert_eq!(s["process"]["noNewPrivileges"], true);

    // host network: no net sysctl
    let mut c = config("");
    c.network_mode = NetworkMode::Host;
    assert!(spec(&c, root.path())["linux"]["sysctl"]
        .get("net.ipv4.ping_group_range")
        .is_none());
}

#[test]
fn privileged_and_unmasked() {
    let root = rootfs();
    let mut c = config("");
    c.privileged = true;
    let s = spec(&c, root.path());
    assert!(s["linux"].get("seccomp").is_none());
    assert!(s["linux"]
        .get("maskedPaths")
        .is_none_or(|m| m == &serde_json::json!([])));
    let sys = s["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["destination"] == "/sys")
        .unwrap();
    assert!(!sys["options"].as_array().unwrap().contains(&"ro".into()));
    // an explicit profile applies to a privileged container too
    c.security_opt.seccomp = r#"{"defaultAction": "SCMP_ACT_LOG"}"#.into();
    assert_eq!(
        spec(&c, root.path())["linux"]["seccomp"]["defaultAction"],
        "SCMP_ACT_LOG"
    );

    let mut c = config("");
    c.security_opt.mask_paths = vec!["/proc/version".into()];
    c.security_opt.unmask_paths = vec!["/proc/kcore".into(), "/proc/sys".into()];
    c.security_opt.proc_opts = Some("hidepid=2".into());
    let s = spec(&c, root.path());
    let masked: Vec<&str> = s["linux"]["maskedPaths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(masked.contains(&"/proc/version") && !masked.contains(&"/proc/kcore"));
    assert!(!s["linux"]["readonlyPaths"]
        .as_array()
        .unwrap()
        .contains(&"/proc/sys".into()));
    let proc = s["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["destination"] == "/proc")
        .unwrap();
    assert!(proc["options"]
        .as_array()
        .unwrap()
        .contains(&"hidepid=2".into()));

    c.security_opt.unmask_paths = vec!["ALL".into()];
    let s = spec(&c, root.path());
    assert_eq!(
        s["linux"]["maskedPaths"],
        serde_json::json!(["/proc/version"])
    );
    assert!(s["linux"]
        .get("readonlyPaths")
        .is_none_or(|m| m == &serde_json::json!([])));

    // `unmask=ALL` with lists: exactly those lists (what the CRI's masked and
    // read-only paths are), and the read-only paths asked for add to the
    // defaults without it
    c.security_opt.readonly_paths = vec!["/tmp".into()];
    let s = spec(&c, root.path());
    assert_eq!(s["linux"]["readonlyPaths"], serde_json::json!(["/tmp"]));
    c.security_opt.unmask_paths.clear();
    let s = spec(&c, root.path());
    let readonly: Vec<&str> = s["linux"]["readonlyPaths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(readonly.contains(&"/tmp") && readonly.contains(&"/proc/sys"));
    // `unmask=` of a path takes out the default, not one asked for (as
    // for the masked paths)
    c.security_opt.unmask_paths = vec!["/proc/sys".into(), "/tmp".into()];
    let s = spec(&c, root.path());
    let readonly: Vec<&str> = s["linux"]["readonlyPaths"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(readonly.contains(&"/tmp") && !readonly.contains(&"/proc/sys"));
}

#[test]
fn invalid_security_settings_fail() {
    let root = rootfs();
    let state = tempfile::tempdir().unwrap();
    let rt = OciRuntime::new(state.path().to_path_buf()).unwrap();
    let mut c = config("");
    c.cap_add = vec!["CAP_NOPE".into()];
    assert!(rt.generate_spec(&c, root.path()).is_err());
    let mut c = config("");
    c.security_opt.seccomp = "/nonexistent/seccomp.json".into();
    assert!(rt.generate_spec(&c, root.path()).is_err());
    c.security_opt.seccomp = r#"{"defaultAction": "SCMP_ACT_NOPE"}"#.into();
    assert!(rt.generate_spec(&c, root.path()).is_err());
}

#[test]
fn create_options_reach_the_spec() {
    use velarx_wire::options::{rlimit, CreateOptions};
    let root = rootfs();
    let mut c = config("");
    c.oom_score_adj = Some(100);
    c.read_only_rootfs = true;
    c.options = CreateOptions {
        rlimits: vec![rlimit("nofile", 10, 20).unwrap()],
        annotations: [("k".to_string(), "v".to_string())].into(),
        pid_ns: "host".into(),
        shm_size: Some(2 << 20),
        read_only_tmpfs: true,
        personality: Some("LINUX32".into()),
        rootfs_propagation: Some("rslave".into()),
        ..Default::default()
    };
    let s = spec(&c, root.path());
    assert_eq!(s["process"]["oomScoreAdj"], 100);
    let nofile = s["process"]["rlimits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["type"] == "RLIMIT_NOFILE")
        .unwrap();
    assert_eq!(
        (nofile["soft"].as_u64(), nofile["hard"].as_u64()),
        (Some(10), Some(20))
    );
    assert_eq!(s["annotations"]["k"], "v");
    let ns = s["linux"]["namespaces"].as_array().unwrap();
    assert!(!ns.iter().any(|n| n["type"] == "pid"));
    assert!(ns.iter().any(|n| n["type"] == "cgroup"));
    let mounts = s["mounts"].as_array().unwrap();
    let shm = mounts
        .iter()
        .find(|m| m["destination"] == "/dev/shm")
        .unwrap();
    assert!(shm["options"]
        .as_array()
        .unwrap()
        .contains(&"size=2048k".into()));
    assert!(mounts
        .iter()
        .any(|m| m["destination"] == "/run" && m["type"] == "tmpfs"));
    assert_eq!(s["linux"]["personality"]["domain"], "LINUX32");
    assert_eq!(s["linux"]["rootfsPropagation"], "rslave");
    // the environment is the one of the create: no default is added
    assert!(env(&s, "PATH").is_none());
}
