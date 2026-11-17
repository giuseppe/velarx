// SPDX-License-Identifier: Apache-2.0
//! CDI devices in the OCI spec of a container: the spec that
//! `generate_spec` writes, with the edits of the spec files of a directory.

use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use velarx_runtime::cdi;
use velarx_runtime::container::{ContainerConfig, OciRuntime};

const SPEC: &str = r#"
cdiVersion: "0.6.0"
kind: fake.vendor.com/dev
devices:
  - name: d0
    containerEdits:
      env: ["FAKE_DEV=d0"]
      deviceNodes:
        - {path: /dev/fake0, hostPath: /dev/zero, permissions: rw}
  - name: d1
    containerEdits:
      env: ["FAKE_DEV=d1"]
      deviceNodes:
        - {path: /dev/fake1, type: c, major: 240, minor: 1, fileMode: 432, uid: 5, gid: 6}
containerEdits:
  env: ["FAKE_KIND=1"]
  mounts:
    - {hostPath: /var/tmp, containerPath: /fake, options: [ro, nosuid, nodev, bind]}
  hooks:
    - {hookName: poststop, path: /usr/bin/true, args: [true], timeout: 3}
"#;

fn specs() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("fake.yaml");
    std::fs::write(&p, SPEC).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    d
}

fn generated(root: &Path) -> Value {
    let state = tempfile::tempdir().unwrap();
    let rt = OciRuntime::new(state.path().to_path_buf()).unwrap();
    let config = ContainerConfig {
        id: "c1".into(),
        ..Default::default()
    };
    serde_json::to_value(rt.generate_spec(&config, root).unwrap()).unwrap()
}

fn with_cdi(devices: &[&str], dirs: &[&Path], bind: bool) -> Result<Value, String> {
    let root = tempfile::tempdir().unwrap();
    let mut spec = generated(root.path());
    let names: Vec<String> = devices.iter().map(|d| d.to_string()).collect();
    let dirs: Vec<_> = dirs.iter().map(|d| d.to_path_buf()).collect();
    cdi::apply(&mut spec, &cdi::resolve(&names, &dirs)?, bind);
    Ok(spec)
}

fn env(spec: &Value) -> Vec<&str> {
    spec["process"]["env"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

#[test]
fn a_device_adds_its_edits_and_those_of_its_spec_to_the_spec() {
    let d = specs();
    let s = with_cdi(&["fake.vendor.com/dev=d0"], &[d.path()], false).unwrap();
    let env = env(&s);
    assert!(env.contains(&"FAKE_KIND=1") && env.contains(&"FAKE_DEV=d0"));
    assert!(!env.contains(&"FAKE_DEV=d1"));
    // a node of the host's /dev/zero with a cgroup rule allowing rw only
    let node = &s["linux"]["devices"][0];
    assert_eq!(
        (node["path"].as_str(), node["type"].as_str()),
        (Some("/dev/fake0"), Some("c"))
    );
    assert_eq!(
        (node["major"].as_u64(), node["minor"].as_u64()),
        (Some(1), Some(5))
    );
    let rules = s["linux"]["resources"]["devices"].as_array().unwrap();
    assert_eq!(
        rules.last().unwrap(),
        &json!({"allow": true, "type": "c", "major": 1, "minor": 5, "access": "rw"})
    );
    assert!(s["mounts"].as_array().unwrap().iter().any(|m| m
        == &json!({"destination": "/fake", "type": "bind", "source": "/var/tmp",
                   "options": ["ro", "nosuid", "nodev", "bind"]})));
    assert_eq!(
        s["hooks"]["poststop"],
        json!([{"path": "/usr/bin/true", "args": ["true"], "timeout": 3}])
    );
}

#[test]
fn several_devices_make_the_edits_of_the_spec_once() {
    let d = specs();
    let s = with_cdi(
        &["fake.vendor.com/dev=d0", "fake.vendor.com/dev=d1"],
        &[d.path()],
        false,
    )
    .unwrap();
    assert_eq!(env(&s).iter().filter(|e| **e == "FAKE_KIND=1").count(), 1);
    assert_eq!(s["hooks"]["poststop"].as_array().unwrap().len(), 1);
    let nodes = s["linux"]["devices"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    // the numbers, mode and owner a spec gives without a device on the host
    assert_eq!(
        nodes[1],
        json!({"path": "/dev/fake1", "type": "c", "major": 240, "minor": 1,
               "fileMode": 432, "uid": 5, "gid": 6})
    );
}

#[test]
fn where_nodes_cannot_be_made_the_host_device_is_bind_mounted() {
    let d = specs();
    let s = with_cdi(&["fake.vendor.com/dev=d0"], &[d.path()], true).unwrap();
    assert!(s["linux"].get("devices").is_none());
    assert!(s["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["destination"] == "/dev/fake0"
            && m["source"] == "/dev/zero"
            && m["type"] == "bind"));
    // and no rule is added to the device cgroup
    let plain = generated(tempfile::tempdir().unwrap().path());
    assert_eq!(
        s["linux"]["resources"]["devices"],
        plain["linux"]["resources"]["devices"]
    );
}

#[test]
fn a_device_no_spec_defines_is_refused_by_name() {
    let d = specs();
    let e = with_cdi(&["fake.vendor.com/dev=d9"], &[d.path()], false).unwrap_err();
    assert!(
        e.contains("unresolvable CDI devices fake.vendor.com/dev=d9"),
        "{e}"
    );
    let e = with_cdi(
        &["fake.vendor.com/dev=d0"],
        &[Path::new("/nonexistent")],
        false,
    )
    .unwrap_err();
    assert!(e.contains("unresolvable CDI devices"), "{e}");
}

#[test]
fn the_specs_are_read_again_at_each_use() {
    let d = specs();
    let name = "fake.vendor.com/dev=d1";
    assert!(with_cdi(&[name], &[d.path()], false).is_ok());
    std::fs::remove_file(d.path().join("fake.yaml")).unwrap();
    assert!(with_cdi(&[name], &[d.path()], false).is_err());
    let p = d.path().join("again.json");
    std::fs::write(
        &p,
        r#"{"cdiVersion":"0.6.0","kind":"fake.vendor.com/dev","devices":[{"name":"d1","containerEdits":{"env":["AGAIN=1"]}}]}"#,
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    let s = with_cdi(&[name], &[d.path()], false).unwrap();
    assert!(env(&s).contains(&"AGAIN=1"));
}

#[test]
fn a_device_on_the_command_line_is_a_cdi_device_unless_it_is_a_path() {
    use velarx::cli::run::parse_device;
    let d = parse_device("vendor.com/class=a:b");
    assert_eq!(
        (d.path_on_host.as_str(), d.path_in_container.as_str()),
        ("vendor.com/class=a:b", "")
    );
    let d = parse_device("/dev/fuse:/dev/f:r");
    assert_eq!(
        (
            d.path_on_host.as_str(),
            d.path_in_container.as_str(),
            d.cgroup_permissions.as_str()
        ),
        ("/dev/fuse", "/dev/f", "r")
    );
}
