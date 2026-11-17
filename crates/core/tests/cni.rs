// SPDX-License-Identifier: Apache-2.0
//! The CNI executor against fake plugins: chaining with prevResult, the
//! environment, the runtime config, failed ADDs undone, DEL from the cache
//! after the configuration is gone, STATUS, timeouts and the GC of the
//! attachments of gone containers.

use std::path::Path;
use std::time::Duration;
use velarx_netkernel::cni::{self, Attachment, CniConfig, CniError, PortMapping};

const FAKE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/cni-fake-plugin.sh"
);

fn setup(dir: &Path) -> CniConfig {
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::create_dir_all(dir.join("conf")).unwrap();
    // (links, not copies: a copy is open for writing while it is made,
    // and a fork of another test of the process that holds it then makes
    // the exec of the plugin fail with ETXTBSY)
    for t in ["fake1", "fake2", "loopback", "slow"] {
        std::os::unix::fs::symlink(FAKE, dir.join("bin").join(t)).unwrap();
    }
    CniConfig {
        conf_dir: dir.join("conf"),
        bin_dirs: vec![dir.join("nothing"), dir.join("bin")],
        cache_dir: dir.join("cache"),
        timeout: Duration::from_secs(10),
    }
}

fn attachment(id: &str) -> Attachment {
    Attachment {
        container_id: id.into(),
        netns: Some("/run/netns/test".into()),
        ifname: "eth0".into(),
        pod_name: "web".into(),
        pod_namespace: "default".into(),
        pod_uid: "uid-1".into(),
        port_mappings: vec![PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".into(),
            host_ip: String::new(),
        }],
        ..Attachment::default()
    }
}

fn log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("log")).unwrap_or_default()
}

fn write_conflist(dir: &Path) {
    std::fs::write(
        dir.join("conf/10-test.conflist"),
        r#"{"cniVersion":"1.1.0","name":"testnet","plugins":[
            {"type":"fake1","bridge":"cni0"},
            {"type":"fake2","capabilities":{"portMappings":true}}]}"#,
    )
    .unwrap();
}

#[test]
fn the_configurations_are_found_by_name_or_the_first_valid_one() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let cfg = setup(dir);
    assert!(matches!(cni::load(&cfg, None), Err(CniError::NoConfig(_))));
    std::fs::write(dir.join("conf/00-bad.conf"), "{").unwrap();
    assert!(matches!(cni::load(&cfg, None), Err(CniError::Invalid(_))));
    write_conflist(dir);
    std::fs::write(
        dir.join("conf/20-other.conf"),
        r#"{"cniVersion":"0.4.0","name":"other","type":"loopback"}"#,
    )
    .unwrap();
    assert_eq!(cni::load(&cfg, None).unwrap().name, "testnet");
    assert_eq!(cni::load(&cfg, Some("other")).unwrap().name, "other");
    assert!(matches!(
        cni::load(&cfg, Some("nope")),
        Err(CniError::NoConfig(_))
    ));
}

#[test]
fn add_chains_the_plugins_and_caches_the_result_and_del_uses_the_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let cfg = setup(dir);
    write_conflist(dir);
    let net = cni::load(&cfg, None).unwrap();

    let a = attachment("aaaa");
    let result = cni::add(&cfg, &net, &a).unwrap();
    assert_eq!(cni::result_ips(&result, "eth0")[0].to_string(), "10.1.2.3");
    let l = log(dir);
    let fake1 = l.find("== fake1 ADD").unwrap();
    let fake2 = l.find("== fake2 ADD").unwrap();
    assert!(fake1 < fake2, "{l}");
    assert!(l.contains("CNI_CONTAINERID=aaaa"), "{l}");
    assert!(l.contains("CNI_IFNAME=eth0"), "{l}");
    assert!(l.contains("CNI_NETNS=/run/netns/test"), "{l}");
    assert!(l.contains("K8S_POD_NAME=web"), "{l}");
    let second = &l[fake2..];
    assert!(second.contains("\"prevResult\""), "{second}");
    assert!(
        second.contains(
            "\"portMappings\":[{\"containerPort\":80,\"hostIP\":\"\",\"hostPort\":8080,\"protocol\":\"tcp\"}]"
        ),
        "{second}"
    );
    assert!(!l[fake1..fake2].contains("runtimeConfig"), "{l}");
    assert!(dir.join("cache/results/testnet-aaaa-eth0").exists());
    assert_eq!(
        cni::cached_result(&cfg, &a).unwrap().1,
        Some(result.clone())
    );

    // DEL after the configuration is gone: from the cache, in reverse
    std::fs::remove_file(dir.join("log")).unwrap();
    std::fs::remove_file(dir.join("conf/10-test.conflist")).unwrap();
    cni::del(&cfg, &a).unwrap();
    let l = log(dir);
    assert!(
        l.find("== fake2 DEL").unwrap() < l.find("== fake1 DEL").unwrap(),
        "{l}"
    );
    assert!(l.contains("\"prevResult\""), "{l}");
    assert!(!dir.join("cache/results/testnet-aaaa-eth0").exists());
    assert!(cni::cached_result(&cfg, &a).is_none());
    // nothing cached and no configuration: nothing to fail
    cni::del(&cfg, &a).unwrap();
}

#[test]
fn a_failed_add_is_undone() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let cfg = setup(dir);
    write_conflist(dir);
    let net = cni::load(&cfg, None).unwrap();
    std::fs::write(dir.join("fail"), "fake2").unwrap();
    let e = cni::add(&cfg, &net, &attachment("bbbb"))
        .unwrap_err()
        .to_string();
    assert!(e.contains("boom: fake failure"), "{e}");
    let l = log(dir);
    assert!(
        l.contains("== fake1 DEL") && l.contains("== fake2 DEL"),
        "{l}"
    );
    assert!(!dir.join("cache/results/testnet-bbbb-eth0").exists());
}

#[test]
fn status_asks_the_plugins() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let cfg = setup(dir);
    write_conflist(dir);
    let net = cni::load(&cfg, None).unwrap();
    cni::status(&cfg, &net).unwrap();
    std::fs::write(dir.join("notready"), "fake1").unwrap();
    assert!(cni::status(&cfg, &net)
        .unwrap_err()
        .to_string()
        .contains("not ready"));
}

#[test]
fn the_attachments_of_gone_containers_are_released() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let cfg = setup(dir);
    write_conflist(dir);
    let net = cni::load(&cfg, None).unwrap();
    cni::add(&cfg, &net, &attachment("live")).unwrap();
    cni::add(&cfg, &net, &attachment("gone")).unwrap();
    std::fs::remove_file(dir.join("log")).unwrap();
    assert_eq!(cni::gc(&cfg, &|id| id == "live"), 1);
    assert!(dir.join("cache/results/testnet-live-eth0").exists());
    assert!(!dir.join("cache/results/testnet-gone-eth0").exists());
    assert!(log(dir).contains("CNI_CONTAINERID=gone"));
}

#[test]
fn a_del_gets_the_pod_cidr_and_the_ports_of_the_add() {
    // (the bridge of a node takes its range from the pod CIDR: its DEL,
    // without it, fails "no IP ranges specified", and the rules of the
    // attachment stay)
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let cfg = setup(dir);
    std::fs::write(
        dir.join("conf/10-test.conflist"),
        r#"{"cniVersion":"1.1.0","name":"testnet","plugins":[
            {"type":"fake1","capabilities":{"ipRanges":true}},
            {"type":"fake2","capabilities":{"portMappings":true}}]}"#,
    )
    .unwrap();
    let net = cni::load(&cfg, None).unwrap();
    let ranges = Attachment {
        ip_ranges: vec!["10.244.0.0/24".into()],
        ..attachment("cccc")
    };
    cni::add(&cfg, &net, &ranges).unwrap();
    cni::add(
        &cfg,
        &net,
        &Attachment {
            ip_ranges: ranges.ip_ranges.clone(),
            ..attachment("dddd")
        },
    )
    .unwrap();
    // a removal and the GC know only the container
    let bare = |id: &str| Attachment {
        container_id: id.into(),
        ifname: "eth0".into(),
        ..Attachment::default()
    };
    for (id, del) in [
        (
            "cccc",
            Box::new(|| cni::del(&cfg, &bare("cccc")).unwrap()) as Box<dyn Fn()>,
        ),
        (
            "dddd",
            Box::new(|| assert_eq!(cni::gc(&cfg, &|_| false), 1)),
        ),
    ] {
        let _ = std::fs::remove_file(dir.join("log"));
        del();
        let l = log(dir);
        let fake1 = &l[l.find("== fake1 DEL").unwrap()..];
        assert!(
            fake1.contains(r#""ipRanges":[[{"subnet":"10.244.0.0/24"}]]"#),
            "{id}: {l}"
        );
        let fake2 = &l[l.find("== fake2 DEL").unwrap()..l.find("== fake1 DEL").unwrap()];
        assert!(fake2.contains(r#""hostPort":8080"#), "{id}: {l}");
    }
}

#[test]
fn a_plugin_that_does_not_answer_is_killed_and_one_that_is_not_there_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let mut cfg = setup(dir);
    std::fs::write(
        dir.join("conf/05-slow.conf"),
        r#"{"cniVersion":"1.0.0","name":"slow","type":"slow"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("conf/06-missing.conf"),
        r#"{"cniVersion":"1.0.0","name":"missing","type":"nosuchplugin"}"#,
    )
    .unwrap();
    cfg.timeout = Duration::from_secs(1);
    let slow = cni::load(&cfg, Some("slow")).unwrap();
    // The plugin sleeps for an hour: the answer within the deadline is the
    // kill (the error comes once the plugin has been reaped).
    let (tx, rx) = std::sync::mpsc::channel();
    let c = cfg.clone();
    std::thread::spawn(move || {
        let _ = tx.send(cni::add(&c, &slow, &attachment("cccc")));
    });
    let e = rx
        .recv_timeout(Duration::from_secs(300))
        .expect("the plugin that does not answer was not killed")
        .unwrap_err()
        .to_string();
    assert!(e.contains("did not answer"), "{e}");
    let m = cni::load(&cfg, Some("missing")).unwrap();
    let e = cni::add(&cfg, &m, &attachment("dddd"))
        .unwrap_err()
        .to_string();
    assert!(e.contains("cannot find the CNI plugin"), "{e}");
}
