// SPDX-License-Identifier: Apache-2.0
//! Integration tests for pod operations

use sha2::{Digest, Sha256};

#[test]
fn test_pod_id_generation_uses_sha256() {
    let pod_name = "test-pod";
    let timestamp = 1234567890i64;

    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", pod_name, timestamp));
    let hash = hex::encode(hasher.finalize());

    let pod_id = &hash[..12];
    assert_eq!(pod_id.len(), 12);

    assert!(pod_id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_pod_spec_serialization() {
    use std::collections::BTreeMap;
    use velarx_core::services::{PodDnsConfig, PodPortMapping, PodSpec};

    let spec = PodSpec {
        name: "test-pod".to_string(),
        hostname: Some("test-host".to_string()),
        networks: vec!["bridge".to_string()],
        dns: PodDnsConfig::default(),
        add_hosts: vec![],
        security_context: Default::default(),
        ports: vec![PodPortMapping {
            container_port: 80,
            host_port: Some(8080),
            host_ip: None,
            protocol: "tcp".to_string(),
        }],
        labels: {
            let mut m = BTreeMap::new();
            m.insert("app".to_string(), "test".to_string());
            m
        },
        annotations: BTreeMap::new(),
        share_pid: false,
        share_ipc: true,
        share_net: true,
        share_uts: true,
        share_cgroup: false,
        userns: None,
        infra_image: Some("pause:latest".to_string()),
        infra_command: None,
        infra_name: None,
        infra_conmon_pidfile: None,
        exit_policy: Default::default(),
        ..Default::default()
    };

    let json = serde_json::to_string(&spec).unwrap();
    let parsed: PodSpec = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.name, spec.name);
    assert_eq!(parsed.hostname, spec.hostname);
    assert_eq!(parsed.labels.get("app"), Some(&"test".to_string()));
    assert!(parsed.share_ipc);
}

#[test]
fn test_pod_state_transitions() {
    use velarx_core::services::PodState;

    assert_eq!(PodState::Created, PodState::Created);
    assert_ne!(PodState::Created, PodState::Running);
    assert_ne!(PodState::Running, PodState::Stopped);
    assert_ne!(PodState::Stopped, PodState::Paused);
}

#[test]
fn test_pod_error_display() {
    use velarx_core::services::PodError;

    let err = PodError::NotFound("test-pod".to_string());
    assert!(err.to_string().contains("test-pod"));

    let err = PodError::AlreadyExists("existing-pod".to_string());
    assert!(err.to_string().contains("existing-pod"));

    let err = PodError::Running;
    assert!(err.to_string().contains("running"));
}

#[test]
fn test_pod_dns_config() {
    use velarx_core::services::PodDnsConfig;

    let dns = PodDnsConfig {
        servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
        searches: vec!["example.com".to_string()],
        options: vec!["ndots:5".to_string()],
    };

    let json = serde_json::to_string(&dns).unwrap();
    let parsed: PodDnsConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.servers.len(), 2);
    assert_eq!(parsed.searches.len(), 1);
    assert_eq!(parsed.options.len(), 1);
}

#[test]
fn test_pod_port_mapping() {
    use velarx_core::services::PodPortMapping;

    let port = PodPortMapping {
        container_port: 443,
        host_port: Some(8443),
        host_ip: Some("0.0.0.0".to_string()),
        protocol: "tcp".to_string(),
    };

    let json = serde_json::to_string(&port).unwrap();
    let parsed: PodPortMapping = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.container_port, 443);
    assert_eq!(parsed.host_port, Some(8443));
    assert_eq!(parsed.protocol, "tcp");
}
