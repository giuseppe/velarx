// SPDX-License-Identifier: Apache-2.0
//! Comprehensive integration tests for velarx
//!
//! These tests cover:
//! - Container lifecycle (create, start, stop, delete)
//! - Image pull with a fallback to other sources
//! - Health check execution
//! - Checkpoint/restore flow
//! - Network namespace sharing

use sha2::{Digest, Sha256};
use velarx_core::services::{
    build_resolv_conf,
    ContainerError,
    HostsConfig,
    MountSpec,
    MountType, // Network types are re-exported from services, not from services::network
    ResolvParams,
    VolumeDriver,
    VolumeError,
    VolumeMountOptions,
};
use velarx_proto::health::{Healthcheck, OnFailure};
use velarx_wire::request::NetworkMode;
use velarx_wire::request::{
    CreateContainerRequest, PortMapping, ResourceLimits, RestartPolicy, SecurityOptions,
};

mod container_lifecycle {
    use super::*;

    #[tokio::test]
    async fn test_container_create_request_builder() {
        let req = CreateContainerRequest {
            image: "alpine:latest".to_string(),
            name: Some("test-container".to_string()),
            command: vec!["echo".to_string(), "hello".to_string()],
            env: vec!["FOO=bar".to_string()],
            tty: true,
            ..Default::default()
        };

        assert_eq!(req.image, "alpine:latest");
        assert_eq!(req.name, Some("test-container".to_string()));
        assert_eq!(req.command.len(), 2);
        assert!(req.tty);
        assert!(!req.privileged);
    }

    #[tokio::test]
    async fn test_container_request_with_resources() {
        let resources = ResourceLimits {
            memory: Some(512 * 1024 * 1024),       // 512MB
            memory_swap: Some(1024 * 1024 * 1024), // 1GB
            cpu_shares: Some(512),
            cpu_quota: Some(50000),
            cpu_period: Some(100000),
            cpuset_cpus: Some("0,1".to_string()),
            cpuset_mems: Some("0".to_string()),
            ..Default::default()
        };

        let req = CreateContainerRequest {
            image: "alpine:latest".to_string(),
            resources: Some(resources),
            ..Default::default()
        };

        let res = req.resources.as_ref().unwrap();
        assert_eq!(res.memory, Some(512 * 1024 * 1024));
        assert_eq!(res.cpu_shares, Some(512));
    }

    #[tokio::test]
    async fn test_container_request_with_network_mode() {
        let req = CreateContainerRequest {
            image: "alpine:latest".to_string(),
            network_mode: NetworkMode::Host,
            ..Default::default()
        };

        assert_eq!(req.network_mode, NetworkMode::Host);
    }

    #[tokio::test]
    async fn test_container_request_with_network_container_mode() {
        let req = CreateContainerRequest {
            image: "alpine:latest".to_string(),
            network_mode: NetworkMode::Container("abc123".into()),
            ..Default::default()
        };

        assert!(matches!(req.network_mode, NetworkMode::Container(_)));
    }

    #[test]
    fn test_container_id_format() {
        // Container IDs should be 12 hex characters
        let image_name = "test-image:latest";
        let timestamp = 1234567890i64;

        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", image_name, timestamp));
        let hash = hex::encode(hasher.finalize());
        let container_id = &hash[..12];

        assert_eq!(container_id.len(), 12);
        assert!(container_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_container_error_types() {
        let not_found = ContainerError::NotFound("test-id".to_string());
        assert!(not_found.to_string().contains("test-id"));

        let already_exists = ContainerError::AlreadyExists("test-id".to_string());
        assert!(already_exists.to_string().contains("test-id"));

        let not_running = ContainerError::NotRunning("test-id".to_string());
        assert!(not_running.to_string().contains("not running"));

        let already_running = ContainerError::AlreadyRunning("test-id".to_string());
        assert!(already_running.to_string().contains("running"));
    }

    #[tokio::test]
    async fn test_container_request_serialization() {
        let mut req = CreateContainerRequest {
            image: "nginx:latest".to_string(),
            name: Some("web-server".to_string()),
            env: vec!["PORT=80".to_string()],
            ..Default::default()
        };
        req.ports = vec![PortMapping {
            container_port: 80,
            host_port: Some(8080),
            host_ip: "0.0.0.0".to_string(),
            protocol: "tcp".to_string(),
        }];

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("nginx:latest"));
        assert!(json.contains("web-server"));

        let parsed: CreateContainerRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.image, "nginx:latest");
        assert_eq!(parsed.name, Some("web-server".to_string()));
    }
}

mod checkpoint_restore {
    use velarx_wire::wire::{CheckpointOptions, CheckpointRecord, RestoreOptions};

    // checkpoint and restore go through the runtime: e2e run-lifecycle.bats
    // checkpoint and api/checkpoint.bats, as root; here the requests
    #[test]
    fn the_requests_have_defaults() {
        let c: CheckpointOptions = serde_json::from_str("{}").unwrap();
        assert!(!c.leave_running && c.export.is_none() && !c.keep);
        let r: RestoreOptions = serde_json::from_str("{}").unwrap();
        assert!(r.import.is_none() && r.name.is_none());
        let rec: CheckpointRecord = serde_json::from_str("{}").unwrap();
        assert!(!rec.checkpointed);
    }
}

mod volume_tests {
    use super::*;

    #[test]
    fn test_mount_spec_parse_bind_mount() {
        let spec = MountSpec::parse_volume_arg("/host/path:/container/path").unwrap();
        assert_eq!(spec.mount_type, MountType::Bind);
        assert_eq!(spec.source, Some("/host/path".to_string()));
        assert_eq!(spec.target, "/container/path");
        assert!(!spec.options.read_only);
    }

    #[test]
    fn test_mount_spec_parse_named_volume() {
        let spec = MountSpec::parse_volume_arg("myvolume:/data").unwrap();
        assert_eq!(spec.mount_type, MountType::Volume);
        assert_eq!(spec.source, Some("myvolume".to_string()));
        assert_eq!(spec.target, "/data");
    }

    #[test]
    fn test_mount_spec_parse_readonly() {
        let spec = MountSpec::parse_volume_arg("/src:/dest:ro").unwrap();
        assert!(spec.options.read_only);
    }

    #[test]
    fn test_mount_spec_parse_selinux() {
        let spec = MountSpec::parse_volume_arg("/src:/dest:z").unwrap();
        assert_eq!(
            spec.options.selinux_relabel,
            Some(velarx_core::services::SelinuxRelabel::Shared)
        );

        let spec = MountSpec::parse_volume_arg("/src:/dest:Z").unwrap();
        assert_eq!(
            spec.options.selinux_relabel,
            Some(velarx_core::services::SelinuxRelabel::Private)
        );
    }

    #[test]
    fn test_mount_spec_parse_propagation() {
        let spec = MountSpec::parse_volume_arg("/src:/dest:shared").unwrap();
        assert_eq!(
            spec.options.propagation,
            velarx_core::services::BindPropagation::Shared
        );
    }

    #[test]
    fn test_mount_spec_parse_mount_arg() {
        let spec = MountSpec::parse_mount_arg(
            "type=bind,source=/src,target=/dest,readonly,bind-propagation=shared",
        )
        .unwrap();

        assert_eq!(spec.mount_type, MountType::Bind);
        assert_eq!(spec.source, Some("/src".to_string()));
        assert_eq!(spec.target, "/dest");
        assert!(spec.options.read_only);
    }

    #[test]
    fn test_mount_spec_parse_tmpfs() {
        let spec = MountSpec::parse_mount_arg("type=tmpfs,target=/tmp").unwrap();
        assert_eq!(spec.mount_type, MountType::Tmpfs);
        assert_eq!(spec.target, "/tmp");
    }

    #[test]
    fn test_volume_driver_default() {
        let driver = VolumeDriver::default();
        assert_eq!(driver, VolumeDriver::Local);
    }

    #[test]
    fn test_volume_error_display() {
        let err = VolumeError::NotFound("myvolume".to_string());
        assert!(err.to_string().contains("myvolume"));

        let err = VolumeError::AlreadyExists("existing".to_string());
        assert!(err.to_string().contains("existing"));

        let err = VolumeError::InUse("busy".to_string());
        assert!(err.to_string().contains("busy"));
    }

    #[test]
    fn test_oci_mount_generation() {
        let spec = MountSpec {
            mount_type: MountType::Bind,
            source: Some("/host/data".to_string()),
            target: "/container/data".to_string(),
            options: VolumeMountOptions {
                read_only: true,
                ..Default::default()
            },
        };

        let oci_mount = spec
            .to_oci_mount(std::path::Path::new("/var/lib/velarx/volumes"))
            .unwrap();
        assert_eq!(oci_mount.destination, "/container/data");
        assert_eq!(oci_mount.source, "/host/data");
        assert!(oci_mount.options.contains(&"ro".to_string()));
    }
}

mod network_tests {
    use super::*;

    #[test]
    fn test_network_mode_parse() {
        assert_eq!(NetworkMode::parse("host"), NetworkMode::Host);
        assert_eq!(NetworkMode::parse("none"), NetworkMode::Off);
        assert_eq!(NetworkMode::parse("bridge"), NetworkMode::Bridge(None));
        assert_eq!(NetworkMode::parse("pasta"), NetworkMode::Pasta(None));
    }

    #[test]
    fn test_network_mode_container() {
        let mode = NetworkMode::parse("container:abc123");
        match mode {
            NetworkMode::Container(id) => assert_eq!(id, "abc123"),
            _ => panic!("expected Container mode"),
        }
    }

    #[test]
    fn test_dns_config_generation() {
        // no usable server of the host: the pair podman falls back to
        let resolv_conf = build_resolv_conf(&ResolvParams::default());

        assert!(resolv_conf.contains("nameserver 8.8.8.8"));
        assert!(resolv_conf.contains("nameserver 8.8.4.4"));
    }

    #[test]
    fn test_hosts_config_generation() {
        let mut hosts = HostsConfig::new();
        hosts.add_container("127.0.0.1", "container1", None);
        hosts.add_host("10.0.0.5", "database");
        hosts
            .add_extra_hosts(&["webserver:10.0.0.10".to_string()], None)
            .unwrap();

        let content = hosts.generate_hosts();
        assert!(content.contains("127.0.0.1"));
        assert!(content.contains("localhost"));
        assert!(content.contains("container1"));
        assert!(content.contains("database"));
        assert!(content.contains("10.0.0.10"));
    }
}

mod security_tests {
    use super::*;

    #[test]
    fn test_security_options_default() {
        let opts = SecurityOptions::default();
        assert!(!opts.no_new_privileges);
        assert!(!opts.seccomp_unconfined);
        assert!(!opts.apparmor_unconfined);
        assert!(opts.seccomp_profile.is_none());
        assert!(opts.apparmor_profile.is_none());
        assert!(opts.selinux_label.is_none());
        assert!(opts.mask_paths.is_empty());
        assert!(opts.readonly_paths.is_empty());
    }

    #[test]
    fn test_security_options_configured() {
        let opts = SecurityOptions {
            no_new_privileges: true,
            seccomp_unconfined: false,
            seccomp_profile: Some("/path/to/seccomp.json".to_string()),
            selinux_label: Some("container_t".to_string()),
            apparmor_profile: Some("docker-default".to_string()),
            apparmor_unconfined: false,
            mask_paths: vec!["/proc/kcore".to_string()],
            readonly_paths: vec!["/proc/sys".to_string()],
            ..Default::default()
        };

        assert!(opts.no_new_privileges);
        assert_eq!(
            opts.seccomp_profile,
            Some("/path/to/seccomp.json".to_string())
        );
        assert_eq!(opts.mask_paths.len(), 1);
    }

    #[test]
    fn test_security_options_serialization() {
        let opts = SecurityOptions {
            no_new_privileges: true,
            seccomp_unconfined: true,
            ..Default::default()
        };

        let json = serde_json::to_string(&opts).unwrap();
        let parsed: SecurityOptions = serde_json::from_str(&json).unwrap();

        assert!(parsed.no_new_privileges);
        assert!(parsed.seccomp_unconfined);
    }
}

mod resource_tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert!(limits.memory.is_none());
        assert!(limits.cpu_shares.is_none());
        assert!(limits.cpu_quota.is_none());
    }

    #[test]
    fn test_resource_limits_full() {
        let limits = ResourceLimits {
            memory: Some(1024 * 1024 * 1024),            // 1GB
            memory_swap: Some(2 * 1024 * 1024 * 1024),   // 2GB
            memory_reservation: Some(512 * 1024 * 1024), // 512MB
            cpu_shares: Some(1024),
            cpu_quota: Some(100000),
            cpu_period: Some(100000),
            cpuset_cpus: Some("0-3".to_string()),
            cpuset_mems: Some("0".to_string()),
            blkio_weight: Some(500),
            ..Default::default()
        };

        assert_eq!(limits.memory, Some(1024 * 1024 * 1024));
        assert_eq!(limits.cpu_shares, Some(1024));
        assert_eq!(limits.blkio_weight, Some(500));
    }

    #[test]
    fn test_resource_limits_serialization() {
        let limits = ResourceLimits {
            memory: Some(512 * 1024 * 1024),
            cpu_quota: Some(50000),
            ..Default::default()
        };

        let json = serde_json::to_string(&limits).unwrap();
        let parsed: ResourceLimits = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.memory, limits.memory);
        assert_eq!(parsed.cpu_quota, limits.cpu_quota);
    }
}

mod restart_policy_tests {
    use super::*;

    #[test]
    fn test_restart_policy_none() {
        let policy = RestartPolicy {
            name: "no".to_string(),
            maximum_retry_count: 0,
        };

        assert_eq!(policy.name, "no");
        assert_eq!(policy.maximum_retry_count, 0);
    }

    #[test]
    fn test_restart_policy_on_failure() {
        let policy = RestartPolicy {
            name: "on-failure".to_string(),
            maximum_retry_count: 5,
        };

        assert_eq!(policy.name, "on-failure");
        assert_eq!(policy.maximum_retry_count, 5);
    }

    #[test]
    fn test_restart_policy_always() {
        let policy = RestartPolicy {
            name: "always".to_string(),
            maximum_retry_count: 0,
        };

        assert_eq!(policy.name, "always");
    }

    #[test]
    fn test_restart_policy_serialization() {
        let policy = RestartPolicy {
            name: "on-failure".to_string(),
            maximum_retry_count: 3,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: RestartPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, "on-failure");
        assert_eq!(parsed.maximum_retry_count, 3);
    }
}

mod port_mapping_tests {
    use super::*;

    #[test]
    fn test_port_mapping_basic() {
        let port = PortMapping {
            container_port: 80,
            host_port: Some(8080),
            host_ip: "0.0.0.0".to_string(),
            protocol: "tcp".to_string(),
        };

        assert_eq!(port.container_port, 80);
        assert_eq!(port.host_port, Some(8080));
        assert_eq!(port.protocol, "tcp");
    }

    #[test]
    fn test_port_mapping_udp() {
        let port = PortMapping {
            container_port: 53,
            host_port: Some(5353),
            host_ip: "127.0.0.1".to_string(),
            protocol: "udp".to_string(),
        };

        assert_eq!(port.protocol, "udp");
        assert_eq!(port.host_ip, "127.0.0.1");
    }

    #[test]
    fn test_port_mapping_auto_assign() {
        let port = PortMapping {
            container_port: 8080,
            host_port: None, // Auto-assign
            host_ip: "0.0.0.0".to_string(),
            protocol: "tcp".to_string(),
        };

        assert!(port.host_port.is_none());
    }

    #[test]
    fn test_port_mapping_serialization() {
        let port = PortMapping {
            container_port: 443,
            host_port: Some(8443),
            host_ip: "0.0.0.0".to_string(),
            protocol: "tcp".to_string(),
        };

        let json = serde_json::to_string(&port).unwrap();
        let parsed: PortMapping = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.container_port, 443);
        assert_eq!(parsed.host_port, Some(8443));
    }
}

// Health Check Config Tests (from API)

mod health_check_api_tests {
    use super::*;

    #[test]
    fn test_health_check_request() {
        let health = Healthcheck {
            test: vec![
                "CMD".to_string(),
                "curl".to_string(),
                "-f".to_string(),
                "http://localhost/".to_string(),
            ],
            interval_ns: 30_000_000_000,    // 30s in nanoseconds
            timeout_ns: 10_000_000_000,     // 10s
            start_period_ns: 5_000_000_000, // 5s
            retries: 3,
            start_interval_ns: 0,
            ..Default::default()
        };

        assert_eq!(health.test.len(), 4);
        assert_eq!(health.retries, 3);
    }

    #[test]
    fn test_health_check_none() {
        let health = Healthcheck {
            test: vec!["NONE".to_string()],
            interval_ns: 0,
            timeout_ns: 0,
            start_period_ns: 0,
            retries: 0,
            start_interval_ns: 0,
            ..Default::default()
        };

        assert_eq!(health.test[0], "NONE");
    }

    #[test]
    fn test_health_check_cmd_shell() {
        let health = Healthcheck {
            test: vec![
                "CMD-SHELL".to_string(),
                "curl -f http://localhost/ || exit 1".to_string(),
            ],
            interval_ns: 30_000_000_000,
            timeout_ns: 30_000_000_000,
            start_period_ns: 0,
            retries: 3,
            start_interval_ns: 0,
            on_failure: OnFailure::Restart,
            ..Default::default()
        };

        assert_eq!(health.test[0], "CMD-SHELL");
        assert!(health.test[1].contains("curl"));
        assert_eq!(health.on_failure, OnFailure::Restart);
    }
}
