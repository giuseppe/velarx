// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the request types and the network modes

use velarx_wire::request::NetworkMode;
use velarx_wire::request::{CreateContainerRequest, PortMapping, SecurityOptions};

mod container_lifecycle {
    use super::*;

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
}

mod security_tests {
    use super::*;

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
