// SPDX-License-Identifier: Apache-2.0
//! Tests for the request types of the client

#[tokio::test]
async fn test_client_request_builder() {
    use velarx::client::CreateContainerRequest;

    let req = CreateContainerRequest {
        name: Some("test".to_string()),
        image: "alpine:latest".to_string(),
        command: vec!["echo".to_string(), "hello".to_string()],
        ..Default::default()
    };

    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("alpine:latest"));
    assert!(json.contains("echo"));
}
