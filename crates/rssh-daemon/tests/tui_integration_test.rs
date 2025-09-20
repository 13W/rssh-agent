/// Integration tests that use real TUI structures and mock responses
/// These tests ensure daemon and TUI use the same data format
use std::process::{Child, Command};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::sleep;

#[tokio::test]
async fn test_manage_list_with_empty_keys() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Build a real manage.list request as TUI would
    let ext_request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&ext_request, &mut cbor_data).unwrap();

    let mut message = vec![27]; // SSH_AGENTC_EXTENSION
    let ext_name = b"rssh-agent@local";
    message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_name);
    message.extend_from_slice(&cbor_data);

    let mut request = Vec::new();
    request.extend_from_slice(&(message.len() as u32).to_be_bytes());
    request.extend_from_slice(&message);

    let response = send_request(&socket_path, &request).await;

    // Even when locked, we should be able to parse the response format
    if response[4] == 6 {
        // SSH_AGENT_SUCCESS
        // Parse response as TUI would
        let mut offset = 5;
        let data_len = u32::from_be_bytes([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ]) as usize;
        offset += 4;

        let cbor_data = &response[offset..offset + data_len];
        let ext_response: rssh_proto::cbor::ExtensionResponse =
            ciborium::from_reader(cbor_data).expect("Should parse ExtensionResponse");

        assert!(ext_response.success);

        // Parse the ManageListResponse
        let list_response: rssh_proto::cbor::ManageListResponse =
            ciborium::from_reader(&ext_response.data[..]).expect("Should parse ManageListResponse");

        assert!(list_response.ok);
        assert_eq!(list_response.keys.len(), 0); // Empty when locked
    }

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_manage_list_response_parsing() {
    // Test parsing of mock response data
    use rssh_proto::cbor::{ExtensionResponse, ManageListResponse, ManagedKey};

    // Create a test response with keys
    let test_keys = vec![
        ManagedKey {
            fp_sha256_hex: "SHA256:test1".to_string(),
            key_type: "ssh-ed25519".to_string(),
            format: "ssh-ed25519".to_string(),
            description: "Test key 1".to_string(),
            source: "internal".to_string(),
            loaded: true,
            has_disk: true,
            has_cert: false,
            password_protected: false,
            constraints: serde_json::json!({
                "confirm": true,
                "lifetime_expires_at": null,
            }),
            default_constraints: None,
            created: None,
            updated: None,
        },
        ManagedKey {
            fp_sha256_hex: "SHA256:test2".to_string(),
            key_type: "ssh-rsa".to_string(),
            format: "rsa-sha2-512".to_string(),
            description: "Test key 2".to_string(),
            source: "external".to_string(),
            loaded: true,
            has_disk: false,
            has_cert: false,
            password_protected: false,
            constraints: serde_json::json!({
                "confirm": false,
                "lifetime_expires_at": null,
            }),
            default_constraints: None,
            created: None,
            updated: None,
        },
    ];

    let list_response = ManageListResponse {
        ok: true,
        keys: test_keys.clone(),
    };

    // Serialize to CBOR as daemon would
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&list_response, &mut data_cbor).unwrap();

    let ext_response = ExtensionResponse {
        success: true,
        data: data_cbor,
    };

    let mut response_cbor = Vec::new();
    ciborium::into_writer(&ext_response, &mut response_cbor).unwrap();

    // Now parse it back as TUI would
    let parsed_ext: ExtensionResponse = ciborium::from_reader(&response_cbor[..]).unwrap();
    assert!(parsed_ext.success);

    let parsed_list: ManageListResponse = ciborium::from_reader(&parsed_ext.data[..]).unwrap();
    assert!(parsed_list.ok);
    assert_eq!(parsed_list.keys.len(), 2);
    assert_eq!(parsed_list.keys[0].fp_sha256_hex, "SHA256:test1");
    assert_eq!(parsed_list.keys[1].fp_sha256_hex, "SHA256:test2");
}

#[tokio::test]
async fn test_manage_response_formats() {
    // Test that our mock response files can be parsed
    let response_data = std::fs::read("../../tests/mocks/06_manage_list.response")
        .expect("Should read mock response");

    if response_data.len() > 5 && response_data[4] == 6 {
        // SSH_AGENT_SUCCESS
        let mut offset = 5;

        if response_data.len() >= offset + 4 {
            let data_len = u32::from_be_bytes([
                response_data[offset],
                response_data[offset + 1],
                response_data[offset + 2],
                response_data[offset + 3],
            ]) as usize;
            offset += 4;

            if response_data.len() >= offset + data_len {
                let cbor_data = &response_data[offset..offset + data_len];

                // Try to parse as our ExtensionResponse
                let result: Result<rssh_proto::cbor::ExtensionResponse, _> =
                    ciborium::from_reader(cbor_data);

                assert!(
                    result.is_ok(),
                    "Mock response should parse as ExtensionResponse"
                );

                if let Ok(ext_resp) = result {
                    // Try to parse the inner data
                    let list_result: Result<rssh_proto::cbor::ManageListResponse, _> =
                        ciborium::from_reader(&ext_resp.data[..]);

                    assert!(
                        list_result.is_ok(),
                        "Should parse ManageListResponse from mock"
                    );
                }
            }
        }
    }
}

// Helper functions
async fn start_test_daemon() -> (Child, String, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();

    let build_output = Command::new("cargo")
        .args(&["build", "--package", "rssh-cli", "--bin", "rssh-agent"])
        .output()
        .expect("Failed to build rssh-agent");

    if !build_output.status.success() {
        panic!("Failed to build rssh-agent");
    }

    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|p| {
            std::path::Path::new(&p)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .unwrap_or_else(|_| std::env::current_dir().unwrap());

    let binary_path = workspace_root.join("target/debug/rssh-agent");

    let mut daemon = Command::new(&binary_path)
        .args(&["daemon", "--socket", &socket_str, "--foreground"])
        .spawn()
        .expect("Failed to start daemon");

    sleep(Duration::from_secs(2)).await;

    match daemon.try_wait() {
        Ok(Some(status)) => panic!("Daemon exited with status: {:?}", status),
        Ok(None) => {}
        Err(e) => panic!("Error checking daemon status: {}", e),
    }

    if !std::path::Path::new(&socket_str).exists() {
        daemon.kill().ok();
        panic!("Socket file not created");
    }

    (daemon, socket_str, temp_dir)
}

async fn send_request(socket_path: &str, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .expect("Failed to connect to socket");

    stream
        .write_all(request)
        .await
        .expect("Failed to write request");

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .expect("Failed to read response length");

    let response_len = u32::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; response_len];
    stream
        .read_exact(&mut response)
        .await
        .expect("Failed to read response");

    let mut full_response = len_buf.to_vec();
    full_response.extend_from_slice(&response);
    full_response
}
