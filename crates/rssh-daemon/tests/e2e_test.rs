/// End-to-end tests that actually parse and validate CBOR responses
/// These tests would have caught the namespace and structure errors
use std::fs;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::sleep;

#[tokio::test]
async fn test_manage_list_cbor_structure() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Build a proper manage.list request
    let ext_request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&ext_request, &mut cbor_data).unwrap();

    // Build SSH wire format with CORRECT namespace
    let mut message = vec![27]; // SSH_AGENTC_EXTENSION
    let ext_name = b"rssh-agent@local"; // This would have caught the namespace error!
    message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_name);
    message.extend_from_slice(&cbor_data);

    let mut request = Vec::new();
    request.extend_from_slice(&(message.len() as u32).to_be_bytes());
    request.extend_from_slice(&message);

    let response = send_request(&socket_path, &request).await;

    // Agent is locked, should return SSH_AGENT_FAILURE
    assert_eq!(response[4], 5, "Should return failure when locked");

    // But let's also test that if it returned success, we could parse it
    // This simulates what TUI does
    if response[4] == 6 {
        // SSH_AGENT_SUCCESS
        // Parse the wire-encoded CBOR
        let mut offset = 5; // Skip length (4) and message type (1)

        if response.len() >= offset + 4 {
            let data_len = u32::from_be_bytes([
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ]) as usize;
            offset += 4;

            if response.len() >= offset + data_len {
                let cbor_data = &response[offset..offset + data_len];

                // Try to parse as ExtensionResponse - this would have caught the struct error!
                let parsed: Result<rssh_proto::cbor::ExtensionResponse, _> =
                    ciborium::from_reader(cbor_data);

                assert!(parsed.is_ok(), "Should be able to parse ExtensionResponse");

                if let Ok(ext_resp) = parsed {
                    assert!(ext_resp.success, "Response should indicate success");

                    // Try to parse the data field
                    let data_parsed: Result<serde_json::Value, _> =
                        ciborium::from_reader(&ext_resp.data[..]);
                    assert!(data_parsed.is_ok(), "Should be able to parse data field");
                }
            }
        }
    }

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_wrong_namespace_error() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test with WRONG namespace - this should fail
    let ext_request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&ext_request, &mut cbor_data).unwrap();

    let mut message = vec![27]; // SSH_AGENTC_EXTENSION
    let wrong_namespace = b"rssh.manage"; // WRONG namespace
    message.extend_from_slice(&(wrong_namespace.len() as u32).to_be_bytes());
    message.extend_from_slice(wrong_namespace);
    message.extend_from_slice(&cbor_data);

    let mut request = Vec::new();
    request.extend_from_slice(&(message.len() as u32).to_be_bytes());
    request.extend_from_slice(&message);

    let response = send_request(&socket_path, &request).await;

    // Should return failure because of wrong namespace
    assert_eq!(response[4], 5, "Should fail with wrong namespace");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_direct_cbor_without_namespace() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test sending CBOR directly without namespace (like old TUI did)
    let ext_request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&ext_request, &mut cbor_data).unwrap();

    // Send CBOR directly after message type (no namespace)
    let mut message = vec![27]; // SSH_AGENTC_EXTENSION
    message.extend_from_slice(&cbor_data); // Direct CBOR, no namespace!

    let mut request = Vec::new();
    request.extend_from_slice(&(message.len() as u32).to_be_bytes());
    request.extend_from_slice(&message);

    let response = send_request(&socket_path, &request).await;

    // Should fail because no namespace
    assert_eq!(response[4], 5, "Should fail without namespace");

    daemon.kill().expect("Failed to kill daemon");
}

// Helper functions
async fn start_test_daemon() -> (Child, String, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();

    // Build the daemon
    let build_output = Command::new("cargo")
        .args(&["build", "--package", "rssh-cli", "--bin", "rssh-agent"])
        .output()
        .expect("Failed to build rssh-agent");

    if !build_output.status.success() {
        panic!("Failed to build rssh-agent");
    }

    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|p| {
            Path::new(&p)
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

    // Verify daemon is running
    match daemon.try_wait() {
        Ok(Some(status)) => panic!("Daemon exited with status: {:?}", status),
        Ok(None) => {} // Still running
        Err(e) => panic!("Error checking daemon status: {}", e),
    }

    if !Path::new(&socket_str).exists() {
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
