use std::fs;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn test_list_empty_agent() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test with locked agent first (agent starts locked)
    // Read mock request
    let request = read_mock_file("tests/mocks/01_list_empty.request");

    // Send request and get response
    let response = send_request(&socket_path, &request).await;

    // When locked, agent should return FAILURE (5)
    // Response format: [length(4 bytes), SSH_AGENT_FAILURE(1 byte)]
    assert_eq!(
        response,
        vec![0, 0, 0, 1, 5],
        "Expected FAILURE response when locked"
    );

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_lock_unlock_flow() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Agent starts locked, try to list keys
    let list_request = read_mock_file("tests/mocks/01_list_empty.request");
    let response = send_request(&socket_path, &list_request).await;
    assert_eq!(response[4], 5, "Should fail when locked");

    // Try to lock the agent (should fail when already locked)
    let lock_request = build_lock_request();
    let response = send_request(&socket_path, &lock_request).await;
    assert_eq!(response[4], 5, "Lock should fail when already locked"); // SSH_AGENT_FAILURE

    // Try to list keys again (should still fail when locked)
    let response = send_request(&socket_path, &list_request).await;
    assert_eq!(response[4], 5, "Should fail when locked");

    // Note: We can't test unlock without a proper master password setup
    // The daemon requires initialization with a master password

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_add_identity_flow() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Try to add an identity (will fail if locked)
    let add_request = build_add_identity_request();
    let response = send_request(&socket_path, &add_request).await;

    // Should fail when locked
    assert_eq!(response[4], 5, "Add identity should fail when locked");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_extension_requests() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test rssh.manage extension
    let ext_request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&ext_request, &mut cbor_data).unwrap();

    let request = build_extension_request("rssh-agent@local", cbor_data);
    let response = send_request(&socket_path, &request).await;

    // Should get either failure (locked) or extension response
    assert!(
        response[4] == 5 || response[4] == 28 || response[4] == 6,
        "Should get a valid response for extension"
    );

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_remove_all_identities() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Read mock request
    let request = read_mock_file("tests/mocks/03_remove_all.request");

    // Send request and get response
    let response = send_request(&socket_path, &request).await;

    // Agent is locked, so should return FAILURE
    assert_eq!(
        response,
        vec![0, 0, 0, 1, 5], // SSH_AGENT_FAILURE
        "Remove all should fail when locked"
    );

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_sign_request_no_key() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Read mock request
    let request = read_mock_file("tests/mocks/04_sign_request.request");

    // Send request and get response
    let response = send_request(&socket_path, &request).await;

    // Should get a failure response since no key is loaded
    assert_eq!(
        response[4], 5,
        "Expected SSH_AGENT_FAILURE for sign with no key"
    );

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_multiple_requests_sequential() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test multiple requests in sequence (agent is locked)
    let requests = vec![
        read_mock_file("tests/mocks/01_list_empty.request"),
        read_mock_file("tests/mocks/03_remove_all.request"),
        read_mock_file("tests/mocks/01_list_empty.request"),
    ];

    // All should fail with SSH_AGENT_FAILURE when locked
    for request in requests.iter() {
        let response = send_request(&socket_path, request).await;
        assert_eq!(
            response,
            vec![0, 0, 0, 1, 5], // SSH_AGENT_FAILURE
            "All requests should fail when locked"
        );
    }

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_concurrent_requests() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Send multiple requests concurrently
    let socket_path_clone1 = socket_path.clone();
    let socket_path_clone2 = socket_path.clone();

    let request1 = read_mock_file("tests/mocks/01_list_empty.request");
    let request2 = read_mock_file("tests/mocks/03_remove_all.request");

    let handle1 = tokio::spawn(async move { send_request(&socket_path_clone1, &request1).await });

    let handle2 = tokio::spawn(async move { send_request(&socket_path_clone2, &request2).await });

    let response1 = handle1.await.unwrap();
    let response2 = handle2.await.unwrap();

    // Verify both responses are valid (agent is locked, so both should fail)
    assert_eq!(response1[4], 5, "Expected SSH_AGENT_FAILURE (locked)");
    assert_eq!(response2[4], 5, "Expected SSH_AGENT_FAILURE (locked)");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_mock_sign_request() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test sign request from mocks
    let sign_request = read_mock_file("tests/mocks/04_sign_request.request");
    let response = send_request(&socket_path, &sign_request).await;

    // Should fail because agent is locked and has no keys
    assert_eq!(response[4], 5, "Sign should fail without keys");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_list_identities_response_format() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Even when locked, we should get a proper response format
    let list_request = read_mock_file("tests/mocks/01_list_empty.request");
    let response = send_request(&socket_path, &list_request).await;

    // Validate response structure
    assert_eq!(response.len(), 5, "Response should be 5 bytes for failure");
    assert_eq!(&response[0..4], &[0, 0, 0, 1], "Length should be 1");
    assert_eq!(response[4], 5, "Should be SSH_AGENT_FAILURE");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_invalid_message_handling() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Send an invalid message (unknown message type)
    let invalid_request = vec![0, 0, 0, 1, 99]; // 99 is not a valid message type
    let response = send_request(&socket_path, &invalid_request).await;

    // Should return failure
    assert_eq!(response[4], 5, "Invalid message should return failure");

    // Send empty message
    let empty_request = vec![0, 0, 0, 0]; // Empty message
    let response = send_request(&socket_path, &empty_request).await;

    // Should return failure
    assert_eq!(response[4], 5, "Empty message should return failure");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_protocol_compliance() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test that all supported message types from mocks work
    let test_messages = vec![
        ("01_list_empty.request", 5),   // Should fail when locked
        ("03_remove_all.request", 5),   // Should fail when locked
        ("04_sign_request.request", 5), // Should fail when locked
    ];

    for (mock_file, expected_response_type) in test_messages {
        let request = read_mock_file(&format!("tests/mocks/{}", mock_file));
        let response = send_request(&socket_path, &request).await;
        assert_eq!(
            response[4], expected_response_type,
            "Mock {} should return expected response type",
            mock_file
        );
    }

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_extension_cbor_formats() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test different CBOR extension formats
    let extensions = vec![
        ("manage.list", vec![]),
        ("manage.add", vec![1, 2, 3]), // With data
        ("manage.remove", vec![]),
    ];

    for (ext_name, data) in extensions {
        let ext_request = rssh_proto::cbor::ExtensionRequest {
            extension: ext_name.to_string(),
            data: data.clone(),
        };

        let mut cbor_data = Vec::new();
        ciborium::into_writer(&ext_request, &mut cbor_data).unwrap();

        let request = build_extension_request("rssh-agent@local", cbor_data);
        let response = send_request(&socket_path, &request).await;

        // Should get a valid response (failure when locked is OK)
        assert!(
            response.len() >= 5,
            "Extension {} should return valid response",
            ext_name
        );
    }

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_manage_list_operation() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Send manage.list request from mock
    let request = read_mock_file("tests/mocks/06_manage_list.request");
    let response = send_request(&socket_path, &request).await;

    // Agent is locked, so should return failure
    assert_eq!(response[4], 5, "Manage list should fail when locked");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_manage_add_operation() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Send manage.add request from mock
    let request = read_mock_file("tests/mocks/07_manage_add.request");
    let response = send_request(&socket_path, &request).await;

    // Agent is locked, so should return failure
    assert_eq!(response[4], 5, "Manage add should fail when locked");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_manage_remove_operation() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Send manage.remove request from mock
    let request = read_mock_file("tests/mocks/08_manage_remove.request");
    let response = send_request(&socket_path, &request).await;

    // Agent is locked, so should return failure
    assert_eq!(response[4], 5, "Manage remove should fail when locked");

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_manage_extension_parsing() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test that the extension request parses correctly
    // Build a properly formatted manage.list request
    let ext_request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&ext_request, &mut cbor_data).unwrap();

    // Build SSH wire format with extension namespace
    let mut message = vec![27]; // SSH_AGENTC_EXTENSION
    let ext_name = b"rssh-agent@local";
    message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_name);
    message.extend_from_slice(&cbor_data);

    // Add length prefix
    let mut request = Vec::new();
    request.extend_from_slice(&(message.len() as u32).to_be_bytes());
    request.extend_from_slice(&message);

    let response = send_request(&socket_path, &request).await;

    // Should get a response (failure when locked is OK)
    assert!(response.len() >= 5, "Should get a valid response");
    assert!(
        response[4] == 5 || response[4] == 28 || response[4] == 6,
        "Should get SSH_AGENT_FAILURE, SSH_AGENT_EXTENSION_FAILURE, or SSH_AGENT_SUCCESS"
    );

    daemon.kill().expect("Failed to kill daemon");
}

#[tokio::test]
async fn test_manage_cbor_edge_cases() {
    let (mut daemon, socket_path, _temp_dir) = start_test_daemon().await;

    // Test 1: Direct CBOR without SSH wrapper (like TUI might send)
    let ext_request = rssh_proto::cbor::ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_only = Vec::new();
    ciborium::into_writer(&ext_request, &mut cbor_only).unwrap();

    // This should fail because it's missing the SSH protocol wrapper
    let mut malformed_request = Vec::new();
    malformed_request.extend_from_slice(&((cbor_only.len() + 1) as u32).to_be_bytes());
    malformed_request.push(27); // SSH_AGENTC_EXTENSION
    malformed_request.extend_from_slice(&cbor_only);

    let response = send_request(&socket_path, &malformed_request).await;
    assert_eq!(response[4], 5, "Direct CBOR should fail when locked");

    // Test 2: Properly formatted request with namespace
    let proper_request = read_mock_file("tests/mocks/06_manage_list.request");
    let response = send_request(&socket_path, &proper_request).await;
    assert_eq!(response[4], 5, "Should fail when locked");

    // Test 3: Invalid CBOR data
    let mut invalid_cbor = vec![27]; // SSH_AGENTC_EXTENSION
    let ext_name = b"rssh-agent@local";
    invalid_cbor.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
    invalid_cbor.extend_from_slice(ext_name);
    invalid_cbor.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // Invalid CBOR

    let mut invalid_request = Vec::new();
    invalid_request.extend_from_slice(&(invalid_cbor.len() as u32).to_be_bytes());
    invalid_request.extend_from_slice(&invalid_cbor);

    let response = send_request(&socket_path, &invalid_request).await;
    assert_eq!(response[4], 5, "Invalid CBOR should return failure");

    daemon.kill().expect("Failed to kill daemon");
}

// Helper functions

async fn start_test_daemon() -> (Child, String, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();

    // Build the daemon first
    let build_output = Command::new("cargo")
        .args(&["build", "--package", "rssh-cli", "--bin", "rssh-agent"])
        .output()
        .expect("Failed to build rssh-agent");

    if !build_output.status.success() {
        panic!(
            "Failed to build rssh-agent: {}",
            String::from_utf8_lossy(&build_output.stderr)
        );
    }

    // Get the workspace root directory
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

    // Start daemon as subprocess using the built binary
    println!("Starting daemon with binary: {:?}", binary_path);
    println!("Socket path: {}", socket_str);

    if !binary_path.exists() {
        panic!(
            "Binary not found at {:?}. Current dir: {:?}",
            binary_path,
            std::env::current_dir()
        );
    }

    let mut daemon = Command::new(&binary_path)
        .args(&["daemon", "--socket", &socket_str, "--foreground"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start daemon");

    // Give daemon time to start listening
    sleep(Duration::from_secs(3)).await;

    // Check if the daemon is still running
    match daemon.try_wait() {
        Ok(Some(status)) => {
            // Process has exited, read stderr
            let output = daemon
                .wait_with_output()
                .expect("Failed to read daemon output");
            panic!(
                "Daemon exited with status: {:?}\nstdout: {}\nstderr: {}",
                status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(None) => {
            // Still running, good
            println!("Daemon is running");
        }
        Err(e) => panic!("Error checking daemon status: {}", e),
    }

    // Check if socket exists
    if !Path::new(&socket_str).exists() {
        // Kill the daemon and get output
        daemon.kill().ok();
        let output = daemon
            .wait_with_output()
            .expect("Failed to read daemon output");
        panic!(
            "Socket file not created at {}\nstdout: {}\nstderr: {}",
            socket_str,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    (daemon, socket_str, temp_dir)
}

async fn send_request(socket_path: &str, request: &[u8]) -> Vec<u8> {
    println!(
        "Sending request of {} bytes to {}",
        request.len(),
        socket_path
    );

    let result = timeout(Duration::from_secs(5), async {
        let mut stream = match UnixStream::connect(socket_path).await {
            Ok(s) => s,
            Err(e) => panic!("Failed to connect to socket: {}", e),
        };

        println!("Connected to socket, sending request...");

        // Send request
        if let Err(e) = stream.write_all(request).await {
            panic!("Failed to write request: {}", e);
        }

        println!("Request sent, reading response...");

        // Read response length
        let mut len_buf = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut len_buf).await {
            panic!("Failed to read response length: {}", e);
        }

        let response_len = u32::from_be_bytes(len_buf) as usize;
        println!("Response length: {} bytes", response_len);

        // Read response
        let mut response = vec![0u8; response_len];
        if let Err(e) = stream.read_exact(&mut response).await {
            panic!("Failed to read response body: {}", e);
        }

        println!("Response received");

        // Return with length prefix
        let mut full_response = len_buf.to_vec();
        full_response.extend_from_slice(&response);
        full_response
    })
    .await;

    match result {
        Ok(r) => r,
        Err(_) => {
            // Check if daemon is still running
            println!("Checking if daemon is still alive...");
            if Path::new(socket_path).exists() {
                println!("Socket still exists");
            } else {
                println!("Socket no longer exists!");
            }
            panic!("Request timed out after 5 seconds");
        }
    }
}

fn read_mock_file(path: &str) -> Vec<u8> {
    let full_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read(&full_path).unwrap_or_else(|e| {
        panic!("Failed to read mock file {:?}: {}", full_path, e);
    })
}

fn build_lock_request() -> Vec<u8> {
    let mut message = vec![22]; // SSH_AGENTC_LOCK
    // Add dummy password (OpenSSH ignores it anyway)
    let password = b"dummy";
    message.extend_from_slice(&(password.len() as u32).to_be_bytes());
    message.extend_from_slice(password);

    // Add length prefix
    let mut request = Vec::new();
    request.extend_from_slice(&(message.len() as u32).to_be_bytes());
    request.extend_from_slice(&message);
    request
}

fn build_add_identity_request() -> Vec<u8> {
    // Create a test Ed25519 key
    let mut message = vec![17]; // SSH_AGENTC_ADD_IDENTITY

    // Key type
    let key_type = b"ssh-ed25519";
    message.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    message.extend_from_slice(key_type);

    // Public key (32 bytes for Ed25519)
    let public_key = vec![1u8; 32];
    message.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    message.extend_from_slice(&public_key);

    // Private key (64 bytes for Ed25519)
    let private_key = vec![2u8; 64];
    message.extend_from_slice(&(private_key.len() as u32).to_be_bytes());
    message.extend_from_slice(&private_key);

    // Comment
    let comment = b"test-ed25519-key";
    message.extend_from_slice(&(comment.len() as u32).to_be_bytes());
    message.extend_from_slice(comment);

    // Add length prefix
    let mut request = Vec::new();
    request.extend_from_slice(&(message.len() as u32).to_be_bytes());
    request.extend_from_slice(&message);
    request
}

fn build_extension_request(extension_name: &str, data: Vec<u8>) -> Vec<u8> {
    let mut message = vec![27]; // SSH_AGENTC_EXTENSION

    // Extension name
    message.extend_from_slice(&(extension_name.len() as u32).to_be_bytes());
    message.extend_from_slice(extension_name.as_bytes());

    // Extension data
    message.extend_from_slice(&data);

    // Add length prefix
    let mut request = Vec::new();
    request.extend_from_slice(&(message.len() as u32).to_be_bytes());
    request.extend_from_slice(&message);
    request
}
