use rssh_daemon::extensions;
use rssh_proto::cbor::ExtensionRequest;
use rssh_proto::messages::{SSH_AGENT_FAILURE, SSH_AGENTC_EXTENSION};
use tempfile::tempdir;

#[test]
fn test_extension_request_parsing_direct_cbor() {
    // Test parsing direct CBOR (as sent by TUI)
    let request = ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data).unwrap();

    // This should parse successfully as direct CBOR
    let parsed = extensions::parse_extension_request(&cbor_data);
    assert!(parsed.is_ok());
    let parsed = parsed.unwrap();
    assert_eq!(parsed.extension, "manage.list");
}

#[test]
fn test_extension_request_parsing_with_ssh_wrapper() {
    // Test parsing with SSH wire protocol wrapper
    let request = ExtensionRequest {
        extension: "manage.list".to_string(),
        data: vec![],
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&request, &mut cbor_data).unwrap();

    // Build SSH wire format: message_type + extension_name_len + extension_name + cbor
    let mut message = Vec::new();
    message.push(SSH_AGENTC_EXTENSION); // Message type (will be skipped)

    let ext_name = extensions::EXTENSION_NAMESPACE;
    message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
    message.extend_from_slice(ext_name.as_bytes());
    message.extend_from_slice(&cbor_data);

    // Skip the message type byte when parsing
    let parsed = extensions::parse_extension_request(&message[1..]);
    assert!(parsed.is_ok());
    let parsed = parsed.unwrap();
    assert_eq!(parsed.extension, "manage.list");
}

#[test]
fn test_extension_response_building() {
    let test_data = vec![1, 2, 3, 4];
    let response = extensions::build_extension_response(test_data.clone());

    // Response should be: message_type + length-prefixed data
    // The function uses MessageType::Success (6) not SSH_AGENT_EXTENSION_RESPONSE
    assert_eq!(response[0], rssh_proto::messages::SSH_AGENT_SUCCESS);

    // The rest is wire-encoded string (length + data)
    let data_len =
        u32::from_be_bytes([response[1], response[2], response[3], response[4]]) as usize;
    assert_eq!(data_len, test_data.len());
    assert_eq!(&response[5..5 + data_len], &test_data[..]);
}

#[test]
fn test_manage_list_handler() {
    use rssh_core::ram_store::KeyInfo;

    let keys = vec![KeyInfo {
        fingerprint: "SHA256:test1".to_string(),
        key_type: "ssh-ed25519".to_string(),
        description: "Test key 1".to_string(),
        has_cert: false,
        confirm: false,
        lifetime_expires_at: None,
        is_external: false,
    }];

    let result = extensions::handle_manage_list(keys, None);
    assert!(result.is_ok());

    let cbor_data = result.unwrap();
    assert!(!cbor_data.is_empty());

    // Parse the response to verify structure - it's now an ExtensionResponse
    let response: rssh_proto::cbor::ExtensionResponse =
        ciborium::from_reader(&cbor_data[..]).unwrap();
    assert!(response.success, "Response should indicate success");

    // Parse the data field which contains the actual response
    let data: serde_json::Value = ciborium::from_reader(&response.data[..]).unwrap();
    assert!(data.get("ok").is_some());
    assert!(data.get("keys").is_some());
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use rssh_daemon::agent::Agent;
    use rssh_daemon::socket::SocketServer;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_manage_list_via_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream as TokioUnixStream;

        // Create a temporary directory for the socket
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Create and start the agent
        let agent = Arc::new(Agent::new());
        let server = SocketServer::new(socket_path.clone(), agent.clone());

        // Start the server in a background task
        let server_handle = tokio::spawn(async move { server.run().await });

        // Give the server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test the connection with timeout
        let test_result = timeout(Duration::from_secs(5), async {
            // Connect to the socket using async TokioUnixStream
            let mut stream = TokioUnixStream::connect(&socket_path).await.unwrap();

            // Build a manage.list request
            let request = ExtensionRequest {
                extension: "manage.list".to_string(),
                data: vec![],
            };

            let mut cbor_data = Vec::new();
            ciborium::into_writer(&request, &mut cbor_data).unwrap();

            // Build SSH protocol message
            let mut message = Vec::new();
            message.extend_from_slice(&(cbor_data.len() as u32 + 1).to_be_bytes());
            message.push(SSH_AGENTC_EXTENSION);
            message.extend_from_slice(&cbor_data);

            // Send the request
            stream.write_all(&message).await.unwrap();

            // Read the response
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;

            let mut response = vec![0u8; len];
            stream.read_exact(&mut response).await.unwrap();

            // The agent is locked by default, so we expect a failure
            // But the important thing is that it doesn't panic
            assert!(response[0] == SSH_AGENT_FAILURE || response[0] == 28);
        })
        .await;

        // Ensure test completed within timeout
        assert!(test_result.is_ok(), "Test timed out");

        // Clean up - abort the server task
        server_handle.abort();
        // Wait a bit for cleanup
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[test]
    fn test_cbor_serialization_compatibility() {
        // Test that our CBOR structures are compatible
        let request = ExtensionRequest {
            extension: "manage.list".to_string(),
            data: vec![],
        };

        // Serialize
        let mut buffer = Vec::new();
        ciborium::into_writer(&request, &mut buffer).unwrap();

        // Deserialize
        let deserialized: ExtensionRequest = ciborium::from_reader(&buffer[..]).unwrap();
        assert_eq!(deserialized.extension, "manage.list");
        assert_eq!(deserialized.data, Vec::<u8>::new());
    }

    #[test]
    fn test_error_response_format() {
        // Test error response using the rssh_proto::cbor::ExtensionResponse format
        let error_data = serde_json::json!({
            "ok": false,
            "error": {
                "code": "test_error",
                "msg": "Test error message"
            }
        });

        let mut error_cbor = Vec::new();
        ciborium::into_writer(&error_data, &mut error_cbor).unwrap();

        let error_response = rssh_proto::cbor::ExtensionResponse {
            success: false,
            data: error_cbor,
        };

        // Serialize
        let mut buffer = Vec::new();
        ciborium::into_writer(&error_response, &mut buffer).unwrap();

        // Deserialize and verify
        let deserialized: rssh_proto::cbor::ExtensionResponse =
            ciborium::from_reader(&buffer[..]).unwrap();
        assert_eq!(deserialized.success, false);

        // Verify error data
        let data: serde_json::Value = ciborium::from_reader(&deserialized.data[..]).unwrap();
        assert_eq!(data["ok"], false);
        assert_eq!(data["error"]["code"], "test_error");
        assert_eq!(data["error"]["msg"], "Test error message");
    }
}
