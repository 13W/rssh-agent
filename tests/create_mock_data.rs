use std::fs;

// SSH Agent Protocol message types
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_EXTENSION: u8 = 27;

fn write_message(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&(data.len() as u32).to_be_bytes());
    result.extend_from_slice(data);
    result
}

fn write_string(s: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&(s.len() as u32).to_be_bytes());
    result.extend_from_slice(s);
    result
}

fn main() -> std::io::Result<()> {
    let mock_dir = "tests/mocks";
    fs::create_dir_all(mock_dir)?;

    // Mock 1: Request identities (empty agent)
    {
        let request = vec![SSH_AGENTC_REQUEST_IDENTITIES];
        let response = vec![
            SSH_AGENT_IDENTITIES_ANSWER,
            0,
            0,
            0,
            0, // 0 keys
        ];

        fs::write(
            format!("{}/01_list_empty.request", mock_dir),
            write_message(&request),
        )?;
        fs::write(
            format!("{}/01_list_empty.response", mock_dir),
            write_message(&response),
        )?;
    }

    // Mock 2: Request identities (one key)
    {
        let request = vec![SSH_AGENTC_REQUEST_IDENTITIES];

        // Sample ED25519 public key blob
        let ed25519_pubkey = vec![
            0, 0, 0, 11, // length of "ssh-ed25519"
            b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32, // length of key data (32 bytes for ed25519)
            // 32 bytes of sample key data
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let comment = b"test-ed25519";

        let mut response = vec![SSH_AGENT_IDENTITIES_ANSWER];
        response.extend_from_slice(&1u32.to_be_bytes()); // 1 key
        response.extend_from_slice(&(ed25519_pubkey.len() as u32).to_be_bytes());
        response.extend_from_slice(&ed25519_pubkey);
        response.extend_from_slice(&(comment.len() as u32).to_be_bytes());
        response.extend_from_slice(comment);

        fs::write(
            format!("{}/02_list_one_key.request", mock_dir),
            write_message(&request),
        )?;
        fs::write(
            format!("{}/02_list_one_key.response", mock_dir),
            write_message(&response),
        )?;
    }

    // Mock 3: Remove all identities
    {
        let request = vec![SSH_AGENTC_REMOVE_ALL_IDENTITIES];
        let response = vec![SSH_AGENT_SUCCESS];

        fs::write(
            format!("{}/03_remove_all.request", mock_dir),
            write_message(&request),
        )?;
        fs::write(
            format!("{}/03_remove_all.response", mock_dir),
            write_message(&response),
        )?;
    }

    // Mock 4: Sign request
    {
        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];

        // Public key blob (same as above)
        let ed25519_pubkey = vec![
            0, 0, 0, 11, // length of "ssh-ed25519"
            b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32, // length of key data
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let data_to_sign = b"test data to sign";

        request.extend_from_slice(&(ed25519_pubkey.len() as u32).to_be_bytes());
        request.extend_from_slice(&ed25519_pubkey);
        request.extend_from_slice(&(data_to_sign.len() as u32).to_be_bytes());
        request.extend_from_slice(data_to_sign);
        request.extend_from_slice(&0u32.to_be_bytes()); // flags

        // Mock signature response
        let mut response = vec![SSH_AGENT_SIGN_RESPONSE];
        let mut signature = vec![
            0, 0, 0, 11, // length of "ssh-ed25519"
            b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            64, // length of signature (64 bytes for ed25519)
        ];
        // Add 64 bytes of mock signature (all 0xaa)
        for _ in 0..64 {
            signature.push(0xaa);
        }
        response.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        response.extend_from_slice(&signature);

        fs::write(
            format!("{}/04_sign_request.request", mock_dir),
            write_message(&request),
        )?;
        fs::write(
            format!("{}/04_sign_request.response", mock_dir),
            write_message(&response),
        )?;
    }

    // Mock 5: Extension request (manage list)
    {
        let mut request = vec![SSH_AGENTC_EXTENSION];
        let ext_name = b"manage@rssh-agent";
        request.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
        request.extend_from_slice(ext_name);

        // CBOR data for list operation
        // This is a simplified mock - actual CBOR would be more complex
        let cbor_data = vec![
            0xa2, 0x62, b'o', b'p', 0x64, b'l', b'i', b's', b't', 0x66, b'p', b'a', b'r', b'a',
            b'm', b's', 0xa0,
        ];
        request.extend_from_slice(&(cbor_data.len() as u32).to_be_bytes());
        request.extend_from_slice(&cbor_data);

        // Mock response with key list
        let response = vec![SSH_AGENT_SUCCESS]; // Simplified response

        fs::write(
            format!("{}/05_extension_list.request", mock_dir),
            write_message(&request),
        )?;
        fs::write(
            format!("{}/05_extension_list.response", mock_dir),
            write_message(&response),
        )?;
    }

    println!("Mock data files created in {}", mock_dir);

    // Create a summary file
    let summary = r#"Mock Data Files
===============

01_list_empty: Request identities when agent is empty
02_list_one_key: Request identities with one ED25519 key
03_remove_all: Remove all identities
04_sign_request: Sign data with ED25519 key
05_extension_list: Extension request for manage list command

Each mock has:
- .request file: The SSH agent protocol request message
- .response file: The expected response message

Message format:
- 4 bytes: message length (big-endian)
- N bytes: message data (first byte is message type)
"#;

    fs::write(format!("{}/README.md", mock_dir), summary)?;

    Ok(())
}
