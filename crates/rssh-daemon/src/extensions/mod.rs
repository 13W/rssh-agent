use rssh_core::{Error, Result};

pub const EXTENSION_NAMESPACE: &str = "rssh-agent@local";

pub use rssh_proto::cbor::ExtensionRequest;

mod control;
mod constraints;
mod import;
mod keys;

pub use control::{handle_control_shutdown, handle_session_bind};
pub use constraints::{
    handle_manage_set_constraints, handle_manage_set_default_constraints, handle_manage_set_desc,
    handle_manage_update_cert,
};
pub use import::{handle_manage_import, handle_manage_import_direct, handle_manage_set_password};
pub use keys::{
    handle_manage_create, handle_manage_delete, handle_manage_list, handle_manage_load,
    handle_manage_unload,
};

/// Wrap a JSON success payload into a CBOR-encoded `ExtensionResponse { success: true, data }`.
/// Eliminates the 14-line serialization boilerplate repeated across all success handlers.
fn cbor_success(data: serde_json::Value) -> Result<Vec<u8>> {
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&data, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    let response = rssh_proto::cbor::ExtensionResponse {
        success: true,
        data: data_cbor,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

/// Build an error response in CBOR format
pub fn build_error_response(error: Error) -> Result<Vec<u8>> {
    let error_code = match error {
        Error::NotExternal => "not_external",
        Error::AlreadyExists => "already_exists",
        Error::NotFound => "not_found",
        Error::NeedMasterUnlock => "need_master_unlock",
        _ => "internal",
    };

    let response_data = serde_json::json!({
        "ok": false,
        "error": {
            "code": error_code,
            "msg": error.to_string()
        }
    });

    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response_data, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    let response = rssh_proto::cbor::ExtensionResponse {
        success: false,
        data: data_cbor,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

pub fn parse_extension_request(data: &[u8]) -> Result<ExtensionRequest> {
    tracing::debug!(
        "Extension request raw data (len={}): {:02x?}",
        data.len(),
        &data[..data.len().min(50)]
    );

    // Check if this looks like direct CBOR (starts with CBOR map marker 0xA0-0xBF)
    if !data.is_empty() && data[0] >= 0xA0 && data[0] <= 0xBF {
        tracing::debug!("Detected direct CBOR data (marker: 0x{:02x})", data[0]);
        let request: ExtensionRequest = ciborium::from_reader(data)
            .map_err(|e| Error::Internal(format!("CBOR decoding error: {}", e)))?;
        return Ok(request);
    }

    let mut offset = 0;

    // Skip the message type byte if present
    if !data.is_empty() && data[0] == 27 {
        tracing::debug!("Skipping message type byte (27)");
        offset = 1;
    }

    if data.len() < offset + 4 {
        return Err(Error::Internal(format!(
            "Insufficient data for extension name length: {} bytes available",
            data.len() - offset
        )));
    }

    let ext_name_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    tracing::debug!(
        "Extension name length: {} (0x{:08x})",
        ext_name_len,
        ext_name_len
    );

    if ext_name_len > data.len() - offset {
        // Maybe this is direct CBOR after all, try parsing it
        tracing::debug!("Extension name length invalid, trying direct CBOR parse");
        let request: ExtensionRequest = ciborium::from_reader(data)
            .map_err(|e| Error::Internal(format!("CBOR decoding error: {}", e)))?;
        return Ok(request);
    }

    if ext_name_len > 256 {
        return Err(Error::Internal(format!(
            "Extension name too long: {} bytes",
            ext_name_len
        )));
    }

    let ext_name = std::str::from_utf8(&data[offset..offset + ext_name_len])
        .map_err(|e| Error::Internal(format!("Invalid extension name UTF-8: {}", e)))?;
    offset += ext_name_len;

    tracing::debug!("Extension name: {}", ext_name);

    match ext_name {
        EXTENSION_NAMESPACE => {
            let cbor_data = &data[offset..];
            tracing::debug!(
                "CBOR data (len={}): {:02x?}",
                cbor_data.len(),
                &cbor_data[..cbor_data.len().min(50)]
            );

            let request: ExtensionRequest = ciborium::from_reader(cbor_data)
                .map_err(|e| Error::Internal(format!("CBOR decoding error: {}", e)))?;

            Ok(request)
        }
        "session-bind@openssh.com" => {
            tracing::debug!("Handling OpenSSH session-bind extension");
            Ok(ExtensionRequest {
                extension: ext_name.to_string(),
                data: data[offset..].to_vec(),
            })
        }
        _ => {
            tracing::debug!("Received unknown OpenSSH extension: {}", ext_name);
            Ok(ExtensionRequest {
                extension: ext_name.to_string(),
                data: data[offset..].to_vec(),
            })
        }
    }
}

/// Build extension response message
pub fn build_extension_response(cbor_data: Vec<u8>) -> Vec<u8> {
    use rssh_proto::wire;

    let mut response = Vec::new();
    response.push(rssh_proto::wire::MessageType::Success as u8);
    wire::write_string(&mut response, cbor_data.as_slice());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct SetDescRequest {
        fp_sha256_hex: String,
        description: String,
    }

    #[test]
    fn test_set_desc_request_parsing() {
        let request = SetDescRequest {
            fp_sha256_hex: "abcd1234".to_string(),
            description: "Test description".to_string(),
        };

        let mut cbor_data = Vec::new();
        ciborium::into_writer(&request, &mut cbor_data).unwrap();

        let parsed: SetDescRequest = ciborium::from_reader(cbor_data.as_slice()).unwrap();

        assert_eq!(parsed.fp_sha256_hex, "abcd1234");
        assert_eq!(parsed.description, "Test description");
    }

    #[test]
    fn test_description_validation() {
        use rssh_core::keyfile::validate_description;

        assert!(validate_description("Valid description").is_ok());
        assert!(validate_description("A").is_ok());
        assert!(validate_description(&"x".repeat(256)).is_ok());

        assert!(validate_description("").is_err());
        assert!(validate_description(&"x".repeat(257)).is_err());
        assert!(validate_description("Contains\0null").is_err());
        assert!(validate_description("Contains\rcarriage").is_err());
        assert!(validate_description("Contains\nnewline").is_err());
    }

    #[test]
    fn test_session_bind_extension_parsing() {
        let ext_name = "session-bind@openssh.com";
        let hostkey = b"test hostkey data";
        let session_id = b"test session identifier";
        let signature = b"test signature";
        let is_forwarding = true;

        let mut data = Vec::new();
        data.extend_from_slice(&(hostkey.len() as u32).to_be_bytes());
        data.extend_from_slice(hostkey);
        data.extend_from_slice(&(session_id.len() as u32).to_be_bytes());
        data.extend_from_slice(session_id);
        data.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        data.extend_from_slice(signature);
        data.push(if is_forwarding { 1 } else { 0 });

        let mut message = Vec::new();
        message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
        message.extend_from_slice(ext_name.as_bytes());
        message.extend_from_slice(&data);

        let request = parse_extension_request(&message).unwrap();
        assert_eq!(request.extension, "session-bind@openssh.com");
        assert_eq!(request.data, data);
    }

    #[test]
    fn test_session_bind_handler() {
        let hostkey = b"test hostkey data";
        let session_id = b"test session identifier";
        let signature = b"test signature";
        let is_forwarding = false;

        let mut data = Vec::new();
        data.extend_from_slice(&(hostkey.len() as u32).to_be_bytes());
        data.extend_from_slice(hostkey);
        data.extend_from_slice(&(session_id.len() as u32).to_be_bytes());
        data.extend_from_slice(session_id);
        data.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        data.extend_from_slice(signature);
        data.push(if is_forwarding { 1 } else { 0 });

        let response = handle_session_bind(&data).unwrap();

        // Returns failure because session-bind is not yet implemented
        assert_eq!(response.len(), 1);
        assert_eq!(response[0], rssh_proto::wire::MessageType::Failure as u8);
    }

    #[test]
    fn test_session_bind_insufficient_data() {
        let insufficient_data = vec![0, 0, 0];

        let response = handle_session_bind(&insufficient_data).unwrap();

        assert_eq!(response.len(), 1);
        assert_eq!(response[0], rssh_proto::wire::MessageType::Failure as u8);
    }

    #[test]
    fn test_unknown_openssh_extension() {
        let ext_name = "unknown-ext@openssh.com";
        let data = b"some extension data";

        let mut message = Vec::new();
        message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
        message.extend_from_slice(ext_name.as_bytes());
        message.extend_from_slice(data);

        let request = parse_extension_request(&message).unwrap();
        assert_eq!(request.extension, "unknown-ext@openssh.com");
        assert_eq!(request.data, data);
    }

    #[test]
    fn test_manage_delete_request_parsing() {
        use rssh_proto::cbor::{ManageDeleteRequest, ManageDeleteResponse};

        let request = ManageDeleteRequest {
            fp_sha256_hex: "1234567890abcdef".to_string(),
        };

        let mut cbor_data = Vec::new();
        ciborium::into_writer(&request, &mut cbor_data).unwrap();

        let parsed: ManageDeleteRequest = ciborium::from_reader(cbor_data.as_slice()).unwrap();
        assert_eq!(parsed.fp_sha256_hex, "1234567890abcdef");

        let response = ManageDeleteResponse {
            ok: true,
            error: None,
            fingerprint: Some("1234567890abcdef".to_string()),
        };

        let mut response_cbor = Vec::new();
        ciborium::into_writer(&response, &mut response_cbor).unwrap();

        let parsed_response: ManageDeleteResponse =
            ciborium::from_reader(response_cbor.as_slice()).unwrap();
        assert!(parsed_response.ok);
        assert!(parsed_response.error.is_none());
        assert_eq!(
            parsed_response.fingerprint,
            Some("1234567890abcdef".to_string())
        );
    }
}
