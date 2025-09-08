use rssh_core::{Error, Result, ram_store::KeyInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const EXTENSION_NAMESPACE: &str = "rssh-agent@local";

// Use the ExtensionRequest from rssh_proto::cbor
pub use rssh_proto::cbor::ExtensionRequest;

// Removed: Now using rssh_proto::cbor::ExtensionResponse
// pub enum ExtensionResponse { ... }

// Removed: No longer needed
// pub struct ErrorInfo { ... }

/// Handle manage.list extension
pub fn handle_manage_list(keys: Vec<KeyInfo>) -> Result<Vec<u8>> {
    let key_list: Vec<HashMap<String, serde_json::Value>> = keys
        .into_iter()
        .map(|key| {
            let mut map = HashMap::new();
            map.insert(
                "fp_sha256_hex".to_string(),
                serde_json::Value::String(key.fingerprint),
            );
            map.insert("type".to_string(), serde_json::Value::String(key.key_type));
            map.insert(
                "description".to_string(),
                serde_json::Value::String(key.description),
            );
            map.insert(
                "source".to_string(),
                serde_json::Value::String("internal".to_string()),
            );
            map.insert("loaded".to_string(), serde_json::Value::Bool(true));
            map.insert("has_disk".to_string(), serde_json::Value::Bool(true));
            map.insert(
                "has_cert".to_string(),
                serde_json::Value::Bool(key.has_cert),
            );

            // Add constraints
            let mut constraints = HashMap::new();
            constraints.insert("confirm".to_string(), serde_json::Value::Bool(key.confirm));
            constraints.insert("lifetime_expires_at".to_string(), serde_json::Value::Null);
            map.insert(
                "constraints".to_string(),
                serde_json::Value::Object(constraints.into_iter().map(|(k, v)| (k, v)).collect()),
            );

            map.insert("created".to_string(), serde_json::Value::Null);
            map.insert("updated".to_string(), serde_json::Value::Null);

            map
        })
        .collect();

    // Create response matching rssh_proto::cbor::ExtensionResponse structure
    let response_data = serde_json::json!({
        "ok": true,
        "keys": key_list
    });

    // Convert to CBOR bytes for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response_data, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse that TUI expects
    let response = rssh_proto::cbor::ExtensionResponse {
        success: true,
        data: data_cbor,
    };

    // Serialize the whole response to CBOR
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

/// Handle control.shutdown extension
pub fn handle_control_shutdown() -> Result<Vec<u8>> {
    // Create response matching rssh_proto::cbor::ExtensionResponse structure
    let response_data = serde_json::json!({
        "ok": true
    });

    // Convert to CBOR bytes for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response_data, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse that TUI expects
    let response = rssh_proto::cbor::ExtensionResponse {
        success: true,
        data: data_cbor,
    };

    // Serialize the whole response to CBOR
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

/// Parse extension request from SSH agent message
pub fn parse_extension_request(data: &[u8]) -> Result<ExtensionRequest> {
    // Debug: log the raw data
    tracing::debug!(
        "Extension request raw data (len={}): {:02x?}",
        data.len(),
        &data[..data.len().min(50)]
    );

    // The message format according to OpenSSH protocol is:
    // byte SSH_AGENTC_EXTENSION (27) - already consumed by caller
    // string extension-name
    // ... extension-specific data (CBOR in our case)

    // Note: The message type (27) has already been consumed by the agent,
    // so data[0] is the first byte of the actual extension message.

    // Check if this looks like direct CBOR (starts with CBOR map marker 0xA0-0xBF)
    // This might happen if TUI sends CBOR directly
    if data.len() > 0 && data[0] >= 0xA0 && data[0] <= 0xBF {
        tracing::debug!("Detected direct CBOR data (marker: 0x{:02x})", data[0]);
        let request: ExtensionRequest = ciborium::from_reader(data)
            .map_err(|e| Error::Internal(format!("CBOR decoding error: {}", e)))?;
        return Ok(request);
    }

    // Parse as SSH wire protocol with extension name
    let mut offset = 0;

    // Skip the message type byte if present
    if data.len() > 0 && data[0] == 27 {
        tracing::debug!("Skipping message type byte (27)");
        offset = 1;
    }

    // Ensure we have enough data for the extension name length field
    if data.len() < offset + 4 {
        return Err(Error::Internal(format!(
            "Insufficient data for extension name length: {} bytes available",
            data.len() - offset
        )));
    }

    // Read extension name string length
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

    // Validate extension name length
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

    if ext_name != EXTENSION_NAMESPACE {
        return Err(Error::Internal(format!(
            "Unknown extension namespace: {}",
            ext_name
        )));
    }

    // The rest is CBOR data
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

/// Build extension response message
pub fn build_extension_response(cbor_data: Vec<u8>) -> Vec<u8> {
    use rssh_proto::wire;

    let mut response = Vec::new();
    response.push(rssh_proto::wire::MessageType::Success as u8);
    wire::write_string(&mut response, cbor_data.as_slice());
    response
}
