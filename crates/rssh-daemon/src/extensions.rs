use rssh_core::{Error, Result, ram_store::KeyInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const EXTENSION_NAMESPACE: &str = "rssh-agent@local";

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExtensionResponse {
    Success {
        ok: bool,
        #[serde(flatten)]
        data: HashMap<String, serde_json::Value>,
    },
    Error {
        ok: bool,
        error: ErrorInfo,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorInfo {
    code: String,
    msg: String,
}

#[derive(Debug, Deserialize)]
pub struct ExtensionRequest {
    pub op: String,
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
}

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

    let response = ExtensionResponse::Success {
        ok: true,
        data: {
            let mut data = HashMap::new();
            data.insert(
                "keys".to_string(),
                serde_json::Value::Array(
                    key_list
                        .into_iter()
                        .map(|m| serde_json::Value::Object(m.into_iter().collect()))
                        .collect(),
                ),
            );
            data
        },
    };

    // Serialize to CBOR
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

/// Handle control.shutdown extension
pub fn handle_control_shutdown() -> Result<Vec<u8>> {
    let response = ExtensionResponse::Success {
        ok: true,
        data: HashMap::new(),
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

/// Parse extension request from CBOR data
pub fn parse_extension_request(data: &[u8]) -> Result<ExtensionRequest> {
    // Skip the SSH message type and extension name to get to the CBOR data
    let mut offset = 1; // Skip message type

    // Read extension type string
    let ext_type_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;
    let ext_type = std::str::from_utf8(&data[offset..offset + ext_type_len])
        .map_err(|e| Error::Internal(format!("Invalid extension type: {}", e)))?;
    offset += ext_type_len;

    if ext_type != EXTENSION_NAMESPACE {
        return Err(Error::Internal(format!(
            "Unknown extension namespace: {}",
            ext_type
        )));
    }

    // Read CBOR data length
    let cbor_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    // Parse CBOR
    let cbor_data = &data[offset..offset + cbor_len];
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
