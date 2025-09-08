use rssh_core::{Error, Result, ram_store::KeyInfo};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;

pub const EXTENSION_NAMESPACE: &str = "rssh-agent@local";

// Use the ExtensionRequest from rssh_proto::cbor
pub use rssh_proto::cbor::ExtensionRequest;

// Removed: Now using rssh_proto::cbor::ExtensionResponse
// pub enum ExtensionResponse { ... }

// Removed: No longer needed
// pub struct ErrorInfo { ... }

/// Handle manage.list extension
pub fn handle_manage_list(ram_keys: Vec<KeyInfo>, storage_dir: Option<&str>) -> Result<Vec<u8>> {
    use chrono::Utc;
    use rssh_proto::cbor::{ManageListResponse, ManagedKey};

    // Collect fingerprints of loaded keys
    let loaded_fingerprints: HashSet<String> =
        ram_keys.iter().map(|k| k.fingerprint.clone()).collect();

    // Convert RAM keys to ManagedKey format
    let mut managed_keys: Vec<ManagedKey> = ram_keys
        .into_iter()
        .map(|key| {
            // Determine format based on key type
            let format = match key.key_type.as_str() {
                "ed25519" => "ssh-ed25519",
                "rsa" => "rsa-sha2-512",
                _ => &key.key_type,
            }.to_string();

            // Build constraints object
            let constraints = serde_json::json!({
                "confirm": key.confirm,
                "lifetime_expires_at": key.lifetime_expires_at.map(|t| {
                    // Convert Instant to ISO 8601 string
                    let duration = t.duration_since(std::time::Instant::now());
                    let expires_at = Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64);
                    expires_at.to_rfc3339()
                }),
            });

            ManagedKey {
                fp_sha256_hex: key.fingerprint.clone(),
                key_type: key.key_type,
                format,
                description: key.description,
                source: if key.is_external { "external".to_string() } else { "internal".to_string() },
                loaded: true,  // These are all loaded in RAM
                has_disk: !key.is_external,  // Internal keys have disk entries
                has_cert: key.has_cert,
                constraints,
                created: None,  // TODO: Track creation time
                updated: None,  // TODO: Track update time
            }
        })
        .collect();

    // Add disk keys that are not loaded
    if let Some(dir) = storage_dir {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    // Check if it's a key file (sha256-*.json)
                    if file_name.starts_with("sha256-") && file_name.ends_with(".json") {
                        // Extract fingerprint from filename
                        let fingerprint = file_name
                            .strip_prefix("sha256-")
                            .and_then(|s| s.strip_suffix(".json"))
                            .unwrap_or("")
                            .to_string();

                        // Skip if this key is already loaded
                        if loaded_fingerprints.contains(&fingerprint) {
                            continue;
                        }

                        // Try to read basic info from the file without decrypting
                        // For now, we'll add a placeholder entry
                        // In a real implementation, we might store metadata unencrypted
                        managed_keys.push(ManagedKey {
                            fp_sha256_hex: fingerprint,
                            key_type: "unknown".to_string(), // Can't determine without decrypting
                            format: "unknown".to_string(),
                            description: "".to_string(), // Can't get without decrypting
                            source: "internal".to_string(), // Disk keys are internal
                            loaded: false,               // Not loaded in RAM
                            has_disk: true,              // Obviously on disk
                            has_cert: false,             // Can't determine without decrypting
                            constraints: serde_json::json!({
                                "confirm": false,
                                "lifetime_expires_at": null,
                            }),
                            created: None,
                            updated: None,
                        });
                    }
                }
            }
        }
    }

    // Create ManageListResponse
    let list_response = ManageListResponse {
        ok: true,
        keys: managed_keys,
    };

    // Serialize response to CBOR for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&list_response, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse wrapper
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

/// Handle manage.import extension - imports an external key to persistent storage
pub async fn handle_manage_import(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use chrono::Utc;
    use rssh_core::keyfile::{KeyFile, KeyPayload, KeyType};

    #[derive(Debug, Deserialize)]
    struct ImportRequest {
        fp_sha256_hex: String,
        description: Option<String>,
        set_key_password: bool,
        new_key_pass_b64: Option<String>,
    }

    // Parse the CBOR request data
    let request: ImportRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse import request: {}", e)))?;

    // Get the external key data
    let key_data = ram_store.get_external_key_data(&request.fp_sha256_hex)?;

    // Get key info for description and type
    let keys = ram_store.list_keys()?;
    let key_info = keys
        .iter()
        .find(|k| k.fingerprint == request.fp_sha256_hex)
        .ok_or(Error::NotFound)?;

    // Use provided description or keep the existing one
    let description = request
        .description
        .unwrap_or_else(|| key_info.description.clone());

    // Determine key type from key_info
    let key_type = match key_info.key_type.as_str() {
        "ed25519" => KeyType::Ed25519,
        "rsa" => KeyType::Rsa,
        _ => {
            return Err(Error::Internal(format!(
                "Unknown key type: {}",
                key_info.key_type
            )));
        }
    };

    // Convert wire format key data to OpenSSH format
    // The key_data is already in the wire format that can be stored
    // For now, we'll store it as base64-encoded openssh-key-v1
    let secret_openssh_b64 = BASE64.encode(&key_data);

    // Create KeyPayload
    let now = Utc::now();
    let payload = KeyPayload {
        key_type,
        description,
        secret_openssh_b64,
        cert_openssh_b64: None, // TODO: Handle certificates if present
        created: now,
        updated: now,
    };

    // Get storage directory from environment or use default
    let storage_dir = std::env::var("RSSH_STORAGE_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.ssh/rssh-agent", home)
    });

    // For now, use a default master password
    // In production, this should be obtained from the config or prompt
    let master_password = "master_password"; // TODO: Get actual master password

    // Write key file to disk
    KeyFile::write(
        &storage_dir,
        &request.fp_sha256_hex,
        &payload,
        master_password,
    )?;

    // Mark the key as internal now that it's been imported
    ram_store.mark_key_as_internal(&request.fp_sha256_hex)?;

    // Create success response
    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": request.fp_sha256_hex
    });

    // Convert to CBOR bytes for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response_data, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse
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

/// Handle manage.load extension - loads a key from disk to RAM
pub async fn handle_manage_load(
    data: &[u8],
    _ram_store: &rssh_core::ram_store::RamStore,
    storage_dir: Option<&str>,
) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rssh_core::keyfile::KeyFile;

    #[derive(Debug, Deserialize)]
    struct LoadRequest {
        fp_sha256_hex: String,
        key_pass_b64: Option<String>,
    }

    // Parse the CBOR request data
    let request: LoadRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse load request: {}", e)))?;

    // Get storage directory
    let storage_dir = storage_dir
        .ok_or_else(|| Error::Internal("Storage directory not configured".to_string()))?;

    // For now, use a default master password
    // TODO: In production, this should be obtained from the config
    let master_password = "master_password";

    // Read the key file from disk
    let _key_payload = KeyFile::read(storage_dir, &request.fp_sha256_hex, master_password)?;

    // Decode the key passphrase if provided
    let _key_passphrase = request
        .key_pass_b64
        .as_ref()
        .map(|b64| BASE64.decode(b64))
        .transpose()
        .map_err(|e| Error::Internal(format!("Invalid base64 in key_pass_b64: {}", e)))?;

    // TODO: Load the key into RAM store
    // For now, just return success
    // ram_store.load_from_disk(&request.fp_sha256_hex, key_payload, key_passphrase)?;

    // Create success response
    let response_data = serde_json::json!({
        "ok": true,
    });

    // Convert to CBOR bytes for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response_data, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse
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

    // Convert to CBOR bytes for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response_data, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse
    let response = rssh_proto::cbor::ExtensionResponse {
        success: false,
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
