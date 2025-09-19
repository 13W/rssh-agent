use rssh_core::{Error, Result, ram_store::KeyInfo};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use ssh_key::rand_core::OsRng;

pub const EXTENSION_NAMESPACE: &str = "rssh-agent@local";

/// Helper function to wrap a ManageOperationResponse in ExtensionResponse
fn wrap_manage_operation_response(
    response: rssh_proto::cbor::ManageOperationResponse,
) -> Result<Vec<u8>> {
    // Convert to CBOR bytes for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse wrapper
    let extension_response = rssh_proto::cbor::ExtensionResponse {
        success: response.ok,
        data: data_cbor,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&extension_response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

/// Helper function to wrap a ManageCreateResponse in ExtensionResponse
fn wrap_manage_create_response(
    response: rssh_proto::cbor::ManageCreateResponse,
) -> Result<Vec<u8>> {
    // Convert to CBOR bytes for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse wrapper
    let extension_response = rssh_proto::cbor::ExtensionResponse {
        success: response.ok,
        data: data_cbor,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&extension_response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

/// Helper function to wrap a ManageDeleteResponse in ExtensionResponse
fn wrap_manage_delete_response(
    response: rssh_proto::cbor::ManageDeleteResponse,
) -> Result<Vec<u8>> {
    // Convert to CBOR bytes for the data field
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Create the ExtensionResponse wrapper
    let extension_response = rssh_proto::cbor::ExtensionResponse {
        success: response.ok,
        data: data_cbor,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&extension_response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

// Use the ExtensionRequest from rssh_proto::cbor
pub use rssh_proto::cbor::ExtensionRequest;

// Removed: Now using rssh_proto::cbor::ExtensionResponse
// pub enum ExtensionResponse { ... }

// Removed: No longer needed
// pub struct ErrorInfo { ... }

/// Handle manage.list extension
pub fn handle_manage_list(
    ram_keys: Vec<KeyInfo>,
    storage_dir: Option<&str>,
    master_password: Option<&str>,
) -> Result<Vec<u8>> {
    use chrono::Utc;
    use rssh_core::keyfile::KeyFile;
    use rssh_proto::cbor::{ManageListResponse, ManagedKey};

    // Collect fingerprints of loaded keys
    let loaded_fingerprints: HashSet<String> =
        ram_keys.iter().map(|k| k.fingerprint.clone()).collect();

    // Build a set of fingerprints that exist on disk
    let mut disk_fingerprints: HashSet<String> = HashSet::new();
    if let Some(dir) = storage_dir
        && let Ok(entries) = fs::read_dir(dir)
    {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string()
                && file_name.starts_with("sha256-")
                && file_name.ends_with(".json")
            {
                let fingerprint = file_name
                    .strip_prefix("sha256-")
                    .and_then(|s| s.strip_suffix(".json"))
                    .unwrap_or("")
                    .to_string();
                disk_fingerprints.insert(fingerprint);
            }
        }
    }

    // Convert RAM keys to ManagedKey format
    // Convert RAM keys to ManagedKey format
    let mut managed_keys: Vec<ManagedKey> = ram_keys
        .into_iter()
        .map(|key| {
            // Check if key exists on disk to determine correct source
            let key_on_disk = disk_fingerprints.contains(&key.fingerprint);

            // If key exists on disk, it's internal regardless of how it was loaded
            let is_internal = key_on_disk || !key.is_external;

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

            // For loaded keys that exist on disk, check if they were originally password-protected
            let originally_password_protected = if key_on_disk {
                if let (Some(dir), Some(master_pwd)) = (storage_dir, master_password) {
                    // Try to read metadata to check if key was originally password-protected
                    match KeyFile::read_metadata(dir, &key.fingerprint, master_pwd) {
                        Ok(metadata) => metadata.password_protected,
                        Err(_) => false, // If we can't read metadata, assume not protected
                    }
                } else {
                    false // No master password available, can't determine
                }
            } else {
                false // External keys are not password-protected
            };

            ManagedKey {
                fp_sha256_hex: key.fingerprint.clone(),
                key_type: key.key_type,
                format,
                description: key.description,
                source: if is_internal { "internal".to_string() } else { "external".to_string() },
                loaded: true,  // These are all loaded in RAM
                has_disk: key_on_disk,  // True if key exists on disk
                has_cert: key.has_cert,
                password_protected: originally_password_protected,  // Check if originally protected
                constraints,
                created: Some(key.created.to_rfc3339()),  // Use actual creation time
                updated: key.updated.map(|t| t.to_rfc3339()),  // Use actual update time
            }
        })
        .collect();

    // Add disk keys that are not loaded
    for fingerprint in disk_fingerprints {
        // Skip if this key is already loaded
        if loaded_fingerprints.contains(&fingerprint) {
            continue;
        }

        // Try to read metadata from the key file if master password is available
        if let (Some(dir), Some(master_pwd)) = (storage_dir, master_password) {
            match KeyFile::read_metadata(dir, &fingerprint, master_pwd) {
                Ok(metadata) => {
                    // Successfully read metadata, use real data
                    let key_type_str = match metadata.key_type {
                        rssh_core::keyfile::KeyType::Ed25519 => "ed25519",
                        rssh_core::keyfile::KeyType::Rsa => "rsa",
                    }
                    .to_string();

                    let format = match metadata.key_type {
                        rssh_core::keyfile::KeyType::Ed25519 => "ssh-ed25519",
                        rssh_core::keyfile::KeyType::Rsa => "rsa-sha2-512",
                    }
                    .to_string();

                    managed_keys.push(ManagedKey {
                        fp_sha256_hex: fingerprint,
                        key_type: key_type_str,
                        format,
                        description: metadata.description,
                        source: "internal".to_string(), // Disk keys are internal
                        loaded: false,                  // Not loaded in RAM
                        has_disk: true,                 // Obviously on disk
                        has_cert: metadata.has_cert,
                        password_protected: metadata.password_protected,
                        constraints: serde_json::json!({
                            "confirm": false,
                            "lifetime_expires_at": null,
                        }),
                        created: Some(metadata.created.to_rfc3339()),
                        updated: Some(metadata.updated.to_rfc3339()),
                    });
                }
                Err(e) => {
                    // Failed to read metadata (wrong password, corrupted file, etc.)
                    // Fall back to placeholder entry
                    tracing::warn!("Failed to read metadata for key {}: {}", fingerprint, e);
                    managed_keys.push(ManagedKey {
                        fp_sha256_hex: fingerprint,
                        key_type: "unknown".to_string(),
                        format: "unknown".to_string(),
                        description: "[error reading metadata]".to_string(),
                        source: "internal".to_string(), // Disk keys are internal
                        loaded: false,                  // Not loaded in RAM
                        has_disk: true,                 // Obviously on disk
                        has_cert: false,                // Can't determine without decrypting
                        password_protected: false,      // Can't determine without decrypting
                        constraints: serde_json::json!({
                            "confirm": false,
                            "lifetime_expires_at": null,
                        }),
                        created: None,
                        updated: None,
                    });
                }
            }
        } else {
            // No master password available, use placeholder
            managed_keys.push(ManagedKey {
                fp_sha256_hex: fingerprint,
                key_type: "unknown".to_string(),
                format: "unknown".to_string(),
                description: "".to_string(),
                source: "internal".to_string(), // Disk keys are internal
                loaded: false,                  // Not loaded in RAM
                has_disk: true,                 // Obviously on disk
                has_cert: false,                // Can't determine without decrypting
                password_protected: false,      // Can't determine without decrypting
                constraints: serde_json::json!({
                    "confirm": false,
                    "lifetime_expires_at": null,
                }),
                created: None,
                updated: None,
            });
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

/// Handle session-bind@openssh.com extension
pub fn handle_session_bind(data: &[u8]) -> Result<Vec<u8>> {
    // Parse session-bind data according to OpenSSH PROTOCOL.agent specification:
    // string hostkey
    // string session identifier
    // string signature
    // bool is_forwarding

    tracing::debug!(
        "Handling session-bind@openssh.com extension, data length: {}",
        data.len()
    );

    let mut offset = 0;

    // For now, we'll implement a basic validation that just parses the structure
    // without performing cryptographic verification. In a full implementation,
    // this would verify the signature and maintain session binding state.

    // Read hostkey string
    if data.len() < offset + 4 {
        tracing::warn!("session-bind: insufficient data for hostkey length");
        return Ok(build_session_bind_failure("insufficient data for hostkey"));
    }

    let hostkey_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + hostkey_len {
        tracing::warn!("session-bind: insufficient data for hostkey");
        return Ok(build_session_bind_failure("insufficient hostkey data"));
    }

    let _hostkey = &data[offset..offset + hostkey_len];
    offset += hostkey_len;
    tracing::debug!("session-bind: hostkey length: {}", hostkey_len);

    // Read session identifier string
    if data.len() < offset + 4 {
        tracing::warn!("session-bind: insufficient data for session ID length");
        return Ok(build_session_bind_failure(
            "insufficient data for session ID",
        ));
    }

    let session_id_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + session_id_len {
        tracing::warn!("session-bind: insufficient data for session ID");
        return Ok(build_session_bind_failure("insufficient session ID data"));
    }

    let _session_id = &data[offset..offset + session_id_len];
    offset += session_id_len;
    tracing::debug!("session-bind: session ID length: {}", session_id_len);

    // Read signature string
    if data.len() < offset + 4 {
        tracing::warn!("session-bind: insufficient data for signature length");
        return Ok(build_session_bind_failure(
            "insufficient data for signature",
        ));
    }

    let signature_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + signature_len {
        tracing::warn!("session-bind: insufficient data for signature");
        return Ok(build_session_bind_failure("insufficient signature data"));
    }

    let _signature = &data[offset..offset + signature_len];
    offset += signature_len;
    tracing::debug!("session-bind: signature length: {}", signature_len);

    // Read is_forwarding boolean
    if data.len() < offset + 1 {
        tracing::warn!("session-bind: insufficient data for is_forwarding flag");
        return Ok(build_session_bind_failure(
            "insufficient data for forwarding flag",
        ));
    }

    let is_forwarding = data[offset] != 0;
    tracing::debug!("session-bind: is_forwarding: {}", is_forwarding);

    // TODO: In a full implementation, this would:
    // 1. Verify the signature using the hostkey and session identifier
    // 2. Check for duplicate session identifiers
    // 3. Prevent rebinding of connections used for authentication
    // 4. Store the binding for use in key constraint validation

    // For now, we accept all session-bind requests and return success
    // This provides OpenSSH compatibility without the security enforcement
    tracing::info!(
        "session-bind: Successfully processed session binding (validation not yet implemented)"
    );

    Ok(build_session_bind_success())
}

/// Build success response for session-bind extension
fn build_session_bind_success() -> Vec<u8> {
    // session-bind responses are simple SSH agent success messages
    // No extension-specific data is required
    vec![rssh_proto::wire::MessageType::Success as u8]
}

/// Build failure response for session-bind extension
fn build_session_bind_failure(reason: &str) -> Vec<u8> {
    tracing::warn!("session-bind: Returning failure: {}", reason);
    vec![rssh_proto::wire::MessageType::Failure as u8]
}

/// Handle manage.import extension - imports an external key to persistent storage
pub async fn handle_manage_import(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
    master_password: &str,
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

    // Try to extract comment from the SSH key if no description is provided
    let key_comment_description = if request.description.is_none() {
        // Attempt to parse the key and extract comment
        // Note: For keys in RAM, they are stored in wire format, so we need to convert them back
        // We'll first convert to our internal SSH key format, then to openssh format to parse with ssh-key crate
        match KeyFile::ssh_key_from_wire_format(
            &key_data,
            &match key_info.key_type.as_str() {
                "ed25519" => KeyType::Ed25519,
                "rsa" => KeyType::Rsa,
                _ => KeyType::Ed25519, // fallback, will be handled properly below
            },
        ) {
            Ok(internal_ssh_key) => {
                // Convert to OpenSSH format (providing both required parameters)
                match internal_ssh_key.to_openssh(None, None) {
                    Ok(openssh_data) => {
                        // Convert Vec<u8> to string for ssh-key crate parsing
                        match std::str::from_utf8(&openssh_data) {
                            Ok(openssh_str) => {
                                // Parse with ssh-key crate to get comment
                                match ssh_key::PrivateKey::from_openssh(openssh_str) {
                                    Ok(ssh_key) => {
                                        let comment = ssh_key.comment();
                                        if comment.is_empty() {
                                            None
                                        } else {
                                            Some(comment.to_string())
                                        }
                                    }
                                    Err(_) => {
                                        tracing::debug!(
                                            "Could not parse OpenSSH key to extract comment"
                                        );
                                        None
                                    }
                                }
                            }
                            Err(_) => {
                                tracing::debug!("OpenSSH data is not valid UTF-8");
                                None
                            }
                        }
                    }
                    Err(_) => {
                        tracing::debug!("Could not convert internal key to OpenSSH format");
                        None
                    }
                }
            }
            Err(_) => {
                tracing::debug!(
                    "Could not parse key from wire format to extract comment, using existing description"
                );
                None
            }
        }
    } else {
        None
    };

    // Use description based on priority:
    // 1. User-provided description (highest priority)
    // 2. Comment/description from the SSH key file itself
    // 3. Existing description from key_info (fallback)
    let description = request
        .description
        .or(key_comment_description)
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

    // Handle certificates according to spec: "On import, if a cert is currently attached in RAM → auto-save into cert_openssh_b64"
    let cert_openssh_b64 = if key_info.has_cert {
        // Certificate is attached but current SSH agent protocol implementation doesn't store cert data in RAM
        // This needs to be implemented in the SSH agent protocol parsing layer first
        tracing::warn!(
            "Key {} has certificate attached but certificate data extraction not yet implemented",
            request.fp_sha256_hex
        );
        None // Will be implemented when SSH agent protocol supports certificate parsing
    } else {
        None // No certificate attached
    };

    // Decode key password if provided
    let key_password = if request.set_key_password {
        if let Some(pass_b64) = &request.new_key_pass_b64 {
            let pass_bytes = BASE64
                .decode(pass_b64)
                .map_err(|e| Error::Config(format!("Invalid base64 key password: {}", e)))?;
            let pass_string = std::str::from_utf8(&pass_bytes)
                .map_err(|e| Error::Config(format!("Invalid UTF-8 key password: {}", e)))?
                .to_string();

            // Validate password constraints
            if pass_string.len() < 4 || pass_string.len() > 1024 {
                return Err(Error::Config(
                    "Key password must be between 4 and 1024 characters".to_string(),
                ));
            }

            Some(pass_string)
        } else {
            return Err(Error::Config(
                "set_key_password is true but new_key_pass_b64 is missing".to_string(),
            ));
        }
    } else {
        None
    };

    // Get storage directory from environment or use default
    let storage_dir = std::env::var("RSSH_STORAGE_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.ssh/rssh-agent", home)
    });

    let now = Utc::now();
    let secret_openssh_b64;
    let password_protected;

    if let Some(password) = &key_password {
        // Convert wire format to SSH key and then to OpenSSH format with password
        tracing::debug!("Converting wire format key to password-protected OpenSSH format");

        let ssh_key = KeyFile::ssh_key_from_wire_format(&key_data, &key_type)
            .map_err(|e| Error::Internal(format!("Failed to convert wire format key: {}", e)))?;

        let openssh_data = ssh_key.to_openssh(Some(password), None).map_err(|e| {
            Error::Internal(format!("Failed to serialize key with password: {}", e))
        })?;

        secret_openssh_b64 = BASE64.encode(&openssh_data);
        password_protected = true;

        tracing::debug!("Successfully converted key to password-protected format");
    } else {
        // Use legacy method for non-password-protected keys (store as wire format)
        tracing::debug!("Storing key in wire format (no password protection)");
        secret_openssh_b64 = BASE64.encode(&key_data);
        password_protected = false;
    }

    let payload = KeyPayload {
        key_type,
        description,
        secret_openssh_b64,
        cert_openssh_b64,
        password_protected,
        created: now,
        updated: now,
    };

    // Write key file to disk
    KeyFile::write(
        &storage_dir,
        &request.fp_sha256_hex,
        &payload,
        master_password,
    )?;

    // Mark the key as internal now that it's been imported
    ram_store.mark_key_as_internal(&request.fp_sha256_hex)?;

    tracing::info!(
        "Successfully imported key {} with {} password protection",
        request.fp_sha256_hex,
        if password_protected { "" } else { "no" }
    );

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

/// Handle manage.import_direct extension - imports an SSH key directly from file data to persistent storage
pub async fn handle_manage_import_direct(data: &[u8], master_password: &str) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use chrono::Utc;
    use rssh_core::keyfile::{KeyFile, KeyPayload, KeyType};

    #[derive(Debug, Deserialize)]
    struct ImportDirectRequest {
        key_data_openssh_b64: String,
        description: Option<String>,
        set_key_password: Option<bool>,
        new_key_pass_b64: Option<String>,
        preserve_original_protection: Option<bool>,
    }

    // Parse the CBOR request data
    let request: ImportDirectRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse import_direct request: {}", e)))?;

    // Decode the SSH key data
    let key_data = BASE64
        .decode(&request.key_data_openssh_b64)
        .map_err(|e| Error::Config(format!("Invalid base64 key data: {}", e)))?;

    // Convert to string for SSH key parsing
    let key_content = std::str::from_utf8(&key_data)
        .map_err(|e| Error::Config(format!("Invalid UTF-8 in key data: {}", e)))?;

    // Parse the SSH private key
    let ssh_key = ssh_key::PrivateKey::from_openssh(key_content)
        .map_err(|e| Error::Config(format!("Invalid SSH key format: {}", e)))?;

    // Check if the original key is encrypted
    let original_is_encrypted = ssh_key.is_encrypted();

    // Calculate fingerprint from public key
    let public_key = ssh_key.public_key();
    let fingerprint = public_key.fingerprint(ssh_key::HashAlg::Sha256);
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());

    // Determine key type
    let key_type = match ssh_key.algorithm() {
        ssh_key::Algorithm::Ed25519 => KeyType::Ed25519,
        ssh_key::Algorithm::Rsa { .. } => KeyType::Rsa,
        _ => {
            return Err(Error::Internal(format!(
                "Unsupported key algorithm: {:?}",
                ssh_key.algorithm()
            )));
        }
    };

    // Extract comment from SSH key
    let key_comment = ssh_key.comment();
    let key_comment_str = if key_comment.is_empty() {
        None
    } else {
        Some(key_comment.to_string())
    };

    // Use description based on priority:
    // 1. User-provided description (highest priority)
    // 2. Comment/description from the SSH key file itself
    // 3. Default fallback description
    let description = request
        .description
        .or(key_comment_str)
        .unwrap_or_else(|| "Imported SSH key".to_string());

    // Validate description
    rssh_core::keyfile::validate_description(&description)
        .map_err(|e| Error::Config(format!("Invalid description: {}", e)))?;

    // Determine how to handle password protection
    let (secret_openssh_b64, password_protected) = if request
        .preserve_original_protection
        .unwrap_or(false)
    {
        // Preserve original protection state
        if original_is_encrypted {
            // Store encrypted key as-is in OpenSSH format
            tracing::debug!("Preserving original password protection");
            (BASE64.encode(key_content.as_bytes()), true)
        } else {
            // Convert unprotected key to wire format
            tracing::debug!("Converting unprotected key to wire format");
            let ssh_private_key =
                rssh_core::openssh::SshPrivateKey::from_openssh(key_content.as_bytes(), None)?;
            let wire_data = ssh_private_key
                .to_wire_format()
                .map_err(|e| Error::Internal(format!("Failed to convert to wire format: {}", e)))?;
            (BASE64.encode(&wire_data), false)
        }
    } else if request.set_key_password.unwrap_or(false) {
        // User wants to set new password protection
        if let Some(pass_b64) = &request.new_key_pass_b64 {
            let pass_bytes = BASE64
                .decode(pass_b64)
                .map_err(|e| Error::Config(format!("Invalid base64 key password: {}", e)))?;
            let pass_string = std::str::from_utf8(&pass_bytes)
                .map_err(|e| Error::Config(format!("Invalid UTF-8 key password: {}", e)))?
                .to_string();

            // Validate password constraints
            if pass_string.len() < 4 || pass_string.len() > 1024 {
                return Err(Error::Config(
                    "Key password must be between 4 and 1024 characters".to_string(),
                ));
            }

            // Decrypt original key if needed, then re-encrypt with new password
            let decrypted_key = if original_is_encrypted {
                // This should not happen in the new flow, but handle it just in case
                return Err(Error::Config(
                    "Cannot set new password on encrypted key without providing original passphrase".to_string(),
                ));
            } else {
                ssh_key.clone()
            };

            // Encrypt with new password
            tracing::debug!("Encrypting key with new password");
            let protected_key = decrypted_key
                .encrypt(&mut OsRng, pass_string.as_bytes())
                .map_err(|e| {
                    Error::Internal(format!("Failed to encrypt key with new password: {}", e))
                })?;

            let protected_data =
                protected_key
                    .to_openssh(ssh_key::LineEnding::LF)
                    .map_err(|e| {
                        Error::Internal(format!("Failed to serialize encrypted key: {}", e))
                    })?;

            (BASE64.encode(protected_data.as_bytes()), true)
        } else {
            return Err(Error::Config(
                "set_key_password is true but new_key_pass_b64 is missing".to_string(),
            ));
        }
    } else {
        // Default behavior: store without password protection in wire format
        tracing::debug!("Converting key to wire format (no password protection)");

        // Decrypt the key if it's encrypted (this should not happen in new flow)
        let decrypted_key = if original_is_encrypted {
            return Err(Error::Config(
                "Cannot import encrypted key without providing passphrase or using preserve_original_protection".to_string(),
            ));
        } else {
            ssh_key.clone()
        };

        // Convert to wire format for storage
        let openssh_data = decrypted_key
            .to_openssh(ssh_key::LineEnding::LF)
            .map_err(|e| Error::Internal(format!("Failed to serialize key: {}", e)))?;

        let ssh_private_key =
            rssh_core::openssh::SshPrivateKey::from_openssh(openssh_data.as_bytes(), None)?;
        let wire_data = ssh_private_key
            .to_wire_format()
            .map_err(|e| Error::Internal(format!("Failed to convert to wire format: {}", e)))?;

        (BASE64.encode(&wire_data), false)
    };

    // Get storage directory from environment or use default
    let storage_dir = std::env::var("RSSH_STORAGE_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.ssh/rssh-agent", home)
    });

    let now = Utc::now();

    let payload = KeyPayload {
        key_type,
        description: description.clone(),
        secret_openssh_b64,
        cert_openssh_b64: None,
        password_protected,
        created: now,
        updated: now,
    };

    // Write key file to disk
    KeyFile::write(&storage_dir, &fingerprint_hex, &payload, master_password)?;

    tracing::info!(
        "Successfully imported key {} directly to disk with {} password protection",
        fingerprint_hex,
        if password_protected { "" } else { "no" }
    );

    // Create success response
    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": fingerprint_hex,
        "description": description
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
    ram_store: &rssh_core::ram_store::RamStore,
    storage_dir: Option<&str>,
    master_password: &str,
) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rssh_core::keyfile::KeyFile;

    #[derive(Debug, Deserialize)]
    struct LoadRequest {
        fp_sha256_hex: String,
        key_pass_b64: Option<String>,
        // Constraint support
        confirm: Option<bool>,
        lifetime_seconds: Option<u32>,
    }

    // Parse the CBOR request data
    let request: LoadRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse load request: {}", e)))?;

    // Get storage directory
    let storage_dir = storage_dir
        .ok_or_else(|| Error::Internal("Storage directory not configured".to_string()))?;

    // First, check if this is a password-protected key by reading metadata
    let metadata = KeyFile::read_metadata(storage_dir, &request.fp_sha256_hex, master_password)?;

    let wire_key_data = if metadata.password_protected {
        // Decode key password if provided
        let key_password = if let Some(pass_b64) = &request.key_pass_b64 {
            let pass_bytes = BASE64
                .decode(pass_b64)
                .map_err(|e| Error::Config(format!("Invalid base64 key password: {}", e)))?;
            let pass_string = std::str::from_utf8(&pass_bytes)
                .map_err(|e| Error::Config(format!("Invalid UTF-8 key password: {}", e)))?
                .to_string(); // Convert to owned String
            Some(pass_string)
        } else {
            return Err(Error::NeedKeyPassword);
        };

        // Read the SSH key with password
        let ssh_key = KeyFile::read_ssh_key(
            storage_dir,
            &request.fp_sha256_hex,
            master_password,
            key_password.as_deref(),
        )?;

        // Convert SSH key to wire format for RAM storage
        ssh_key.to_wire_format()?
    } else {
        // Legacy format: read the key payload and decode the wire format data
        let key_payload = KeyFile::read(storage_dir, &request.fp_sha256_hex, master_password)?;

        // The secret_openssh_b64 field contains wire format key data for legacy keys
        BASE64
            .decode(&key_payload.secret_openssh_b64)
            .map_err(|e| Error::Internal(format!("Failed to decode key data: {}", e)))?
    };

    // Load the key into RAM store
    // Use load_key (not load_external_key) since this is an internal key from disk
    // Convert KeyType enum to string
    let key_type_str = match metadata.key_type {
        rssh_core::keyfile::KeyType::Ed25519 => "ed25519".to_string(),
        rssh_core::keyfile::KeyType::Rsa => "rsa".to_string(),
    };

    ram_store.load_key(
        &request.fp_sha256_hex,
        &wire_key_data,
        metadata.description,
        key_type_str,
        metadata.has_cert,
    )?;

    // Apply constraints if specified
    let confirm = request.confirm.unwrap_or(false);
    let lifetime_secs = request.lifetime_seconds.map(|secs| secs as u64);

    if confirm || lifetime_secs.is_some() {
        if let Err(e) = ram_store.set_constraints(&request.fp_sha256_hex, confirm, lifetime_secs) {
            tracing::warn!(
                "Failed to set constraints for loaded key {}: {}",
                request.fp_sha256_hex,
                e
            );
            // Key was loaded successfully, but constraints failed - this is not fatal
        } else {
            tracing::debug!(
                "Set constraints for loaded key {}: confirm={}, lifetime={:?}",
                request.fp_sha256_hex,
                confirm,
                lifetime_secs
            );
        }
    }

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

/// Handle manage.unload extension - removes a key from RAM while keeping it on disk
pub fn handle_manage_unload(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
) -> Result<Vec<u8>> {
    #[derive(Debug, Deserialize)]
    struct UnloadRequest {
        fp_sha256_hex: String,
    }

    // Parse the CBOR request data
    let request: UnloadRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse unload request: {}", e)))?;

    // Unload the key from RAM store
    ram_store.unload_key(&request.fp_sha256_hex)?;

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

/// Handle manage.delete extension - permanently deletes a key from disk storage
pub fn handle_manage_delete(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
    storage_dir: Option<&str>,
) -> Result<Vec<u8>> {
    use rssh_proto::cbor::{ManageDeleteRequest, ManageDeleteResponse};

    // Parse the CBOR request data
    let request: ManageDeleteRequest = match ciborium::from_reader(data) {
        Ok(req) => req,
        Err(e) => {
            let response = ManageDeleteResponse {
                ok: false,
                error: Some(format!("Failed to parse delete request: {}", e)),
                fingerprint: None,
            };
            return wrap_manage_delete_response(response);
        }
    };

    // Get storage directory
    let storage_dir = match storage_dir {
        Some(dir) => dir,
        None => {
            let response = ManageDeleteResponse {
                ok: false,
                error: Some("Storage directory not configured".to_string()),
                fingerprint: None,
            };
            return wrap_manage_delete_response(response);
        }
    };

    // Construct the keyfile path
    let keyfile_path =
        std::path::Path::new(storage_dir).join(format!("sha256-{}.json", request.fp_sha256_hex));

    // Check if the keyfile exists
    if !keyfile_path.exists() {
        let response = ManageDeleteResponse {
            ok: false,
            error: Some("Key file not found on disk".to_string()),
            fingerprint: Some(request.fp_sha256_hex),
        };
        return wrap_manage_delete_response(response);
    }

    // If the key is loaded in RAM, unload it first
    if let Ok(keys) = ram_store.list_keys() {
        if keys.iter().any(|k| k.fingerprint == request.fp_sha256_hex) {
            tracing::debug!(
                "Key {} is loaded in RAM, unloading before deletion",
                request.fp_sha256_hex
            );
            if let Err(e) = ram_store.unload_key(&request.fp_sha256_hex) {
                tracing::warn!(
                    "Failed to unload key {} from RAM before deletion: {}",
                    request.fp_sha256_hex,
                    e
                );
                // Continue with deletion anyway
            }
        }
    }

    // Delete the keyfile from disk
    match std::fs::remove_file(&keyfile_path) {
        Ok(()) => {
            tracing::info!("Successfully deleted key file: {}", request.fp_sha256_hex);

            let response = ManageDeleteResponse {
                ok: true,
                error: None,
                fingerprint: Some(request.fp_sha256_hex),
            };
            wrap_manage_delete_response(response)
        }
        Err(e) => {
            tracing::error!("Failed to delete key file {}: {}", request.fp_sha256_hex, e);

            let response = ManageDeleteResponse {
                ok: false,
                error: Some(format!("Failed to delete key file: {}", e)),
                fingerprint: Some(request.fp_sha256_hex),
            };
            wrap_manage_delete_response(response)
        }
    }
}

/// Handle manage.set_desc extension - updates the description of a stored key
pub fn handle_manage_set_desc(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
    storage_dir: Option<&str>,
    master_password: &str,
) -> Result<Vec<u8>> {
    use chrono::Utc;
    use rssh_core::keyfile::KeyFile;

    #[derive(Debug, Deserialize)]
    struct SetDescRequest {
        fp_sha256_hex: String,
        description: String,
    }

    // Parse the CBOR request data
    let request: SetDescRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse set_desc request: {}", e)))?;

    // Get storage directory
    let storage_dir = storage_dir
        .ok_or_else(|| Error::Internal("Storage directory not configured".to_string()))?;

    // Validate the new description
    rssh_core::keyfile::validate_description(&request.description)
        .map_err(|e| Error::Config(format!("Invalid description: {}", e)))?;

    // Read the existing key file from disk
    let mut key_payload = KeyFile::read(storage_dir, &request.fp_sha256_hex, master_password)
        .map_err(|e| match e {
            Error::NotFound => Error::NotFound,
            Error::WrongPassword => Error::WrongPassword,
            _ => Error::Internal(format!("Failed to read key file: {}", e)),
        })?;

    // Update the description and timestamp
    key_payload.description = request.description.clone();
    key_payload.updated = Utc::now();

    // Write the updated key file back to disk
    KeyFile::write(
        storage_dir,
        &request.fp_sha256_hex,
        &key_payload,
        master_password,
    )?;
    let _ = ram_store.update_description(&request.fp_sha256_hex, request.description.clone());

    // Create success response
    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": request.fp_sha256_hex,
        "description": request.description
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

/// Handle manage.update_cert extension - updates certificate for an existing key
pub async fn handle_manage_update_cert(
    data: &[u8],
    storage_dir: &str,
    master_password: &str,
) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use chrono::Utc;
    use rssh_core::keyfile::KeyFile;

    #[derive(Debug, Deserialize)]
    struct UpdateCertRequest {
        fp_sha256_hex: String,
        cert_openssh_b64: String,
    }

    // Parse the CBOR request data
    let request: UpdateCertRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse update_cert request: {}", e)))?;

    // Validate certificate format by trying to decode it
    let cert_data = BASE64
        .decode(&request.cert_openssh_b64)
        .map_err(|_| Error::BadCertFormat)?;

    // Parse certificate to validate format and extract public key
    let cert_str = std::str::from_utf8(&cert_data).map_err(|_| Error::BadCertFormat)?;

    // SSH certificates start with ssh-rsa-cert-v01@openssh.com, ssh-ed25519-cert-v01@openssh.com, etc.
    if !cert_str.contains("-cert-v01@openssh.com") {
        return Err(Error::BadCertFormat);
    }

    // Validate certificate format by parsing it
    if validate_certificate_format(&cert_data).is_err() {
        return Err(Error::BadCertFormat);
    }

    // Read existing keyfile
    let mut payload = KeyFile::read(storage_dir, &request.fp_sha256_hex, master_password)?;

    // TODO: In a full implementation, we should validate that the certificate's public key
    // matches the stored key's public key. For now, we just ensure the certificate is valid format.
    // This validation could be added once we have a reliable way to extract and compare public keys.

    // Update certificate and timestamp
    payload.cert_openssh_b64 = Some(request.cert_openssh_b64.clone());
    payload.updated = Utc::now();

    // Write updated keyfile atomically
    KeyFile::write(
        storage_dir,
        &request.fp_sha256_hex,
        &payload,
        master_password,
    )?;

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

/// Validate SSH certificate format
fn validate_certificate_format(cert_data: &[u8]) -> rssh_core::Result<()> {
    use ssh_key::Certificate;

    let cert_str = std::str::from_utf8(cert_data).map_err(|_| Error::BadCertFormat)?;

    // Parse the certificate using ssh-key crate to validate format
    Certificate::from_openssh(cert_str).map_err(|_| Error::BadCertFormat)?;

    Ok(())
}

/// Handle manage.change_pass extension
pub fn handle_manage_change_pass(
    data: &[u8],
    storage_dir: Option<&str>,
    master_password: &str,
) -> Result<Vec<u8>> {
    use rssh_core::config::Config;
    use rssh_core::keyfile::KeyFile;
    use rssh_proto::cbor::ManageOperationResponse;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct ChangePassRequest {
        old_password: String,
        new_password: String,
    }

    // Parse the request
    let request: ChangePassRequest = match ciborium::from_reader(data) {
        Ok(req) => req,
        Err(e) => {
            let response = ManageOperationResponse {
                ok: false,
                error: Some(format!("Invalid request format: {}", e)),
            };
            return wrap_manage_operation_response(response);
        }
    };

    // Validate password constraints
    if request.new_password.len() < 8 || request.new_password.len() > 1024 {
        let response = ManageOperationResponse {
            ok: false,
            error: Some("New password must be between 8 and 1024 characters".to_string()),
        };
        return wrap_manage_operation_response(response);
    }

    if request.new_password.trim().is_empty() {
        let response = ManageOperationResponse {
            ok: false,
            error: Some("New password cannot be empty or whitespace only".to_string()),
        };
        return wrap_manage_operation_response(response);
    }

    // Verify the old password matches current master password
    if request.old_password != master_password {
        let response = ManageOperationResponse {
            ok: false,
            error: Some("Current password is incorrect".to_string()),
        };
        return wrap_manage_operation_response(response);
    }

    // Get storage directory
    let storage_dir = match storage_dir {
        Some(dir) => dir,
        None => {
            let response = ManageOperationResponse {
                ok: false,
                error: Some("Storage directory not configured".to_string()),
            };
            return wrap_manage_operation_response(response);
        }
    };

    // Enumerate all keyfiles
    let keyfile_fingerprints = match enumerate_keyfiles(storage_dir) {
        Ok(fingerprints) => fingerprints,
        Err(e) => {
            let response = ManageOperationResponse {
                ok: false,
                error: Some(format!("Failed to enumerate keyfiles: {}", e)),
            };
            return wrap_manage_operation_response(response);
        }
    };

    // Re-encrypt all keyfiles with the new password
    for fingerprint in &keyfile_fingerprints {
        tracing::debug!("Re-encrypting keyfile for fingerprint: {}", fingerprint);

        // Read the keyfile with the old password
        let payload = match KeyFile::read(storage_dir, fingerprint, &request.old_password) {
            Ok(payload) => payload,
            Err(e) => {
                let response = ManageOperationResponse {
                    ok: false,
                    error: Some(format!("Failed to read keyfile {}: {}", fingerprint, e)),
                };
                return wrap_manage_operation_response(response);
            }
        };

        // Write it back with the new password
        if let Err(e) = KeyFile::write(storage_dir, fingerprint, &payload, &request.new_password) {
            let response = ManageOperationResponse {
                ok: false,
                error: Some(format!(
                    "Failed to re-encrypt keyfile {}: {}",
                    fingerprint, e
                )),
            };
            return wrap_manage_operation_response(response);
        }
    }

    // Update the config.json with new password sentinel
    // First verify we can read the existing config with the old password
    let config_path = std::path::Path::new(storage_dir).join("config.json");
    if config_path.exists() {
        let config_json = match std::fs::read_to_string(&config_path) {
            Ok(json) => json,
            Err(e) => {
                let response = ManageOperationResponse {
                    ok: false,
                    error: Some(format!("Failed to read config: {}", e)),
                };
                return wrap_manage_operation_response(response);
            }
        };

        let config: Config = match serde_json::from_str(&config_json) {
            Ok(config) => config,
            Err(e) => {
                let response = ManageOperationResponse {
                    ok: false,
                    error: Some(format!("Failed to parse config: {}", e)),
                };
                return wrap_manage_operation_response(response);
            }
        };

        // Verify old password can decrypt the existing sentinel
        if !config.verify_sentinel(&request.old_password) {
            let response = ManageOperationResponse {
                ok: false,
                error: Some("Current password verification failed against config".to_string()),
            };
            return wrap_manage_operation_response(response);
        }
    }

    // Create new config with updated sentinel for new password
    if let Err(e) = Config::new_with_sentinel(storage_dir, &request.new_password) {
        let response = ManageOperationResponse {
            ok: false,
            error: Some(format!("Failed to update config with new password: {}", e)),
        };
        return wrap_manage_operation_response(response);
    }

    tracing::info!(
        "Successfully changed master password and re-encrypted {} keyfiles",
        keyfile_fingerprints.len()
    );

    // Return success response
    let response = ManageOperationResponse {
        ok: true,
        error: None,
    };
    wrap_manage_operation_response(response)
}

/// Handle manage.set_password extension - sets or removes password protection for existing stored keys
pub async fn handle_manage_set_password(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
    master_password: &str,
) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rssh_core::keyfile::KeyFile;
    use rssh_proto::cbor::{ManageSetPasswordRequest, ManageSetPasswordResponse};

    // Parse the CBOR request data
    let request: ManageSetPasswordRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse set_password request: {}", e)))?;

    tracing::debug!(
        "Processing set_password request for key: {} (set_protection: {})",
        request.fp_sha256_hex,
        request.set_password_protection
    );

    // Validate input
    if request.set_password_protection && request.new_key_pass_b64.is_none() {
        return wrap_manage_set_password_response(ManageSetPasswordResponse {
            ok: false,
            error: Some(
                "new_key_pass_b64 is required when set_password_protection is true".to_string(),
            ),
            fingerprint: Some(request.fp_sha256_hex.clone()),
        });
    }

    // Get storage directory from environment or use default
    let storage_dir = std::env::var("RSSH_STORAGE_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.ssh/rssh-agent", home)
    });

    // Check if keyfile exists on disk (this is the primary requirement)
    let keyfile_path =
        std::path::Path::new(&storage_dir).join(format!("sha256-{}.json", request.fp_sha256_hex));
    if !keyfile_path.exists() {
        return wrap_manage_set_password_response(ManageSetPasswordResponse {
            ok: false,
            error: Some("Key is not stored on disk. Create or import the key first.".to_string()),
            fingerprint: Some(request.fp_sha256_hex.clone()),
        });
    }

    // Optional: Check if key is in RAM store and verify it's not external
    // But don't require it to be loaded - we can work with disk-only keys
    if let Ok(keys) = ram_store.list_keys() {
        if let Some(key_info) = keys.iter().find(|k| k.fingerprint == request.fp_sha256_hex) {
            // If it's in RAM and is external, reject the operation
            if key_info.is_external {
                return wrap_manage_set_password_response(ManageSetPasswordResponse {
                    ok: false,
                    error: Some(
                        "Cannot set password on external keys. Use manage.import to import them first."
                            .to_string(),
                    ),
                    fingerprint: Some(request.fp_sha256_hex.clone()),
                });
            }
        }
    }

    // Read the existing key file
    let mut payload = KeyFile::read(&storage_dir, &request.fp_sha256_hex, master_password)
        .map_err(|e| Error::Internal(format!("Failed to read existing keyfile: {}", e)))?;

    tracing::debug!(
        "Read keyfile: type={:?}, password_protected={}, created={}, updated={}",
        payload.key_type,
        payload.password_protected,
        payload.created,
        payload.updated
    );

    // Validate current password requirement for password-protected keys
    let current_key_password = if payload.password_protected {
        // If key is currently password-protected, we need the current password to decrypt it
        if request.current_key_pass_b64.is_none() {
            return wrap_manage_set_password_response(ManageSetPasswordResponse {
                ok: false,
                error: Some(
                    "current_key_pass_b64 is required when key is currently password-protected"
                        .to_string(),
                ),
                fingerprint: Some(request.fp_sha256_hex.clone()),
            });
        }

        let current_pass_b64 = request.current_key_pass_b64.as_ref().unwrap();
        let current_pass_bytes = BASE64
            .decode(current_pass_b64)
            .map_err(|e| Error::Config(format!("Invalid base64 current key password: {}", e)))?;
        let current_pass_string = std::str::from_utf8(&current_pass_bytes)
            .map_err(|e| Error::Config(format!("Invalid UTF-8 current key password: {}", e)))?;

        tracing::debug!(
            "Current key password provided (length: {})",
            current_pass_string.len()
        );
        Some(current_pass_string.to_string())
    } else {
        // Key is not password-protected, no current password needed
        None
    };

    // Decode and validate the new password if provided
    let new_key_password = if request.set_password_protection {
        let pass_b64 = request.new_key_pass_b64.as_ref().unwrap();
        let pass_bytes = BASE64
            .decode(pass_b64)
            .map_err(|e| Error::Config(format!("Invalid base64 new key password: {}", e)))?;
        let pass_string = std::str::from_utf8(&pass_bytes)
            .map_err(|e| Error::Config(format!("Invalid UTF-8 new key password: {}", e)))?;

        // Validate password constraints
        if pass_string.len() < 4 || pass_string.len() > 1024 {
            return wrap_manage_set_password_response(ManageSetPasswordResponse {
                ok: false,
                error: Some("Key password must be between 4 and 1024 characters".to_string()),
                fingerprint: Some(request.fp_sha256_hex.clone()),
            });
        }

        tracing::debug!("Validated new key password (length: {})", pass_string.len());
        Some(pass_string.to_string())
    } else {
        tracing::debug!("Removing password protection");
        None
    };

    // Get the current key data and parse the SSH key
    let current_key_bytes = BASE64
        .decode(&payload.secret_openssh_b64)
        .map_err(|e| Error::Internal(format!("Failed to decode existing key: {}", e)))?;

    tracing::debug!(
        "Current key data: {} bytes, format: {}",
        current_key_bytes.len(),
        if payload.password_protected {
            "OpenSSH"
        } else {
            "wire"
        }
    );

    // Parse the SSH private key based on its current format
    let ssh_key = if payload.password_protected {
        // Key is already in OpenSSH format, parse with current password
        tracing::debug!("Parsing key from OpenSSH format with current password");
        rssh_core::openssh::SshPrivateKey::from_openssh(
            &current_key_bytes,
            current_key_password.as_deref(),
        )
        .map_err(|e| Error::Internal(format!("Failed to parse existing OpenSSH key: {}", e)))?
    } else {
        // Key is in wire format, need to convert to SshPrivateKey first
        tracing::debug!("Converting key from wire format to OpenSSH format");
        KeyFile::ssh_key_from_wire_format(&current_key_bytes, &payload.key_type)
            .map_err(|e| Error::Internal(format!("Failed to convert wire format key: {}", e)))?
    };

    tracing::debug!(
        "Successfully parsed SSH key, algorithm: {:?}",
        ssh_key.algorithm()
    );

    // Re-serialize with the new password setting according to storage format convention
    let new_key_bytes = if request.set_password_protection {
        // Setting password protection: convert to OpenSSH format with password
        let key_password = new_key_password.as_ref().unwrap();
        tracing::debug!("Serializing key with password protection (OpenSSH format)");
        ssh_key.to_openssh(Some(key_password), None).map_err(|e| {
            Error::Internal(format!("Failed to serialize key with new password: {}", e))
        })?
    } else {
        // Removing password protection: convert to wire format (backward compatibility)
        tracing::debug!("Serializing key without password protection (wire format)");
        ssh_key.to_wire_format().map_err(|e| {
            Error::Internal(format!("Failed to serialize key to wire format: {}", e))
        })?
    };

    tracing::debug!("Successfully serialized key: {} bytes", new_key_bytes.len());

    // Update the payload with the re-encoded key and new status
    payload.secret_openssh_b64 = BASE64.encode(&new_key_bytes);
    payload.password_protected = request.set_password_protection;
    payload.updated = chrono::Utc::now();

    tracing::debug!(
        "Updated payload: password_protected={}, updated={}",
        payload.password_protected,
        payload.updated
    );

    // Write the updated key file back to disk
    KeyFile::write(
        &storage_dir,
        &request.fp_sha256_hex,
        &payload,
        master_password,
    )
    .map_err(|e| Error::Internal(format!("Failed to write updated keyfile: {}", e)))?;

    tracing::info!(
        "Successfully {} password protection for key: {}",
        if request.set_password_protection {
            "set"
        } else {
            "removed"
        },
        request.fp_sha256_hex
    );

    // Return success response
    wrap_manage_set_password_response(ManageSetPasswordResponse {
        ok: true,
        error: None,
        fingerprint: Some(request.fp_sha256_hex),
    })
}

/// Helper function to wrap ManageSetPasswordResponse in CBOR format
fn wrap_manage_set_password_response(
    response: rssh_proto::cbor::ManageSetPasswordResponse,
) -> Result<Vec<u8>> {
    let response_data = serde_json::json!(response);

    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response_data, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    let cbor_response = rssh_proto::cbor::ExtensionResponse {
        success: true,
        data: data_cbor,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&cbor_response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}

/// Handle manage.create extension - generates a new SSH key
pub async fn handle_manage_create(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
    storage_dir: Option<&str>,
    master_password: &str,
) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use chrono::Utc;
    use rssh_core::keyfile::{KeyFile, KeyPayload, KeyType, calculate_fingerprint_hex};
    use rssh_core::openssh::SshPrivateKey;
    use rssh_proto::cbor::{ManageCreateRequest, ManageCreateResponse};

    // Parse the CBOR request data
    let request: ManageCreateRequest = match ciborium::from_reader(data) {
        Ok(req) => req,
        Err(e) => {
            let response = ManageCreateResponse {
                ok: false,
                error: Some(format!("Failed to parse create request: {}", e)),
                fingerprint: None,
                public_key: None,
            };
            return wrap_manage_create_response(response);
        }
    };

    // Validate and generate the private key
    let (private_key, key_type) = match request.key_type.as_str() {
        "ed25519" => {
            let key = SshPrivateKey::generate_ed25519()
                .map_err(|e| Error::Internal(format!("Failed to generate Ed25519 key: {}", e)))?;
            (key, KeyType::Ed25519)
        }
        "rsa" => {
            let bit_length = request.bit_length.unwrap_or(2048) as usize;
            let key = SshPrivateKey::generate_rsa(bit_length)
                .map_err(|e| Error::Internal(format!("Failed to generate RSA key: {}", e)))?;
            (key, KeyType::Rsa)
        }
        _ => {
            let response = ManageCreateResponse {
                ok: false,
                error: Some(format!(
                    "Unsupported key type: {}. Supported types: ed25519, rsa",
                    request.key_type
                )),
                fingerprint: None,
                public_key: None,
            };
            return wrap_manage_create_response(response);
        }
    };

    // Get storage directory
    let storage_dir = match storage_dir {
        Some(dir) => dir,
        None => {
            let response = ManageCreateResponse {
                ok: false,
                error: Some("Storage directory not configured".to_string()),
                fingerprint: None,
                public_key: None,
            };
            return wrap_manage_create_response(response);
        }
    };

    // Get public key bytes and calculate fingerprint
    let public_key_bytes = private_key.public_key_bytes();
    let fingerprint_hex = calculate_fingerprint_hex(&public_key_bytes);

    // Convert private key to wire format for consistent storage
    let wire_key_data = private_key.to_wire_format().map_err(|e| {
        Error::Internal(format!(
            "Failed to serialize private key to wire format: {}",
            e
        ))
    })?;
    let secret_openssh_b64 = BASE64.encode(&wire_key_data);

    // Serialize public key to OpenSSH format for response
    let public_key_openssh = format!(
        "{} {}",
        if private_key.is_ed25519() {
            "ssh-ed25519"
        } else {
            "ssh-rsa"
        },
        BASE64.encode(&public_key_bytes)
    );
    let public_key_b64 = BASE64.encode(public_key_openssh.as_bytes());

    // Create description
    let description = request.description.unwrap_or_else(|| match key_type {
        KeyType::Ed25519 => "Generated Ed25519 key".to_string(),
        KeyType::Rsa => {
            let bits = private_key.rsa_bits().unwrap_or(2048);
            format!("Generated RSA {} key", bits)
        }
    });

    // Validate description
    if let Err(e) = rssh_core::keyfile::validate_description(&description) {
        let response = ManageCreateResponse {
            ok: false,
            error: Some(format!("Invalid description: {}", e)),
            fingerprint: None,
            public_key: None,
        };
        return wrap_manage_create_response(response);
    }

    // Create KeyPayload
    let now = Utc::now();
    let payload = KeyPayload {
        key_type,
        description: description.clone(),
        secret_openssh_b64,
        cert_openssh_b64: None,
        password_protected: false, // New keys created via manage.create are not password-protected
        created: now,
        updated: now,
    };

    // Write key file to disk
    if let Err(e) = KeyFile::write(storage_dir, &fingerprint_hex, &payload, master_password) {
        let response = ManageCreateResponse {
            ok: false,
            error: Some(format!("Failed to save key to disk: {}", e)),
            fingerprint: None,
            public_key: None,
        };
        return wrap_manage_create_response(response);
    }

    tracing::info!(
        "Created new {} key with fingerprint: {}",
        request.key_type,
        fingerprint_hex
    );

    // Optionally load the key to RAM
    if request.load_to_ram {
        // Read the keyfile we just wrote to get the key data for loading
        match KeyFile::read(storage_dir, &fingerprint_hex, master_password) {
            Ok(key_payload) => {
                // Decode the key data from base64
                match BASE64.decode(&key_payload.secret_openssh_b64) {
                    Ok(wire_key_data) => {
                        // Convert KeyType enum to string
                        let key_type_str = match key_payload.key_type {
                            rssh_core::keyfile::KeyType::Ed25519 => "ed25519".to_string(),
                            rssh_core::keyfile::KeyType::Rsa => "rsa".to_string(),
                        };

                        // Load the key into RAM
                        // Note: The load_key method expects wire format, and we're now storing wire format
                        // This is consistent with the import functionality
                        if let Err(e) = ram_store.load_key(
                            &fingerprint_hex,
                            &wire_key_data,
                            key_payload.description,
                            key_type_str,
                            key_payload.cert_openssh_b64.is_some(),
                        ) {
                            tracing::warn!("Failed to load newly created key to RAM: {}", e);
                            // Don't fail the entire operation if RAM loading fails
                        } else {
                            tracing::debug!("Loaded newly created key to RAM");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to decode key data for RAM loading: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read keyfile for RAM loading: {}", e);
            }
        }
    }

    // Create success response
    let response = ManageCreateResponse {
        ok: true,
        error: None,
        fingerprint: Some(fingerprint_hex),
        public_key: Some(public_key_b64),
    };

    wrap_manage_create_response(response)
}

/// Helper function to enumerate keyfile fingerprints in a directory
fn enumerate_keyfiles(storage_dir: &str) -> Result<Vec<String>> {
    let mut fingerprints = Vec::new();

    let entries = fs::read_dir(storage_dir)
        .map_err(|e| Error::Internal(format!("Failed to read storage directory: {}", e)))?;

    for entry in entries {
        let entry =
            entry.map_err(|e| Error::Internal(format!("Failed to read directory entry: {}", e)))?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if file_name.starts_with("sha256-")
            && file_name.ends_with(".json")
            && let Some(fingerprint) = file_name
                .strip_prefix("sha256-")
                .and_then(|s| s.strip_suffix(".json"))
        {
            fingerprints.push(fingerprint.to_string());
        }
    }

    Ok(fingerprints)
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
    // ... extension-specific data (CBOR in our case for rssh-agent@local)

    // Note: The message type (27) has already been consumed by the agent,
    // so data[0] is the first byte of the actual extension message.

    // Check if this looks like direct CBOR (starts with CBOR map marker 0xA0-0xBF)
    // This might happen if TUI sends CBOR directly
    if !data.is_empty() && data[0] >= 0xA0 && data[0] <= 0xBF {
        tracing::debug!("Detected direct CBOR data (marker: 0x{:02x})", data[0]);
        let request: ExtensionRequest = ciborium::from_reader(data)
            .map_err(|e| Error::Internal(format!("CBOR decoding error: {}", e)))?;
        return Ok(request);
    }

    // Parse as SSH wire protocol with extension name
    let mut offset = 0;

    // Skip the message type byte if present
    if !data.is_empty() && data[0] == 27 {
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

    // Handle different extension namespaces
    match ext_name {
        EXTENSION_NAMESPACE => {
            // Custom rssh-agent@local extensions with CBOR data
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
            // OpenSSH session-bind extension with binary data
            tracing::debug!("Handling OpenSSH session-bind extension");

            // For session-bind, we create a synthetic ExtensionRequest
            // The actual parsing of session-bind data will be done by the handler
            Ok(ExtensionRequest {
                extension: ext_name.to_string(),
                data: data[offset..].to_vec(),
            })
        }
        _ => {
            // Other OpenSSH extensions that we don't specifically handle
            tracing::debug!("Received unknown OpenSSH extension: {}", ext_name);

            // Create a synthetic ExtensionRequest for unknown extensions
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

mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Debug, Serialize, Deserialize)]
    struct SetDescRequest {
        fp_sha256_hex: String,
        description: String,
    }

    #[test]
    fn test_set_desc_request_parsing() {
        // Test that we can parse a valid set_desc request
        let request = SetDescRequest {
            fp_sha256_hex: "abcd1234".to_string(),
            description: "Test description".to_string(),
        };

        let mut cbor_data = Vec::new();
        ciborium::into_writer(&request, &mut cbor_data).unwrap();

        // Try to parse it back
        let parsed: SetDescRequest = ciborium::from_reader(cbor_data.as_slice()).unwrap();

        assert_eq!(parsed.fp_sha256_hex, "abcd1234");
        assert_eq!(parsed.description, "Test description");
    }

    #[test]
    fn test_description_validation() {
        use rssh_core::keyfile::validate_description;

        // Valid descriptions
        assert!(validate_description("Valid description").is_ok());
        assert!(validate_description("A").is_ok());
        assert!(validate_description(&"x".repeat(256)).is_ok()); // Max length

        // Invalid descriptions
        assert!(validate_description("").is_err()); // Empty
        assert!(validate_description(&"x".repeat(257)).is_err()); // Too long
        assert!(validate_description("Contains\0null").is_err()); // Null character
        assert!(validate_description("Contains\rcarriage").is_err()); // CR
        assert!(validate_description("Contains\nnewline").is_err()); // LF
    }

    #[test]
    fn test_session_bind_extension_parsing() {
        // Test that we can parse a session-bind extension request
        let ext_name = "session-bind@openssh.com";
        let hostkey = b"test hostkey data";
        let session_id = b"test session identifier";
        let signature = b"test signature";
        let is_forwarding = true;

        // Build mock session-bind data according to OpenSSH wire format:
        // string hostkey
        // string session identifier
        // string signature
        // bool is_forwarding
        let mut data = Vec::new();

        // Write hostkey string
        data.extend_from_slice(&(hostkey.len() as u32).to_be_bytes());
        data.extend_from_slice(hostkey);

        // Write session identifier string
        data.extend_from_slice(&(session_id.len() as u32).to_be_bytes());
        data.extend_from_slice(session_id);

        // Write signature string
        data.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        data.extend_from_slice(signature);

        // Write is_forwarding boolean
        data.push(if is_forwarding { 1 } else { 0 });

        // Build the full SSH extension message
        let mut message = Vec::new();

        // Extension name length and value
        message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
        message.extend_from_slice(ext_name.as_bytes());

        // Extension data
        message.extend_from_slice(&data);

        // Test parsing
        let request = parse_extension_request(&message).unwrap();
        assert_eq!(request.extension, "session-bind@openssh.com");
        assert_eq!(request.data, data);
    }

    #[test]
    fn test_session_bind_handler() {
        // Test the session-bind handler with mock data
        let hostkey = b"test hostkey data";
        let session_id = b"test session identifier";
        let signature = b"test signature";
        let is_forwarding = false;

        // Build session-bind data
        let mut data = Vec::new();

        // Write hostkey string
        data.extend_from_slice(&(hostkey.len() as u32).to_be_bytes());
        data.extend_from_slice(hostkey);

        // Write session identifier string
        data.extend_from_slice(&(session_id.len() as u32).to_be_bytes());
        data.extend_from_slice(session_id);

        // Write signature string
        data.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        data.extend_from_slice(signature);

        // Write is_forwarding boolean
        data.push(if is_forwarding { 1 } else { 0 });

        // Test handler
        let response = handle_session_bind(&data).unwrap();

        // Should return SSH agent success message
        assert_eq!(response.len(), 1);
        assert_eq!(response[0], rssh_proto::wire::MessageType::Success as u8);
    }

    #[test]
    fn test_session_bind_insufficient_data() {
        // Test session-bind handler with insufficient data
        let insufficient_data = vec![0, 0, 0]; // Not enough for even hostkey length

        let response = handle_session_bind(&insufficient_data).unwrap();

        // Should return SSH agent failure message
        assert_eq!(response.len(), 1);
        assert_eq!(response[0], rssh_proto::wire::MessageType::Failure as u8);
    }

    #[test]
    fn test_unknown_openssh_extension() {
        // Test that unknown OpenSSH extensions are handled gracefully
        let ext_name = "unknown-ext@openssh.com";
        let data = b"some extension data";

        // Build the full SSH extension message
        let mut message = Vec::new();

        // Extension name length and value
        message.extend_from_slice(&(ext_name.len() as u32).to_be_bytes());
        message.extend_from_slice(ext_name.as_bytes());

        // Extension data
        message.extend_from_slice(data);

        // Test parsing
        let request = parse_extension_request(&message).unwrap();
        assert_eq!(request.extension, "unknown-ext@openssh.com");
        assert_eq!(request.data, data);
    }

    #[test]
    fn test_manage_delete_request_parsing() {
        use rssh_proto::cbor::{ManageDeleteRequest, ManageDeleteResponse};

        // Test that we can parse a valid delete request
        let request = ManageDeleteRequest {
            fp_sha256_hex: "1234567890abcdef".to_string(),
        };

        let mut cbor_data = Vec::new();
        ciborium::into_writer(&request, &mut cbor_data).unwrap();

        // Try to parse it back
        let parsed: ManageDeleteRequest = ciborium::from_reader(cbor_data.as_slice()).unwrap();
        assert_eq!(parsed.fp_sha256_hex, "1234567890abcdef");

        // Test response structure
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
