use rssh_core::{Error, Result, ram_store::KeyInfo};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;

use super::cbor_success;

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
    let mut managed_keys: Vec<ManagedKey> = ram_keys
        .into_iter()
        .map(|key| {
            let key_on_disk = disk_fingerprints.contains(&key.fingerprint);

            // If key exists on disk, it's internal regardless of how it was loaded
            let is_internal = key_on_disk || !key.is_external;

            let format = match key.key_type.as_str() {
                "ed25519" => "ssh-ed25519",
                "rsa" => "rsa-sha2-512",
                _ => &key.key_type,
            }
            .to_string();

            let constraints = serde_json::json!({
                "confirm": key.confirm,
                "notification": key.notification,
                "lifetime_expires_at": key.lifetime_expires_at.map(|t| {
                    let duration = t.duration_since(std::time::Instant::now());
                    let expires_at = Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64);
                    expires_at.to_rfc3339()
                }),
            });

            // For loaded keys that exist on disk, check metadata for password protection and default constraints
            let (originally_password_protected, default_constraints) = if key_on_disk {
                if let (Some(dir), Some(master_pwd)) = (storage_dir, master_password) {
                    match KeyFile::read_metadata(dir, &key.fingerprint, master_pwd) {
                        Ok(metadata) => {
                            let defaults = Some(serde_json::json!({
                                "default_confirm": metadata.default_confirm,
                                "default_notification": metadata.default_notification,
                                "default_lifetime_seconds": metadata.default_lifetime_seconds,
                            }));
                            (metadata.password_protected, defaults)
                        }
                        Err(_) => (false, None),
                    }
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            };

            ManagedKey {
                fp_sha256_hex: key.fingerprint.clone(),
                key_type: key.key_type,
                format,
                description: key.description,
                source: if is_internal {
                    "internal".to_string()
                } else {
                    "external".to_string()
                },
                loaded: true,
                has_disk: key_on_disk,
                has_cert: key.has_cert,
                password_protected: originally_password_protected,
                constraints,
                default_constraints,
                created: Some(key.created.to_rfc3339()),
                updated: key.updated.map(|t| t.to_rfc3339()),
            }
        })
        .collect();

    // Add disk keys that are not loaded
    for fingerprint in disk_fingerprints {
        if loaded_fingerprints.contains(&fingerprint) {
            continue;
        }

        if let (Some(dir), Some(master_pwd)) = (storage_dir, master_password) {
            match KeyFile::read_metadata(dir, &fingerprint, master_pwd) {
                Ok(metadata) => {
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
                        source: "internal".to_string(),
                        loaded: false,
                        has_disk: true,
                        has_cert: metadata.has_cert,
                        password_protected: metadata.password_protected,
                        constraints: serde_json::json!({
                            "confirm": false,
                            "notification": false,
                            "lifetime_expires_at": null,
                        }),
                        default_constraints: Some(serde_json::json!({
                            "default_confirm": metadata.default_confirm,
                            "default_notification": metadata.default_notification,
                            "default_lifetime_seconds": metadata.default_lifetime_seconds,
                        })),
                        created: Some(metadata.created.to_rfc3339()),
                        updated: Some(metadata.updated.to_rfc3339()),
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to read metadata for key {}: {}", fingerprint, e);
                    managed_keys.push(ManagedKey {
                        fp_sha256_hex: fingerprint,
                        key_type: "unknown".to_string(),
                        format: "unknown".to_string(),
                        description: "[error reading metadata]".to_string(),
                        source: "internal".to_string(),
                        loaded: false,
                        has_disk: true,
                        has_cert: false,
                        password_protected: false,
                        constraints: serde_json::json!({
                            "confirm": false,
                            "notification": false,
                            "lifetime_expires_at": null,
                        }),
                        default_constraints: None,
                        created: None,
                        updated: None,
                    });
                }
            }
        } else {
            managed_keys.push(ManagedKey {
                fp_sha256_hex: fingerprint,
                key_type: "unknown".to_string(),
                format: "unknown".to_string(),
                description: "".to_string(),
                source: "internal".to_string(),
                loaded: false,
                has_disk: true,
                has_cert: false,
                password_protected: false,
                constraints: serde_json::json!({
                    "confirm": false,
                    "notification": false,
                    "lifetime_expires_at": null,
                }),
                default_constraints: None,
                created: None,
                updated: None,
            });
        }
    }

    // Serialize response using ManageListResponse (has its own CBOR wrapper)
    let list_response = ManageListResponse {
        ok: true,
        keys: managed_keys,
    };

    let mut data_cbor = Vec::new();
    ciborium::into_writer(&list_response, &mut data_cbor)
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
        confirm: Option<bool>,
        #[serde(default)]
        notification: Option<bool>,
        lifetime_seconds: Option<u32>,
    }

    let request: LoadRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse load request: {}", e)))?;

    let storage_dir = storage_dir
        .ok_or_else(|| Error::Internal("Storage directory not configured".to_string()))?;

    let metadata = KeyFile::read_metadata(storage_dir, &request.fp_sha256_hex, master_password)?;

    let wire_key_data = if metadata.password_protected {
        let key_password = if let Some(pass_b64) = &request.key_pass_b64 {
            let pass_bytes = BASE64
                .decode(pass_b64)
                .map_err(|e| Error::Config(format!("Invalid base64 key password: {}", e)))?;
            let pass_string = std::str::from_utf8(&pass_bytes)
                .map_err(|e| Error::Config(format!("Invalid UTF-8 key password: {}", e)))?
                .to_string();
            Some(pass_string)
        } else {
            return Err(Error::NeedKeyPassword);
        };

        let ssh_key = KeyFile::read_ssh_key(
            storage_dir,
            &request.fp_sha256_hex,
            master_password,
            key_password.as_deref(),
        )?;

        ssh_key.to_wire_format()?
    } else {
        let key_payload = KeyFile::read(storage_dir, &request.fp_sha256_hex, master_password)?;

        BASE64
            .decode(&key_payload.secret_openssh_b64)
            .map_err(|e| Error::Internal(format!("Failed to decode key data: {}", e)))?
    };

    let key_type_str = match metadata.key_type {
        rssh_core::keyfile::KeyType::Ed25519 => "ed25519".to_string(),
        rssh_core::keyfile::KeyType::Rsa => "rsa".to_string(),
    };

    // Determine final constraints using precedence:
    // 1. Explicit request parameters (highest priority)
    // 2. Stored default constraints from keyfile metadata
    // 3. System defaults (false/None) (lowest priority)
    let final_confirm = request.confirm.unwrap_or(metadata.default_confirm);
    let final_notification = request
        .notification
        .unwrap_or(metadata.default_notification);
    let final_lifetime_secs = request
        .lifetime_seconds
        .map(|secs| secs as u64)
        .or(metadata.default_lifetime_seconds);

    ram_store.load_key_with_defaults(
        &request.fp_sha256_hex,
        &wire_key_data,
        metadata.description,
        key_type_str,
        metadata.has_cert,
        final_confirm,
        final_notification,
        final_lifetime_secs,
    )?;

    tracing::debug!(
        "Loaded key {} with constraints: confirm={}, notification={}, lifetime={:?}",
        &request.fp_sha256_hex[..12],
        final_confirm,
        final_notification,
        final_lifetime_secs
    );

    let response_data = serde_json::json!({
        "ok": true,
    });

    cbor_success(response_data)
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

    let request: UnloadRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse unload request: {}", e)))?;

    ram_store.unload_key(&request.fp_sha256_hex)?;

    let response_data = serde_json::json!({
        "ok": true,
    });

    cbor_success(response_data)
}

/// Handle manage.delete extension - permanently deletes a key from disk storage
pub fn handle_manage_delete(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
    storage_dir: Option<&str>,
) -> Result<Vec<u8>> {
    use rssh_proto::cbor::{ManageDeleteRequest, ManageDeleteResponse};

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

    let keyfile_path =
        std::path::Path::new(storage_dir).join(format!("sha256-{}.json", request.fp_sha256_hex));

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

/// Helper function to wrap a ManageDeleteResponse in ExtensionResponse
fn wrap_manage_delete_response(response: rssh_proto::cbor::ManageDeleteResponse) -> Result<Vec<u8>> {
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    let extension_response = rssh_proto::cbor::ExtensionResponse {
        success: response.ok,
        data: data_cbor,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&extension_response, &mut cbor_data)
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
    use rssh_core::keyfile::{calculate_fingerprint_hex, KeyFile, KeyPayload, KeyType};
    use rssh_core::openssh::SshPrivateKey;
    use rssh_proto::cbor::{ManageCreateRequest, ManageCreateResponse};

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

    let public_key_bytes = private_key.public_key_bytes();
    let fingerprint_hex = calculate_fingerprint_hex(&public_key_bytes);

    let wire_key_data = private_key.to_wire_format().map_err(|e| {
        Error::Internal(format!(
            "Failed to serialize private key to wire format: {}",
            e
        ))
    })?;
    let secret_openssh_b64 = BASE64.encode(&wire_key_data);

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

    let description = request.description.unwrap_or_else(|| match key_type {
        KeyType::Ed25519 => "Generated Ed25519 key".to_string(),
        KeyType::Rsa => {
            let bits = private_key.rsa_bits().unwrap_or(2048);
            format!("Generated RSA {} key", bits)
        }
    });

    if let Err(e) = rssh_core::keyfile::validate_description(&description) {
        let response = ManageCreateResponse {
            ok: false,
            error: Some(format!("Invalid description: {}", e)),
            fingerprint: None,
            public_key: None,
        };
        return wrap_manage_create_response(response);
    }

    let now = Utc::now();
    let payload = KeyPayload {
        key_type,
        description: description.clone(),
        secret_openssh_b64,
        cert_openssh_b64: None,
        password_protected: false,
        default_confirm: request.confirm.unwrap_or(false),
        default_notification: request.notification.unwrap_or(false),
        default_lifetime_seconds: request.lifetime_seconds.map(|s| s as u64),
        pub_key_fingerprint_sha256: String::new(), // set by write_payload
        created: now,
        updated: now,
    };

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

    if request.load_to_ram {
        match KeyFile::read(storage_dir, &fingerprint_hex, master_password) {
            Ok(key_payload) => {
                match BASE64.decode(&key_payload.secret_openssh_b64) {
                    Ok(wire_key_data) => {
                        let key_type_str = match key_payload.key_type {
                            rssh_core::keyfile::KeyType::Ed25519 => "ed25519".to_string(),
                            rssh_core::keyfile::KeyType::Rsa => "rsa".to_string(),
                        };

                        if let Err(e) = ram_store.load_key_with_defaults(
                            &fingerprint_hex,
                            &wire_key_data,
                            key_payload.description,
                            key_type_str,
                            key_payload.cert_openssh_b64.is_some(),
                            key_payload.default_confirm,
                            key_payload.default_notification,
                            key_payload.default_lifetime_seconds,
                        ) {
                            tracing::warn!("Failed to load newly created key to RAM: {}", e);
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

    let response = ManageCreateResponse {
        ok: true,
        error: None,
        fingerprint: Some(fingerprint_hex),
        public_key: Some(public_key_b64),
    };

    wrap_manage_create_response(response)
}

/// Helper function to wrap a ManageCreateResponse in ExtensionResponse
fn wrap_manage_create_response(
    response: rssh_proto::cbor::ManageCreateResponse,
) -> Result<Vec<u8>> {
    let mut data_cbor = Vec::new();
    ciborium::into_writer(&response, &mut data_cbor)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    let extension_response = rssh_proto::cbor::ExtensionResponse {
        success: response.ok,
        data: data_cbor,
    };

    let mut cbor_data = Vec::new();
    ciborium::into_writer(&extension_response, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    Ok(cbor_data)
}
