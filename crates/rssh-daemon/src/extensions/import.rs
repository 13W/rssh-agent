use rssh_core::{Error, Result};
use serde::Deserialize;

use super::cbor_success;

/// Handle manage.import extension - imports an external key to persistent storage
pub async fn handle_manage_import(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
    storage_dir: &str,
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

    let request: ImportRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse import request: {}", e)))?;

    let key_data = ram_store.get_external_key_data(&request.fp_sha256_hex)?;

    let keys = ram_store.list_keys()?;
    let key_info = keys
        .iter()
        .find(|k| k.fingerprint == request.fp_sha256_hex)
        .ok_or(Error::NotFound)?;

    // Try to extract comment from the SSH key if no description is provided
    let key_comment_description = if request.description.is_none() {
        match KeyFile::ssh_key_from_wire_format(
            &key_data,
            &match key_info.key_type.as_str() {
                "ed25519" => KeyType::Ed25519,
                "rsa" => KeyType::Rsa,
                _ => KeyType::Ed25519,
            },
        ) {
            Ok(internal_ssh_key) => match internal_ssh_key.to_openssh(None, None) {
                Ok(openssh_data) => match std::str::from_utf8(&openssh_data) {
                    Ok(openssh_str) => match ssh_key::PrivateKey::from_openssh(openssh_str) {
                        Ok(ssh_key) => {
                            let comment = ssh_key.comment();
                            if comment.is_empty() {
                                None
                            } else {
                                Some(comment.to_string())
                            }
                        }
                        Err(_) => {
                            tracing::debug!("Could not parse OpenSSH key to extract comment");
                            None
                        }
                    },
                    Err(_) => {
                        tracing::debug!("OpenSSH data is not valid UTF-8");
                        None
                    }
                },
                Err(_) => {
                    tracing::debug!("Could not convert internal key to OpenSSH format");
                    None
                }
            },
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
        None
    } else {
        None
    };

    let key_password = if request.set_key_password {
        if let Some(pass_b64) = &request.new_key_pass_b64 {
            let pass_bytes = BASE64
                .decode(pass_b64)
                .map_err(|e| Error::Config(format!("Invalid base64 key password: {}", e)))?;
            let pass_string = std::str::from_utf8(&pass_bytes)
                .map_err(|e| Error::Config(format!("Invalid UTF-8 key password: {}", e)))?
                .to_string();

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

    let now = Utc::now();
    let secret_openssh_b64;
    let password_protected;

    if let Some(password) = &key_password {
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
        default_confirm: false,
        default_notification: false,
        default_lifetime_seconds: None,
        pub_key_fingerprint_sha256: String::new(), // set by write_payload
        created: now,
        updated: now,
    };

    KeyFile::write(
        storage_dir,
        &request.fp_sha256_hex,
        &payload,
        master_password,
    )?;

    ram_store.mark_key_as_internal(&request.fp_sha256_hex)?;

    tracing::info!(
        "Successfully imported key {} with {} password protection",
        request.fp_sha256_hex,
        if password_protected { "" } else { "no" }
    );

    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": request.fp_sha256_hex
    });

    cbor_success(response_data)
}

/// Handle manage.import_direct extension - imports an SSH key directly from file data to persistent storage
pub async fn handle_manage_import_direct(
    data: &[u8],
    storage_dir: &str,
    master_password: &str,
) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use chrono::Utc;
    use rssh_core::keyfile::{KeyFile, KeyPayload, KeyType};
    use ssh_key::rand_core::OsRng;

    #[derive(Debug, Deserialize)]
    struct ImportDirectRequest {
        key_data_openssh_b64: String,
        description: Option<String>,
        set_key_password: Option<bool>,
        new_key_pass_b64: Option<String>,
        preserve_original_protection: Option<bool>,
    }

    let request: ImportDirectRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse import_direct request: {}", e)))?;

    let key_data = BASE64
        .decode(&request.key_data_openssh_b64)
        .map_err(|e| Error::Config(format!("Invalid base64 key data: {}", e)))?;

    let key_content = std::str::from_utf8(&key_data)
        .map_err(|e| Error::Config(format!("Invalid UTF-8 in key data: {}", e)))?;

    let ssh_key = ssh_key::PrivateKey::from_openssh(key_content)
        .map_err(|e| Error::Config(format!("Invalid SSH key format: {}", e)))?;

    let original_is_encrypted = ssh_key.is_encrypted();

    let public_key = ssh_key.public_key();
    let fingerprint = public_key.fingerprint(ssh_key::HashAlg::Sha256);
    let fingerprint_hex = hex::encode(fingerprint.as_bytes());

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

    rssh_core::keyfile::validate_description(&description)
        .map_err(|e| Error::Config(format!("Invalid description: {}", e)))?;

    let (secret_openssh_b64, password_protected) =
        if request.preserve_original_protection.unwrap_or(false) {
            if original_is_encrypted {
                tracing::debug!("Preserving original password protection");
                (BASE64.encode(key_content.as_bytes()), true)
            } else {
                tracing::debug!("Converting unprotected key to wire format");
                let ssh_private_key = rssh_core::openssh::SshPrivateKey::from_openssh(
                    key_content.as_bytes(),
                    None,
                )?;
                let wire_data = ssh_private_key.to_wire_format().map_err(|e| {
                    Error::Internal(format!("Failed to convert to wire format: {}", e))
                })?;
                (BASE64.encode(&wire_data), false)
            }
        } else if request.set_key_password.unwrap_or(false) {
            if let Some(pass_b64) = &request.new_key_pass_b64 {
                let pass_bytes = BASE64
                    .decode(pass_b64)
                    .map_err(|e| Error::Config(format!("Invalid base64 key password: {}", e)))?;
                let pass_string = std::str::from_utf8(&pass_bytes)
                    .map_err(|e| Error::Config(format!("Invalid UTF-8 key password: {}", e)))?
                    .to_string();

                if pass_string.len() < 4 || pass_string.len() > 1024 {
                    return Err(Error::Config(
                        "Key password must be between 4 and 1024 characters".to_string(),
                    ));
                }

                let decrypted_key = if original_is_encrypted {
                    return Err(Error::Config(
                        "Cannot set new password on encrypted key without providing original passphrase".to_string(),
                    ));
                } else {
                    ssh_key.clone()
                };

                tracing::debug!("Encrypting key with new password");
                let protected_key = decrypted_key
                    .encrypt(&mut OsRng, pass_string.as_bytes())
                    .map_err(|e| {
                        Error::Internal(format!("Failed to encrypt key with new password: {}", e))
                    })?;

                let protected_data = protected_key
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
            tracing::debug!("Converting key to wire format (no password protection)");

            let decrypted_key = if original_is_encrypted {
                return Err(Error::Config(
                    "Cannot import encrypted key without providing passphrase or using preserve_original_protection".to_string(),
                ));
            } else {
                ssh_key.clone()
            };

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

    let now = Utc::now();

    let payload = KeyPayload {
        key_type,
        description: description.clone(),
        secret_openssh_b64,
        cert_openssh_b64: None,
        password_protected,
        default_confirm: false,
        default_notification: false,
        default_lifetime_seconds: None,
        pub_key_fingerprint_sha256: String::new(), // set by write_payload
        created: now,
        updated: now,
    };

    KeyFile::write(storage_dir, &fingerprint_hex, &payload, master_password)?;

    tracing::info!(
        "Successfully imported key {} directly to disk with {} password protection",
        fingerprint_hex,
        if password_protected { "" } else { "no" }
    );

    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": fingerprint_hex,
        "description": description
    });

    cbor_success(response_data)
}

/// Handle manage.set_password extension - sets or removes password protection for existing stored keys
pub async fn handle_manage_set_password(
    data: &[u8],
    ram_store: &rssh_core::ram_store::RamStore,
    storage_dir: &str,
    master_password: &str,
) -> Result<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rssh_core::keyfile::KeyFile;
    use rssh_proto::cbor::{ManageSetPasswordRequest, ManageSetPasswordResponse};

    let request: ManageSetPasswordRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse set_password request: {}", e)))?;

    tracing::debug!(
        "Processing set_password request for key: {} (set_protection: {})",
        request.fp_sha256_hex,
        request.set_password_protection
    );

    if request.set_password_protection && request.new_key_pass_b64.is_none() {
        return wrap_manage_set_password_response(ManageSetPasswordResponse {
            ok: false,
            error: Some(
                "new_key_pass_b64 is required when set_password_protection is true".to_string(),
            ),
            fingerprint: Some(request.fp_sha256_hex.clone()),
        });
    }

    let keyfile_path =
        std::path::Path::new(storage_dir).join(format!("sha256-{}.json", request.fp_sha256_hex));
    if !keyfile_path.exists() {
        return wrap_manage_set_password_response(ManageSetPasswordResponse {
            ok: false,
            error: Some("Key is not stored on disk. Create or import the key first.".to_string()),
            fingerprint: Some(request.fp_sha256_hex.clone()),
        });
    }

    if let Ok(keys) = ram_store.list_keys() {
        if let Some(key_info) = keys.iter().find(|k| k.fingerprint == request.fp_sha256_hex) {
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

    let mut payload = KeyFile::read(storage_dir, &request.fp_sha256_hex, master_password)
        .map_err(|e| Error::Internal(format!("Failed to read existing keyfile: {}", e)))?;

    tracing::debug!(
        "Read keyfile: type={:?}, password_protected={}, created={}, updated={}",
        payload.key_type,
        payload.password_protected,
        payload.created,
        payload.updated
    );

    let current_key_password = if payload.password_protected {
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
        None
    };

    let new_key_password = if request.set_password_protection {
        let pass_b64 = request.new_key_pass_b64.as_ref().unwrap();
        let pass_bytes = BASE64
            .decode(pass_b64)
            .map_err(|e| Error::Config(format!("Invalid base64 new key password: {}", e)))?;
        let pass_string = std::str::from_utf8(&pass_bytes)
            .map_err(|e| Error::Config(format!("Invalid UTF-8 new key password: {}", e)))?;

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

    let ssh_key = if payload.password_protected {
        tracing::debug!("Parsing key from OpenSSH format with current password");
        rssh_core::openssh::SshPrivateKey::from_openssh(
            &current_key_bytes,
            current_key_password.as_deref(),
        )
        .map_err(|e| Error::Internal(format!("Failed to parse existing OpenSSH key: {}", e)))?
    } else {
        tracing::debug!("Converting key from wire format to OpenSSH format");
        KeyFile::ssh_key_from_wire_format(&current_key_bytes, &payload.key_type)
            .map_err(|e| Error::Internal(format!("Failed to convert wire format key: {}", e)))?
    };

    tracing::debug!(
        "Successfully parsed SSH key, algorithm: {:?}",
        ssh_key.algorithm()
    );

    let new_key_bytes = if request.set_password_protection {
        let key_password = new_key_password.as_ref().unwrap();
        tracing::debug!("Serializing key with password protection (OpenSSH format)");
        ssh_key.to_openssh(Some(key_password), None).map_err(|e| {
            Error::Internal(format!("Failed to serialize key with new password: {}", e))
        })?
    } else {
        tracing::debug!("Serializing key without password protection (wire format)");
        ssh_key.to_wire_format().map_err(|e| {
            Error::Internal(format!("Failed to serialize key to wire format: {}", e))
        })?
    };

    tracing::debug!("Successfully serialized key: {} bytes", new_key_bytes.len());

    payload.secret_openssh_b64 = BASE64.encode(&new_key_bytes);
    payload.password_protected = request.set_password_protection;
    payload.updated = chrono::Utc::now();

    tracing::debug!(
        "Updated payload: password_protected={}, updated={}",
        payload.password_protected,
        payload.updated
    );

    KeyFile::write(
        storage_dir,
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
