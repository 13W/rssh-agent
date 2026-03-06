use rssh_core::{Error, Result};
use serde::Deserialize;
use std::sync::Arc;

use super::cbor_success;

/// Handle manage.set_constraints extension - sets constraints for a loaded key in RAM immediately
pub fn handle_manage_set_constraints(
    data: &[u8],
    ram_store: &Arc<rssh_core::ram_store::RamStore>,
) -> Result<Vec<u8>> {
    #[derive(Debug, Deserialize)]
    struct SetConstraintsRequest {
        fp_sha256_hex: String,
        confirm: bool,
        #[serde(default)]
        notification: bool,
        lifetime_seconds: Option<u64>,
    }

    let request: SetConstraintsRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse set_constraints request: {}", e)))?;

    ram_store
        .set_constraints(
            &request.fp_sha256_hex,
            request.confirm,
            request.notification,
            request.lifetime_seconds,
        )
        .map_err(|e| match e {
            rssh_core::Error::NotFound => Error::NotFound,
            rssh_core::Error::NeedMasterUnlock => Error::Internal("Agent locked".to_string()),
            _ => Error::Internal(format!("Failed to update constraints: {}", e)),
        })?;

    tracing::info!(
        "Updated constraints for loaded key {}: confirm={}, notification={}, lifetime={:?}",
        &request.fp_sha256_hex[..12],
        request.confirm,
        request.notification,
        request.lifetime_seconds
    );

    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": request.fp_sha256_hex,
        "confirm": request.confirm,
        "notification": request.notification,
        "lifetime_seconds": request.lifetime_seconds
    });

    cbor_success(response_data)
}

/// Handle manage.set_default_constraints extension - sets default constraints for a key
pub fn handle_manage_set_default_constraints(
    data: &[u8],
    storage_dir: Option<&str>,
    master_password: &str,
) -> Result<Vec<u8>> {
    use rssh_core::keyfile::KeyFile;

    #[derive(Debug, Deserialize)]
    struct SetDefaultConstraintsRequest {
        fp_sha256_hex: String,
        default_confirm: bool,
        #[serde(default)]
        default_notification: bool,
        default_lifetime_seconds: Option<u64>,
    }

    let request: SetDefaultConstraintsRequest =
        ciborium::from_reader(data).map_err(|e| {
            Error::Internal(format!(
                "Failed to parse set_default_constraints request: {}",
                e
            ))
        })?;

    let storage_dir = storage_dir
        .ok_or_else(|| Error::Internal("Storage directory not configured".to_string()))?;

    KeyFile::update_default_constraints(
        storage_dir,
        &request.fp_sha256_hex,
        master_password,
        request.default_confirm,
        request.default_notification,
        request.default_lifetime_seconds,
    )
    .map_err(|e| match e {
        Error::NotFound => Error::NotFound,
        Error::WrongPassword => Error::WrongPassword,
        _ => Error::Internal(format!("Failed to update default constraints: {}", e)),
    })?;

    tracing::debug!(
        "Updated default constraints for key {}: confirm={}, notification={}, lifetime={:?}",
        &request.fp_sha256_hex[..12],
        request.default_confirm,
        request.default_notification,
        request.default_lifetime_seconds
    );

    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": request.fp_sha256_hex,
        "default_confirm": request.default_confirm,
        "default_notification": request.default_notification,
        "default_lifetime_seconds": request.default_lifetime_seconds
    });

    cbor_success(response_data)
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

    let request: SetDescRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse set_desc request: {}", e)))?;

    let storage_dir = storage_dir
        .ok_or_else(|| Error::Internal("Storage directory not configured".to_string()))?;

    rssh_core::keyfile::validate_description(&request.description)
        .map_err(|e| Error::Config(format!("Invalid description: {}", e)))?;

    let mut key_payload = KeyFile::read(storage_dir, &request.fp_sha256_hex, master_password)
        .map_err(|e| match e {
            Error::NotFound => Error::NotFound,
            Error::WrongPassword => Error::WrongPassword,
            _ => Error::Internal(format!("Failed to read key file: {}", e)),
        })?;

    key_payload.description = request.description.clone();
    key_payload.updated = Utc::now();

    KeyFile::write(
        storage_dir,
        &request.fp_sha256_hex,
        &key_payload,
        master_password,
    )?;
    let _ = ram_store.update_description(&request.fp_sha256_hex, request.description.clone());

    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": request.fp_sha256_hex,
        "description": request.description
    });

    cbor_success(response_data)
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
    use sha2::{Digest, Sha256};

    #[derive(Debug, Deserialize)]
    struct UpdateCertRequest {
        fp_sha256_hex: String,
        cert_openssh_b64: String,
    }

    let request: UpdateCertRequest = ciborium::from_reader(data)
        .map_err(|e| Error::Internal(format!("Failed to parse update_cert request: {}", e)))?;

    let cert_data = BASE64
        .decode(&request.cert_openssh_b64)
        .map_err(|_| Error::BadCertFormat)?;

    let cert_str = std::str::from_utf8(&cert_data).map_err(|_| Error::BadCertFormat)?;

    // SSH certificates start with ssh-rsa-cert-v01@openssh.com, ssh-ed25519-cert-v01@openssh.com, etc.
    if !cert_str.contains("-cert-v01@openssh.com") {
        return Err(Error::BadCertFormat);
    }

    let cert = validate_certificate_format(&cert_data)?;

    // Validate that the certificate's public key fingerprint matches the stored key.
    // This prevents attaching a certificate for a different key to an existing slot.
    let subject_key = ssh_key::PublicKey::new(cert.public_key().clone(), "");
    let pub_key_blob = subject_key
        .to_bytes()
        .map_err(|_| Error::BadCertFormat)?;
    let mut hasher = Sha256::new();
    hasher.update(&pub_key_blob);
    let cert_fp = hex::encode(hasher.finalize());

    if cert_fp != request.fp_sha256_hex {
        return Err(Error::CertMismatch);
    }

    let mut payload = KeyFile::read(storage_dir, &request.fp_sha256_hex, master_password)?;

    payload.cert_openssh_b64 = Some(request.cert_openssh_b64.clone());
    payload.updated = Utc::now();

    KeyFile::write(
        storage_dir,
        &request.fp_sha256_hex,
        &payload,
        master_password,
    )?;

    let response_data = serde_json::json!({
        "ok": true,
        "fp_sha256_hex": request.fp_sha256_hex
    });

    cbor_success(response_data)
}

/// Validate SSH certificate format and return the parsed certificate
fn validate_certificate_format(cert_data: &[u8]) -> rssh_core::Result<ssh_key::Certificate> {
    use ssh_key::Certificate;

    let cert_str = std::str::from_utf8(cert_data).map_err(|_| Error::BadCertFormat)?;
    Certificate::from_openssh(cert_str).map_err(|_| Error::BadCertFormat)
}
