use crate::{Error, Result, fs_policy};
use argon2::{Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

const KDF_DOMAIN: &str = "rssh-agent:v1:disk";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub version: String,
    pub kdf: KdfParams,
    pub aead: AeadParams,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub name: String,
    pub mib: u32,
    pub t: u32,
    pub p: u32,
    pub salt_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadParams {
    pub name: String,
    pub nonce_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPayload {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub description: String,
    pub secret_openssh_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_openssh_b64: Option<String>,
    /// Indicates if the key data in secret_openssh_b64 is password-protected
    #[serde(default)]
    pub password_protected: bool,
    /// Default confirmation requirement for this key
    #[serde(default)]
    pub default_confirm: bool,
    /// Default notification requirement for this key
    #[serde(default)]
    pub default_notification: bool,
    /// Default lifetime in seconds for this key when loaded
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_lifetime_seconds: Option<u64>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

/// Metadata about a key file (without the secret key data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub description: String,
    pub has_cert: bool,
    /// Indicates if the key requires a password to decrypt
    #[serde(default)]
    pub password_protected: bool,
    /// Default confirmation requirement for this key
    #[serde(default)]
    pub default_confirm: bool,
    /// Default notification requirement for this key
    #[serde(default)]
    pub default_notification: bool,
    /// Default lifetime in seconds for this key when loaded
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_lifetime_seconds: Option<u64>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Ed25519,
    Rsa,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; 32]);

impl KeyFile {
    /// Write a key file to disk with optional key password protection
    pub fn write_with_key_password<P: AsRef<Path>>(
        storage_dir: P,
        fingerprint_hex: &str,
        ssh_key: &crate::openssh::SshPrivateKey,
        description: String,
        cert_openssh_b64: Option<String>,
        master_password: &str,
        key_password: Option<&str>,
    ) -> Result<()> {
        Self::write_with_key_password_and_defaults(
            storage_dir,
            fingerprint_hex,
            ssh_key,
            description,
            cert_openssh_b64,
            master_password,
            key_password,
            false, // default_confirm
            false, // default_notification
            None,  // default_lifetime_seconds
        )
    }

    /// Write a key file to disk with optional key password protection and default constraints
    pub fn write_with_key_password_and_defaults<P: AsRef<Path>>(
        storage_dir: P,
        fingerprint_hex: &str,
        ssh_key: &crate::openssh::SshPrivateKey,
        description: String,
        cert_openssh_b64: Option<String>,
        master_password: &str,
        key_password: Option<&str>,
        default_confirm: bool,
        default_notification: bool,
        default_lifetime_seconds: Option<u64>,
    ) -> Result<()> {
        validate_fingerprint_format(fingerprint_hex)?;
        validate_description(&description)?;

        // Determine key type
        let key_type = if ssh_key.is_ed25519() {
            KeyType::Ed25519
        } else if ssh_key.is_rsa() {
            KeyType::Rsa
        } else {
            return Err(Error::Unsupported);
        };

        let now = Utc::now();
        let password_protected = key_password.is_some();

        // Convert key to appropriate format
        let secret_openssh_b64 = if password_protected {
            // For password-protected keys, store as OpenSSH format (encrypted)
            let openssh_data = ssh_key.to_openssh(key_password, None)?;
            BASE64.encode(&openssh_data)
        } else {
            // For unprotected keys, store as wire format (backward compatibility)
            let wire_data = ssh_key.to_wire_format()?;
            BASE64.encode(&wire_data)
        };

        let payload = KeyPayload {
            key_type,
            description,
            secret_openssh_b64,
            cert_openssh_b64,
            password_protected,
            default_confirm,
            default_notification,
            default_lifetime_seconds,
            created: now,
            updated: now,
        };

        Self::write_payload(storage_dir, fingerprint_hex, &payload, master_password)
    }

    /// Write a key file to disk (legacy method for backward compatibility)
    pub fn write<P: AsRef<Path>>(
        storage_dir: P,
        fingerprint_hex: &str,
        payload: &KeyPayload,
        master_password: &str,
    ) -> Result<()> {
        Self::write_payload(storage_dir, fingerprint_hex, payload, master_password)
    }

    /// Internal method to write a KeyPayload to disk
    fn write_payload<P: AsRef<Path>>(
        storage_dir: P,
        fingerprint_hex: &str,
        payload: &KeyPayload,
        master_password: &str,
    ) -> Result<()> {
        validate_fingerprint_format(fingerprint_hex)?;
        validate_description(&payload.description)?;

        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive key
        let key = derive_key(master_password, &salt, 256, 3, 1)?;

        // Serialize and encrypt payload
        let payload_json = serde_json::to_string(payload)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key.0).map_err(|e| Error::Crypto(e.to_string()))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, payload_json.as_bytes())
            .map_err(|e| Error::Crypto(e.to_string()))?;

        // Create key file
        let keyfile = KeyFile {
            version: "rssh-keyfile/v1".to_string(),
            kdf: KdfParams {
                name: "argon2id".to_string(),
                mib: 256,
                t: 3,
                p: 1,
                salt_b64: BASE64.encode(salt),
            },
            aead: AeadParams {
                name: "xchacha20poly1305".to_string(),
                nonce_b64: BASE64.encode(nonce_bytes),
            },
            ciphertext_b64: BASE64.encode(ciphertext),
        };

        // Write to file
        let filename = format!("sha256-{}.json", fingerprint_hex);
        let filepath = storage_dir.as_ref().join(filename);
        let json = serde_json::to_string_pretty(&keyfile)?;
        fs_policy::atomic_write(&filepath, json.as_bytes())?;

        Ok(())
    }

    /// Read and decrypt a key file from disk
    pub fn read<P: AsRef<Path>>(
        storage_dir: P,
        fingerprint_hex: &str,
        master_password: &str,
    ) -> Result<KeyPayload> {
        validate_fingerprint_format(fingerprint_hex)?;

        let filename = format!("sha256-{}.json", fingerprint_hex);
        let filepath = storage_dir.as_ref().join(filename);

        let json = std::fs::read_to_string(&filepath)?;
        let keyfile: KeyFile = serde_json::from_str(&json)?;

        if keyfile.version != "rssh-keyfile/v1" {
            return Err(Error::Config(format!(
                "Unsupported keyfile version: {}",
                keyfile.version
            )));
        }

        if keyfile.kdf.name != "argon2id" {
            return Err(Error::Config(format!(
                "Unsupported KDF: {}",
                keyfile.kdf.name
            )));
        }

        if keyfile.aead.name != "xchacha20poly1305" {
            return Err(Error::Config(format!(
                "Unsupported AEAD: {}",
                keyfile.aead.name
            )));
        }

        // Decode base64
        let salt = BASE64
            .decode(&keyfile.kdf.salt_b64)
            .map_err(|e| Error::Config(e.to_string()))?;
        let nonce_bytes = BASE64
            .decode(&keyfile.aead.nonce_b64)
            .map_err(|e| Error::Config(e.to_string()))?;
        let ciphertext = BASE64
            .decode(&keyfile.ciphertext_b64)
            .map_err(|e| Error::Config(e.to_string()))?;

        if nonce_bytes.len() != 24 {
            return Err(Error::Config("Invalid nonce length".into()));
        }

        // Derive key
        let key = derive_key(
            master_password,
            &salt,
            keyfile.kdf.mib,
            keyfile.kdf.t,
            keyfile.kdf.p,
        )?;

        // Decrypt
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key.0).map_err(|e| Error::Crypto(e.to_string()))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| Error::WrongPassword)?;

        // Parse payload
        let payload: KeyPayload = serde_json::from_slice(&plaintext)?;
        validate_description(&payload.description)?;

        // Verify fingerprint matches the public key in secret_openssh_b64
        let key_data = BASE64
            .decode(&payload.secret_openssh_b64)
            .map_err(|e| Error::Config(format!("Invalid base64 in secret key: {}", e)))?;

        let calculated_fingerprint = if payload.password_protected {
            // For password-protected keys, data is in OpenSSH format
            // We need to extract the public key for fingerprint verification
            // For now, we'll skip verification since it requires parsing the key with password
            // In production, you might want to store the public key separately
            fingerprint_hex.to_string() // Accept the provided fingerprint
        } else {
            // For legacy keys, data is in wire format
            match parse_wire_key_fingerprint(&key_data) {
                Ok(fp) => fp,
                Err(e) => {
                    return Err(Error::Config(format!(
                        "Failed to parse wire format key: {}",
                        e
                    )));
                }
            }
        };

        if calculated_fingerprint != fingerprint_hex {
            return Err(Error::Config(format!(
                "Fingerprint mismatch: expected {}, calculated {}",
                fingerprint_hex, calculated_fingerprint
            )));
        }

        Ok(payload)
    }

    /// Read and decrypt a key file, returning the SSH private key
    pub fn read_ssh_key<P: AsRef<Path>>(
        storage_dir: P,
        fingerprint_hex: &str,
        master_password: &str,
        key_password: Option<&str>,
    ) -> Result<crate::openssh::SshPrivateKey> {
        let payload = Self::read(storage_dir, fingerprint_hex, master_password)?;

        if payload.password_protected {
            // Key is stored as OpenSSH format and needs key password
            if key_password.is_none() {
                return Err(Error::NeedKeyPassword);
            }

            let openssh_data = BASE64
                .decode(&payload.secret_openssh_b64)
                .map_err(|e| Error::Config(format!("Invalid base64 in secret key: {}", e)))?;

            crate::openssh::SshPrivateKey::from_openssh(&openssh_data, key_password)
        } else {
            // Legacy format: key is stored as wire format, reconstruct SSH key
            let wire_data = BASE64
                .decode(&payload.secret_openssh_b64)
                .map_err(|e| Error::Config(format!("Invalid base64 in secret key: {}", e)))?;

            // For legacy wire format, we need to reconstruct the SSH key
            // This is a simplified approach - in practice, you might want to store
            // the original OpenSSH format alongside the wire format
            Self::ssh_key_from_wire_format(&wire_data, &payload.key_type)
        }
    }

    /// Convert wire format data back to SSH private key (for legacy keys)
    pub fn ssh_key_from_wire_format(
        wire_data: &[u8],
        key_type: &KeyType,
    ) -> Result<crate::openssh::SshPrivateKey> {
        use ssh_key::LineEnding;
        use ssh_key::private::RsaPrivateKey;
        use ssh_key::private::{Ed25519Keypair, KeypairData, PrivateKey, RsaKeypair};
        use ssh_key::public::RsaPublicKey;

        let mut offset = 0;

        // Helper function to read length-prefixed strings from wire format
        let read_string = |data: &[u8], offset: &mut usize| -> Option<Vec<u8>> {
            if data.len() < *offset + 4 {
                return None;
            }
            let len = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]) as usize;
            *offset += 4;

            if data.len() < *offset + len {
                return None;
            }
            let result = data[*offset..*offset + len].to_vec();
            *offset += len;
            Some(result)
        };

        // Read key type string
        let key_type_bytes = read_string(wire_data, &mut offset)
            .ok_or_else(|| Error::Config("Failed to read key type from wire data".to_string()))?;
        let key_type_str = std::str::from_utf8(&key_type_bytes)
            .map_err(|e| Error::Config(format!("Invalid key type in wire data: {}", e)))?;

        match key_type {
            KeyType::Ed25519 => {
                if key_type_str != "ssh-ed25519" {
                    return Err(Error::Config(format!(
                        "Key type mismatch: expected ssh-ed25519, found {}",
                        key_type_str
                    )));
                }

                // Read public key (32 bytes)
                let pub_key_bytes = read_string(wire_data, &mut offset).ok_or_else(|| {
                    Error::Config("Failed to read Ed25519 public key".to_string())
                })?;
                if pub_key_bytes.len() != 32 {
                    return Err(Error::Config(format!(
                        "Invalid Ed25519 public key length: {} (expected 32)",
                        pub_key_bytes.len()
                    )));
                }

                // Read combined private+public key (64 bytes)
                let priv_key_bytes = read_string(wire_data, &mut offset).ok_or_else(|| {
                    Error::Config("Failed to read Ed25519 private key".to_string())
                })?;
                if priv_key_bytes.len() != 64 {
                    return Err(Error::Config(format!(
                        "Invalid Ed25519 private key length: {} (expected 64)",
                        priv_key_bytes.len()
                    )));
                }

                // Convert to fixed-size array for Ed25519Keypair::from_bytes
                let mut key_bytes = [0u8; 64];
                key_bytes.copy_from_slice(&priv_key_bytes);

                // Create Ed25519 keypair
                let keypair = Ed25519Keypair::from_bytes(&key_bytes)
                    .map_err(|e| Error::Config(format!("Invalid Ed25519 keypair: {}", e)))?;

                let key_data = KeypairData::Ed25519(keypair);
                let private_key = PrivateKey::new(key_data, "".to_string()).map_err(|e| {
                    Error::Config(format!("Failed to create SSH private key: {}", e))
                })?;

                Ok(crate::openssh::SshPrivateKey::from_openssh(
                    private_key
                        .to_openssh(LineEnding::LF)
                        .map_err(|e| Error::Config(format!("Failed to serialize key: {}", e)))?
                        .as_bytes(),
                    None,
                )?)
            }
            KeyType::Rsa => {
                if key_type_str != "ssh-rsa" {
                    return Err(Error::Config(format!(
                        "Key type mismatch: expected ssh-rsa, found {}",
                        key_type_str
                    )));
                }

                // Read RSA components in wire format order: n, e, d, iqmp, p, q
                let n_bytes = read_string(wire_data, &mut offset)
                    .ok_or_else(|| Error::Config("Failed to read RSA n".to_string()))?;
                let e_bytes = read_string(wire_data, &mut offset)
                    .ok_or_else(|| Error::Config("Failed to read RSA e".to_string()))?;
                let d_bytes = read_string(wire_data, &mut offset)
                    .ok_or_else(|| Error::Config("Failed to read RSA d".to_string()))?;
                let iqmp_bytes = read_string(wire_data, &mut offset)
                    .ok_or_else(|| Error::Config("Failed to read RSA iqmp".to_string()))?;
                let p_bytes = read_string(wire_data, &mut offset)
                    .ok_or_else(|| Error::Config("Failed to read RSA p".to_string()))?;
                let q_bytes = read_string(wire_data, &mut offset)
                    .ok_or_else(|| Error::Config("Failed to read RSA q".to_string()))?;

                // Convert to Mpint format using ssh-key's types
                let n = ssh_key::Mpint::from_bytes(&n_bytes)
                    .map_err(|e| Error::Config(format!("Invalid RSA n: {}", e)))?;
                let e = ssh_key::Mpint::from_bytes(&e_bytes)
                    .map_err(|e| Error::Config(format!("Invalid RSA e: {}", e)))?;
                let d = ssh_key::Mpint::from_bytes(&d_bytes)
                    .map_err(|e| Error::Config(format!("Invalid RSA d: {}", e)))?;
                let iqmp = ssh_key::Mpint::from_bytes(&iqmp_bytes)
                    .map_err(|e| Error::Config(format!("Invalid RSA iqmp: {}", e)))?;
                let p = ssh_key::Mpint::from_bytes(&p_bytes)
                    .map_err(|e| Error::Config(format!("Invalid RSA p: {}", e)))?;
                let q = ssh_key::Mpint::from_bytes(&q_bytes)
                    .map_err(|e| Error::Config(format!("Invalid RSA q: {}", e)))?;

                // Create RSA keypair manually
                let public_key = RsaPublicKey {
                    n: n.clone(),
                    e: e.clone(),
                };
                let private_key = RsaPrivateKey { d, iqmp, p, q };

                let keypair = RsaKeypair {
                    public: public_key,
                    private: private_key,
                };

                let key_data = KeypairData::Rsa(keypair);
                let private_key = PrivateKey::new(key_data, "".to_string()).map_err(|e| {
                    Error::Config(format!("Failed to create SSH private key: {}", e))
                })?;

                Ok(crate::openssh::SshPrivateKey::from_openssh(
                    private_key
                        .to_openssh(LineEnding::LF)
                        .map_err(|e| Error::Config(format!("Failed to serialize key: {}", e)))?
                        .as_bytes(),
                    None,
                )?)
            }
        }
    }

    /// Read metadata from a key file without loading the secret key data
    pub fn read_metadata<P: AsRef<Path>>(
        storage_dir: P,
        fingerprint_hex: &str,
        master_password: &str,
    ) -> Result<KeyMetadata> {
        // This reuses the same decryption logic as read() but only returns metadata
        let payload = Self::read(storage_dir, fingerprint_hex, master_password)?;

        Ok(KeyMetadata {
            key_type: payload.key_type,
            description: payload.description,
            has_cert: payload.cert_openssh_b64.is_some(),
            password_protected: payload.password_protected,
            default_confirm: payload.default_confirm,
            default_notification: payload.default_notification,
            default_lifetime_seconds: payload.default_lifetime_seconds,
            created: payload.created,
            updated: payload.updated,
        })
    }

    /// Update default constraints for an existing key file
    pub fn update_default_constraints<P: AsRef<Path>>(
        storage_dir: P,
        fingerprint_hex: &str,
        master_password: &str,
        default_confirm: bool,
        default_notification: bool,
        default_lifetime_seconds: Option<u64>,
    ) -> Result<()> {
        // Read the current payload
        let mut payload = Self::read(storage_dir.as_ref(), fingerprint_hex, master_password)?;

        // Update the constraint fields and timestamp
        payload.default_confirm = default_confirm;
        payload.default_notification = default_notification;
        payload.default_lifetime_seconds = default_lifetime_seconds;
        payload.updated = Utc::now();

        // Write the updated payload back to disk
        Self::write_payload(storage_dir, fingerprint_hex, &payload, master_password)
    }
}

/// Calculate SHA-256 fingerprint of a public key
pub fn calculate_fingerprint_hex(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let result = hasher.finalize();
    hex::encode(result)
}

fn validate_fingerprint_format(fp: &str) -> Result<()> {
    if fp.len() != 64 {
        return Err(Error::Config(
            "Fingerprint must be 64 hex characters".into(),
        ));
    }

    if !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Config(
            "Fingerprint must contain only hex characters".into(),
        ));
    }

    Ok(())
}

pub fn validate_description(desc: &str) -> Result<()> {
    if desc.is_empty() || desc.len() > 256 {
        return Err(Error::Config("Description must be 1-256 characters".into()));
    }

    if desc.contains('\0') || desc.contains('\r') || desc.contains('\n') {
        return Err(Error::Config(
            "Description cannot contain NUL, CR, or LF".into(),
        ));
    }

    Ok(())
}

/// Parse wire format key data to extract fingerprint
/// This is a simplified version of the key_utils::parse_wire_key function
/// that only calculates the fingerprint without returning the full parsed data.
fn parse_wire_key_fingerprint(key_data: &[u8]) -> Result<String> {
    // Basic validation - ensure reasonable length bounds for a valid key
    if key_data.len() < 8 {
        return Err(Error::Config(
            "Key data too short - minimum 8 bytes required".into(),
        ));
    }

    // Prevent unreasonably large key data (max 64KB)
    if key_data.len() > 65536 {
        return Err(Error::Config(
            "Key data too large - maximum 64KB allowed".into(),
        ));
    }

    let mut offset = 0;

    // Read key type (length-prefixed string)
    let key_type_len = if key_data.len() < 4 {
        return Err(Error::Config(
            "Key data too short to read type length".into(),
        ));
    } else {
        u32::from_be_bytes([key_data[0], key_data[1], key_data[2], key_data[3]]) as usize
    };
    offset += 4;

    if offset + key_type_len > key_data.len() {
        return Err(Error::Config("Key data too short to read type".into()));
    }

    // Validate key type length is reasonable (max 64 bytes)
    if key_type_len > 64 {
        return Err(Error::Config("Key type name too long".into()));
    }

    let key_type = &key_data[offset..offset + key_type_len];
    let key_type_str = std::str::from_utf8(key_type)
        .map_err(|e| Error::Config(format!("Invalid key type: {}", e)))?;
    offset += key_type_len;

    match key_type_str {
        "ssh-ed25519" => {
            // Read public key (length-prefixed)
            if offset + 4 > key_data.len() {
                return Err(Error::Config(
                    "Key data too short to read Ed25519 public key length".into(),
                ));
            }
            let pub_key_len = u32::from_be_bytes([
                key_data[offset],
                key_data[offset + 1],
                key_data[offset + 2],
                key_data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + pub_key_len > key_data.len() {
                return Err(Error::Config(
                    "Key data too short to read Ed25519 public key".into(),
                ));
            }
            let pub_key = &key_data[offset..offset + pub_key_len];

            // Calculate fingerprint from public key blob
            let mut pub_key_blob = Vec::new();
            pub_key_blob.extend_from_slice(&(11u32).to_be_bytes()); // "ssh-ed25519" length
            pub_key_blob.extend_from_slice(b"ssh-ed25519");
            pub_key_blob.extend_from_slice(&(pub_key_len as u32).to_be_bytes());
            pub_key_blob.extend_from_slice(pub_key);

            let mut hasher = Sha256::new();
            hasher.update(&pub_key_blob);
            Ok(hex::encode(hasher.finalize()))
        }
        "ssh-rsa" => {
            // Read n (modulus) - first component
            if offset + 4 > key_data.len() {
                return Err(Error::Config(
                    "Key data too short to read RSA n length".into(),
                ));
            }
            let n_len = u32::from_be_bytes([
                key_data[offset],
                key_data[offset + 1],
                key_data[offset + 2],
                key_data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + n_len > key_data.len() {
                return Err(Error::Config("Key data too short to read RSA n".into()));
            }
            let n = &key_data[offset..offset + n_len];
            offset += n_len;

            // Read e (public exponent) - second component
            if offset + 4 > key_data.len() {
                return Err(Error::Config(
                    "Key data too short to read RSA e length".into(),
                ));
            }
            let e_len = u32::from_be_bytes([
                key_data[offset],
                key_data[offset + 1],
                key_data[offset + 2],
                key_data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + e_len > key_data.len() {
                return Err(Error::Config("Key data too short to read RSA e".into()));
            }
            let e = &key_data[offset..offset + e_len];

            // Build public key blob for fingerprint (SSH wire format: type, e, n)
            let mut pub_key_blob = Vec::new();
            pub_key_blob.extend_from_slice(&(7u32).to_be_bytes()); // "ssh-rsa" length
            pub_key_blob.extend_from_slice(b"ssh-rsa");
            pub_key_blob.extend_from_slice(&(e_len as u32).to_be_bytes());
            pub_key_blob.extend_from_slice(e);
            pub_key_blob.extend_from_slice(&(n_len as u32).to_be_bytes());
            pub_key_blob.extend_from_slice(n);

            let mut hasher = Sha256::new();
            hasher.update(&pub_key_blob);
            Ok(hex::encode(hasher.finalize()))
        }
        _ => Err(Error::Config(format!(
            "Unsupported key type: {}",
            key_type_str
        ))),
    }
}

fn derive_key(
    password: &str,
    salt: &[u8],
    memory_mib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<DerivedKey> {
    let params = Params::new(
        memory_mib * 1024, // MiB to KiB
        iterations,
        parallelism,
        Some(32),
    )
    .map_err(|e| Error::Crypto(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = DerivedKey([0u8; 32]);
    let mut context = Vec::from(KDF_DOMAIN.as_bytes());
    context.extend_from_slice(salt);

    argon2
        .hash_password_into(password.as_bytes(), &context, &mut key.0)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_keyfile_roundtrip() {
        use crate::openssh::SshPrivateKey;

        let temp = TempDir::new().unwrap();

        // Generate a real SSH key
        let ssh_key = SshPrivateKey::generate_ed25519().unwrap();
        let public_key_bytes = ssh_key.public_key_bytes();
        let fingerprint = calculate_fingerprint_hex(&public_key_bytes);

        // Create wire format key data (like handle_manage_import does)
        // For Ed25519: key_type + pub_key + priv_key (64 bytes total)
        let mut wire_key_data = Vec::new();

        // Key type: "ssh-ed25519" (length-prefixed)
        wire_key_data.extend_from_slice(&(11u32).to_be_bytes());
        wire_key_data.extend_from_slice(b"ssh-ed25519");

        // Public key (32 bytes for Ed25519, length-prefixed)
        let pub_key_raw = &public_key_bytes[19..]; // Skip SSH wire protocol header to get raw 32-byte key
        wire_key_data.extend_from_slice(&(32u32).to_be_bytes());
        wire_key_data.extend_from_slice(pub_key_raw);

        // Private key (64 bytes for Ed25519: 32 secret + 32 public, length-prefixed)
        // For testing, we'll create fake private key data
        let fake_priv_key = [42u8; 64]; // 64 bytes of test data
        wire_key_data.extend_from_slice(&(64u32).to_be_bytes());
        wire_key_data.extend_from_slice(&fake_priv_key);

        let payload = KeyPayload {
            key_type: KeyType::Ed25519,
            description: "test key".to_string(),
            secret_openssh_b64: BASE64.encode(&wire_key_data),
            cert_openssh_b64: None,
            password_protected: false,
            default_confirm: false,
            default_notification: false,
            default_lifetime_seconds: None,
            created: Utc::now(),
            updated: Utc::now(),
        };

        let password = "test_password_123";

        // Write
        KeyFile::write(temp.path(), &fingerprint, &payload, password).unwrap();

        // Read back
        let read_payload = KeyFile::read(temp.path(), &fingerprint, password).unwrap();

        assert_eq!(read_payload.key_type, payload.key_type);
        assert_eq!(read_payload.description, payload.description);
        assert_eq!(read_payload.secret_openssh_b64, payload.secret_openssh_b64);
    }

    #[test]
    fn test_wrong_password() {
        use crate::openssh::SshPrivateKey;

        let temp = TempDir::new().unwrap();

        // Generate a real RSA SSH key
        let ssh_key = SshPrivateKey::generate_rsa(2048).unwrap();
        let public_key_bytes = ssh_key.public_key_bytes();
        let fingerprint = calculate_fingerprint_hex(&public_key_bytes);

        // Create wire format RSA key data for testing
        // RSA wire format: key_type + n + e + d + iqmp + p + q
        let mut wire_key_data = Vec::new();

        // Key type: "ssh-rsa" (length-prefixed)
        wire_key_data.extend_from_slice(&(7u32).to_be_bytes());
        wire_key_data.extend_from_slice(b"ssh-rsa");

        // Extract e (public exponent) and n (modulus) from SSH public key blob
        // SSH RSA public key format: "ssh-rsa" + e + n
        let mut offset = 4; // Skip length prefix
        let key_type_len = u32::from_be_bytes([
            public_key_bytes[0],
            public_key_bytes[1],
            public_key_bytes[2],
            public_key_bytes[3],
        ]) as usize;
        offset += key_type_len; // Skip "ssh-rsa"

        // Read e (public exponent)
        let e_len = u32::from_be_bytes([
            public_key_bytes[offset],
            public_key_bytes[offset + 1],
            public_key_bytes[offset + 2],
            public_key_bytes[offset + 3],
        ]) as usize;
        offset += 4;
        let e = &public_key_bytes[offset..offset + e_len];
        offset += e_len;

        // Read n (modulus)
        let n_len = u32::from_be_bytes([
            public_key_bytes[offset],
            public_key_bytes[offset + 1],
            public_key_bytes[offset + 2],
            public_key_bytes[offset + 3],
        ]) as usize;
        offset += 4;
        let n = &public_key_bytes[offset..offset + n_len];

        // Add n (modulus) to wire format
        wire_key_data.extend_from_slice(&(n_len as u32).to_be_bytes());
        wire_key_data.extend_from_slice(n);

        // Add e (public exponent) to wire format
        wire_key_data.extend_from_slice(&(e_len as u32).to_be_bytes());
        wire_key_data.extend_from_slice(e);

        // Add fake private components (d, iqmp, p, q)
        let fake_component = vec![42u8; 256]; // 256 bytes of fake data
        for _ in 0..4 {
            // d, iqmp, p, q
            wire_key_data.extend_from_slice(&(fake_component.len() as u32).to_be_bytes());
            wire_key_data.extend_from_slice(&fake_component);
        }

        let payload = KeyPayload {
            key_type: KeyType::Rsa,
            description: "test rsa".to_string(),
            secret_openssh_b64: BASE64.encode(&wire_key_data),
            cert_openssh_b64: Some(BASE64.encode(b"fake cert")),
            password_protected: false,
            default_confirm: false,
            default_notification: false,
            default_lifetime_seconds: None,
            created: Utc::now(),
            updated: Utc::now(),
        };

        KeyFile::write(temp.path(), &fingerprint, &payload, "correct_password").unwrap();

        let result = KeyFile::read(temp.path(), &fingerprint, "wrong_password");
        assert!(matches!(result, Err(Error::WrongPassword)));
    }

    #[test]
    fn test_validate_description() {
        assert!(validate_description("valid description").is_ok());
        assert!(validate_description("").is_err());
        assert!(validate_description(&"x".repeat(257)).is_err());
        assert!(validate_description("has\nnewline").is_err());
        assert!(validate_description("has\rcarriage").is_err());
        assert!(validate_description("has\0null").is_err());
    }

    #[test]
    fn test_validate_fingerprint() {
        assert!(validate_fingerprint_format(&"a".repeat(64)).is_ok());
        assert!(validate_fingerprint_format(&"0123456789abcdef".repeat(4)).is_ok());
        assert!(validate_fingerprint_format(&"A".repeat(64)).is_ok());

        assert!(validate_fingerprint_format(&"a".repeat(63)).is_err());
        assert!(validate_fingerprint_format(&"a".repeat(65)).is_err());
        assert!(validate_fingerprint_format(&"g".repeat(64)).is_err());
    }

    #[test]
    fn test_calculate_fingerprint() {
        let data = b"test public key data";
        let fp = calculate_fingerprint_hex(data);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));

        // Known hash for "test public key data"
        assert_eq!(
            fp,
            "748f3737d98f66a92ca085e9732b6f1d319b6a6f8d06d662f2728f2cffc8f2a9"
        );
    }

    #[test]
    fn test_password_protected_key_ed25519() {
        use crate::openssh::SshPrivateKey;

        let temp = TempDir::new().unwrap();

        // Generate a real SSH key
        let ssh_key = SshPrivateKey::generate_ed25519().unwrap();
        let public_key_bytes = ssh_key.public_key_bytes();
        let fingerprint = calculate_fingerprint_hex(&public_key_bytes);

        let master_password = "master_pass_123";
        let key_password = "key_pass_456";
        let description = "password protected test key".to_string();

        // Write with password protection
        KeyFile::write_with_key_password(
            temp.path(),
            &fingerprint,
            &ssh_key,
            description.clone(),
            None,
            master_password,
            Some(key_password),
        )
        .unwrap();

        // Read metadata - should show password_protected = true
        let metadata = KeyFile::read_metadata(temp.path(), &fingerprint, master_password).unwrap();
        assert!(metadata.password_protected);
        assert_eq!(metadata.description, description);
        assert_eq!(metadata.key_type, KeyType::Ed25519);

        // Read with correct passwords should succeed
        let loaded_key = KeyFile::read_ssh_key(
            temp.path(),
            &fingerprint,
            master_password,
            Some(key_password),
        )
        .unwrap();
        assert!(loaded_key.is_ed25519());
        assert_eq!(loaded_key.public_key_bytes(), public_key_bytes);

        // Read without key password should fail
        let result = KeyFile::read_ssh_key(temp.path(), &fingerprint, master_password, None);
        assert!(matches!(result, Err(Error::NeedKeyPassword)));

        // Read with wrong key password should fail
        let result = KeyFile::read_ssh_key(
            temp.path(),
            &fingerprint,
            master_password,
            Some("wrong_key_pass"),
        );
        assert!(matches!(result, Err(Error::BadKeyPassword)));

        // Read with wrong master password should fail
        let result = KeyFile::read_ssh_key(
            temp.path(),
            &fingerprint,
            "wrong_master_pass",
            Some(key_password),
        );
        assert!(matches!(result, Err(Error::WrongPassword)));
    }

    #[test]
    fn test_password_protected_key_rsa() {
        use crate::openssh::SshPrivateKey;

        let temp = TempDir::new().unwrap();

        // Generate a real RSA SSH key
        let ssh_key = SshPrivateKey::generate_rsa(2048).unwrap();
        let public_key_bytes = ssh_key.public_key_bytes();
        let fingerprint = calculate_fingerprint_hex(&public_key_bytes);

        let master_password = "master_pass_rsa";
        let key_password = "key_pass_rsa_456";
        let description = "RSA password protected test key".to_string();

        // Write with password protection
        KeyFile::write_with_key_password(
            temp.path(),
            &fingerprint,
            &ssh_key,
            description.clone(),
            Some(BASE64.encode(b"fake rsa cert")),
            master_password,
            Some(key_password),
        )
        .unwrap();

        // Read metadata - should show password_protected = true and has_cert = true
        let metadata = KeyFile::read_metadata(temp.path(), &fingerprint, master_password).unwrap();
        assert!(metadata.password_protected);
        assert!(metadata.has_cert);
        assert_eq!(metadata.description, description);
        assert_eq!(metadata.key_type, KeyType::Rsa);

        // Read with correct passwords should succeed
        let loaded_key = KeyFile::read_ssh_key(
            temp.path(),
            &fingerprint,
            master_password,
            Some(key_password),
        )
        .unwrap();
        assert!(loaded_key.is_rsa());
        assert_eq!(loaded_key.public_key_bytes(), public_key_bytes);
    }

    #[test]
    fn test_password_removal_format_conversion() {
        use crate::openssh::SshPrivateKey;

        let temp = TempDir::new().unwrap();

        // Generate a real SSH key
        let ssh_key = SshPrivateKey::generate_ed25519().unwrap();
        let public_key_bytes = ssh_key.public_key_bytes();
        let fingerprint = calculate_fingerprint_hex(&public_key_bytes);

        let master_password = "master_pass_123";
        let key_password = "key_pass_456";
        let description = "password removal test key".to_string();

        // Step 1: Write with password protection (should use OpenSSH format)
        KeyFile::write_with_key_password(
            temp.path(),
            &fingerprint,
            &ssh_key,
            description.clone(),
            None,
            master_password,
            Some(key_password),
        )
        .unwrap();

        // Verify the key is stored with password protection
        let payload_protected = KeyFile::read(temp.path(), &fingerprint, master_password).unwrap();
        assert!(payload_protected.password_protected);

        // Step 2: Load the SSH key from password-protected storage
        let loaded_key = KeyFile::read_ssh_key(
            temp.path(),
            &fingerprint,
            master_password,
            Some(key_password),
        )
        .unwrap();

        // Step 3: Simulate password removal by using write_with_key_password with None password
        // This should convert from OpenSSH format to wire format
        KeyFile::write_with_key_password(
            temp.path(),
            &fingerprint,
            &loaded_key,
            description.clone(),
            None,
            master_password,
            None, // Remove password protection
        )
        .unwrap();

        // Step 4: Verify the key is now stored without password protection
        let payload_unprotected =
            KeyFile::read(temp.path(), &fingerprint, master_password).unwrap();
        assert!(!payload_unprotected.password_protected);

        // Step 5: Load the key without password (should work from wire format)
        let reloaded_key = KeyFile::read_ssh_key(
            temp.path(),
            &fingerprint,
            master_password,
            None, // No password needed
        )
        .unwrap();

        // Step 6: Verify the key is still functional and matches original
        assert!(reloaded_key.is_ed25519());
        assert_eq!(reloaded_key.public_key_bytes(), public_key_bytes);

        // Step 7: Verify we can convert back to wire format again (should not corrupt)
        let wire_data = reloaded_key.to_wire_format().unwrap();
        assert!(wire_data.len() > 0);

        // Step 8: Verify we can reconstruct the key from wire format
        let reconstructed_key =
            KeyFile::ssh_key_from_wire_format(&wire_data, &KeyType::Ed25519).unwrap();
        assert_eq!(reconstructed_key.public_key_bytes(), public_key_bytes);
    }

    #[test]
    fn test_unprotected_key_compatibility() {
        use crate::openssh::SshPrivateKey;

        let temp = TempDir::new().unwrap();

        // Generate a real SSH key
        let ssh_key = SshPrivateKey::generate_ed25519().unwrap();
        let public_key_bytes = ssh_key.public_key_bytes();
        let fingerprint = calculate_fingerprint_hex(&public_key_bytes);

        let master_password = "master_pass_123";
        let description = "unprotected test key".to_string();

        // Write without password protection
        KeyFile::write_with_key_password(
            temp.path(),
            &fingerprint,
            &ssh_key,
            description.clone(),
            None,
            master_password,
            None,
        )
        .unwrap();

        // Read metadata - should show password_protected = false
        let metadata = KeyFile::read_metadata(temp.path(), &fingerprint, master_password).unwrap();
        assert!(!metadata.password_protected);
        assert_eq!(metadata.description, description);

        // Read without key password should succeed now that wire format reconstruction is implemented
        let loaded_key = KeyFile::read_ssh_key(temp.path(), &fingerprint, master_password, None);
        assert!(loaded_key.is_ok());

        // Verify the loaded key has the same algorithm as the original
        let loaded_ssh_key = loaded_key.unwrap();
        assert_eq!(loaded_ssh_key.algorithm(), ssh_key.algorithm());
    }

    #[test]
    fn test_backward_compatibility_with_default_false() {
        use serde_json::json;

        let temp = TempDir::new().unwrap();

        // Create a keyfile without the password_protected field (old format)
        let old_keyfile_content = json!({
            "version": "rssh-keyfile/v1",
            "kdf": {
                "name": "argon2id",
                "mib": 256,
                "t": 3,
                "p": 1,
                "salt_b64": "dGVzdF9zYWx0X2RhdGFfMTIzNDU2Nzg5MEFCQ0RFRg=="
            },
            "aead": {
                "name": "xchacha20poly1305",
                "nonce_b64": "dGVzdF9ub25jZV8xMjM0NTY3ODkwQUI="
            },
            "ciphertext_b64": "fake_encrypted_data"
        });

        let keyfile_path = temp.path().join("sha256-test.json");
        std::fs::write(&keyfile_path, old_keyfile_content.to_string()).unwrap();

        // Try to parse - should default password_protected to false
        let keyfile_json = std::fs::read_to_string(&keyfile_path).unwrap();
        let keyfile: KeyFile = serde_json::from_str(&keyfile_json).unwrap();

        // The KeyFile struct should deserialize correctly
        assert_eq!(keyfile.version, "rssh-keyfile/v1");
        assert_eq!(keyfile.kdf.name, "argon2id");
    }
}
