use crate::{Error, Result, fs_policy};
use argon2::{Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use chrono::{DateTime, Utc};
use rand::RngCore;
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
    /// Write a key file to disk
    pub fn write<P: AsRef<Path>>(
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
    // Note: secret_openssh_b64 contains wire format key data (as stored by handle_manage_import)
    let key_data = BASE64
        .decode(&payload.secret_openssh_b64)
        .map_err(|e| Error::Config(format!("Invalid base64 in secret key: {}", e)))?;
    
    // Parse wire format key data to extract public key and calculate fingerprint
    let calculated_fingerprint = match parse_wire_key_fingerprint(&key_data) {
        Ok(fp) => fp,
        Err(e) => {
            return Err(Error::Config(format!("Failed to parse wire format key: {}", e)));
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
            created: payload.created,
            updated: payload.updated,
        })
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

fn validate_description(desc: &str) -> Result<()> {
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
    let mut offset = 0;

    // Read key type (length-prefixed string)
    let key_type_len = if key_data.len() < 4 {
        return Err(Error::Config("Key data too short to read type length".into()));
    } else {
        u32::from_be_bytes([key_data[0], key_data[1], key_data[2], key_data[3]]) as usize
    };
    offset += 4;
    
    if offset + key_type_len > key_data.len() {
        return Err(Error::Config("Key data too short to read type".into()));
    }
    
    let key_type = &key_data[offset..offset + key_type_len];
    let key_type_str = std::str::from_utf8(key_type)
        .map_err(|e| Error::Config(format!("Invalid key type: {}", e)))?;
    offset += key_type_len;

    match key_type_str {
        "ssh-ed25519" => {
            // Read public key (length-prefixed)
            if offset + 4 > key_data.len() {
                return Err(Error::Config("Key data too short to read Ed25519 public key length".into()));
            }
            let pub_key_len = u32::from_be_bytes([
                key_data[offset], key_data[offset + 1], 
                key_data[offset + 2], key_data[offset + 3]
            ]) as usize;
            offset += 4;
            
            if offset + pub_key_len > key_data.len() {
                return Err(Error::Config("Key data too short to read Ed25519 public key".into()));
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
                return Err(Error::Config("Key data too short to read RSA n length".into()));
            }
            let n_len = u32::from_be_bytes([
                key_data[offset], key_data[offset + 1], 
                key_data[offset + 2], key_data[offset + 3]
            ]) as usize;
            offset += 4;
            
            if offset + n_len > key_data.len() {
                return Err(Error::Config("Key data too short to read RSA n".into()));
            }
            let n = &key_data[offset..offset + n_len];
            offset += n_len;

            // Read e (public exponent) - second component
            if offset + 4 > key_data.len() {
                return Err(Error::Config("Key data too short to read RSA e length".into()));
            }
            let e_len = u32::from_be_bytes([
                key_data[offset], key_data[offset + 1], 
                key_data[offset + 2], key_data[offset + 3]
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
        _ => Err(Error::Config(format!("Unsupported key type: {}", key_type_str))),
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
        public_key_bytes[0], public_key_bytes[1], 
        public_key_bytes[2], public_key_bytes[3]
    ]) as usize;
    offset += key_type_len; // Skip "ssh-rsa"
    
    // Read e (public exponent)
    let e_len = u32::from_be_bytes([
        public_key_bytes[offset], public_key_bytes[offset + 1], 
        public_key_bytes[offset + 2], public_key_bytes[offset + 3]
    ]) as usize;
    offset += 4;
    let e = &public_key_bytes[offset..offset + e_len];
    offset += e_len;
    
    // Read n (modulus)  
    let n_len = u32::from_be_bytes([
        public_key_bytes[offset], public_key_bytes[offset + 1], 
        public_key_bytes[offset + 2], public_key_bytes[offset + 3]
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
    for _ in 0..4 { // d, iqmp, p, q
        wire_key_data.extend_from_slice(&(fake_component.len() as u32).to_be_bytes());
        wire_key_data.extend_from_slice(&fake_component);
    }
    
    let payload = KeyPayload {
        key_type: KeyType::Rsa,
        description: "test rsa".to_string(),
        secret_openssh_b64: BASE64.encode(&wire_key_data),
        cert_openssh_b64: Some(BASE64.encode(b"fake cert")),
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
}
