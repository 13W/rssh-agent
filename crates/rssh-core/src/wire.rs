use crate::{Error, Result};
use sha2::{Digest, Sha256};

/// Parsed components of an SSH public key
#[derive(Debug, Clone)]
pub struct ParsedKey {
    pub fingerprint: String,
    pub key_type: String,
    pub public_key_blob: Vec<u8>,
}

/// Parse wire format key data to extract public key components
pub fn parse_wire_key(key_data: &[u8]) -> Result<ParsedKey> {
    let mut offset = 0;

    // Helper to read length-prefixed string
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

    // Read key type
    let key_type_bytes = read_string(key_data, &mut offset)
        .ok_or_else(|| Error::Config("Failed to read key type".to_string()))?;
    let key_type_str = std::str::from_utf8(&key_type_bytes)
        .map_err(|e| Error::Config(format!("Invalid key type: {}", e)))?;

    match key_type_str {
        "ssh-ed25519" => {
            // Read public key
            let pub_key = read_string(key_data, &mut offset)
                .ok_or_else(|| Error::Config("Failed to read public key".to_string()))?;

            // Build public key blob
            let mut pub_key_blob = Vec::new();
            pub_key_blob.extend_from_slice(&(11u32).to_be_bytes()); // "ssh-ed25519" length
            pub_key_blob.extend_from_slice(b"ssh-ed25519");
            pub_key_blob.extend_from_slice(&(pub_key.len() as u32).to_be_bytes());
            pub_key_blob.extend_from_slice(&pub_key);

            let mut hasher = Sha256::new();
            hasher.update(&pub_key_blob);
            let fingerprint = hex::encode(hasher.finalize());

            Ok(ParsedKey {
                fingerprint,
                key_type: "ed25519".to_string(),
                public_key_blob: pub_key_blob,
            })
        }
        "ssh-rsa" => {
            // Read n (modulus)
            let n = read_string(key_data, &mut offset)
                .ok_or_else(|| Error::Config("Failed to read RSA n".to_string()))?;
            // Read e (public exponent)
            let e = read_string(key_data, &mut offset)
                .ok_or_else(|| Error::Config("Failed to read RSA e".to_string()))?;

            // Build public key blob: type, e, n
            let mut pub_key_blob = Vec::new();
            pub_key_blob.extend_from_slice(&(7u32).to_be_bytes()); // "ssh-rsa" length
            pub_key_blob.extend_from_slice(b"ssh-rsa");
            pub_key_blob.extend_from_slice(&(e.len() as u32).to_be_bytes());
            pub_key_blob.extend_from_slice(&e);
            pub_key_blob.extend_from_slice(&(n.len() as u32).to_be_bytes());
            pub_key_blob.extend_from_slice(&n);

            let mut hasher = Sha256::new();
            hasher.update(&pub_key_blob);
            let fingerprint = hex::encode(hasher.finalize());

            Ok(ParsedKey {
                fingerprint,
                key_type: "rsa".to_string(),
                public_key_blob: pub_key_blob,
            })
        }
        _ => Err(Error::Config(format!("Unsupported key type: {}", key_type_str))),
    }
}

/// Extract just the public key blob from wire format key data
pub fn extract_public_key(key_data: &[u8]) -> Option<Vec<u8>> {
    parse_wire_key(key_data).ok().map(|k| k.public_key_blob)
}
