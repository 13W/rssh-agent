use ed25519_dalek::{Signer, SigningKey};
use rssh_proto::wire;
use sha2::{Digest, Sha256, Sha512};

/// Sign data with the given key
pub fn sign_data(key_data: &[u8], data_to_sign: &[u8], flags: u32) -> Result<Vec<u8>, String> {
    let mut offset = 0;

    // Read key type
    let key_type = wire::read_string(key_data, &mut offset)
        .ok_or_else(|| "Failed to read key type".to_string())?;
    let key_type_str =
        std::str::from_utf8(&key_type).map_err(|e| format!("Invalid key type: {}", e))?;

    match key_type_str {
        "ssh-ed25519" => {
            // Read public and private key components
            let _pub_key = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read public key".to_string())?;
            let priv_key = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read private key".to_string())?;

            // Ed25519 private key is 64 bytes (32 bytes secret + 32 bytes public)
            if priv_key.len() != 64 {
                return Err(format!(
                    "Invalid Ed25519 private key length: {}",
                    priv_key.len()
                ));
            }

            // The first 32 bytes are the secret key
            let secret_bytes: [u8; 32] = priv_key[0..32]
                .try_into()
                .map_err(|_| "Failed to convert secret key")?;

            let signing_key = SigningKey::from_bytes(&secret_bytes);
            let signature = signing_key.sign(data_to_sign);

            // Build SSH signature blob
            let mut sig_blob = Vec::new();
            wire::write_string(&mut sig_blob, b"ssh-ed25519");
            wire::write_string(&mut sig_blob, signature.to_bytes().as_ref());

            Ok(sig_blob)
        }
        "ssh-rsa" => {
            // Read RSA components
            let _n = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA n".to_string())?;
            let _e = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA e".to_string())?;
            let _d = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA d".to_string())?;
            let _iqmp = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA iqmp".to_string())?;
            let _p = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA p".to_string())?;
            let _q = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA q".to_string())?;

            // Determine signature algorithm based on flags
            let (_sig_type, _hash) = if flags & 0x04 != 0 {
                // RSA SHA-512
                let mut hasher = Sha512::new();
                hasher.update(data_to_sign);
                ("rsa-sha2-512", hasher.finalize().to_vec())
            } else if flags & 0x02 != 0 {
                // RSA SHA-256
                let mut hasher = Sha256::new();
                hasher.update(data_to_sign);
                ("rsa-sha2-256", hasher.finalize().to_vec())
            } else {
                // Default to SHA-512
                let mut hasher = Sha512::new();
                hasher.update(data_to_sign);
                ("rsa-sha2-512", hasher.finalize().to_vec())
            };

            // For now, return a placeholder - proper RSA signing requires additional dependencies
            // In production, this would use the rsa crate to perform the actual signing
            Err("RSA signing not yet implemented".to_string())
        }
        _ => Err(format!(
            "Unsupported key type for signing: {}",
            key_type_str
        )),
    }
}
