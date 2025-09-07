use rssh_proto::wire;
use sha2::{Digest, Sha256};

/// Parse key components from wire format and calculate fingerprint
pub fn parse_wire_key(key_data: &[u8]) -> Result<(String, String, Vec<u8>), String> {
    let mut offset = 0;

    // Read key type
    let key_type = wire::read_string(key_data, &mut offset)
        .ok_or_else(|| "Failed to read key type".to_string())?;
    let key_type_str =
        std::str::from_utf8(&key_type).map_err(|e| format!("Invalid key type: {}", e))?;

    match key_type_str {
        "ssh-ed25519" => {
            // Read public key (used for fingerprint)
            let pub_key = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read public key".to_string())?;

            // Calculate fingerprint from public key
            let mut pub_key_blob = Vec::new();
            wire::write_string(&mut pub_key_blob, b"ssh-ed25519");
            wire::write_string(&mut pub_key_blob, &pub_key);

            let mut hasher = Sha256::new();
            hasher.update(&pub_key_blob);
            let fingerprint = hex::encode(hasher.finalize());

            // For Ed25519, we'll store the raw components
            // The public key blob is what ssh-add -l expects
            Ok((fingerprint, "ed25519".to_string(), pub_key_blob))
        }
        "ssh-rsa" => {
            // Read n (modulus) and e (public exponent) for fingerprint
            let n = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA n".to_string())?;
            let e = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA e".to_string())?;

            // Build public key blob for fingerprint
            let mut pub_key_blob = Vec::new();
            wire::write_string(&mut pub_key_blob, b"ssh-rsa");
            wire::write_string(&mut pub_key_blob, &e);
            wire::write_string(&mut pub_key_blob, &n);

            let mut hasher = Sha256::new();
            hasher.update(&pub_key_blob);
            let fingerprint = hex::encode(hasher.finalize());

            Ok((fingerprint, "rsa".to_string(), pub_key_blob))
        }
        _ => Err(format!("Unsupported key type: {}", key_type_str)),
    }
}

/// Extract public key blob for identity listing
pub fn get_public_key_blob(key_data: &[u8]) -> Result<Vec<u8>, String> {
    let (_fingerprint, _key_type, pub_key_blob) = parse_wire_key(key_data)?;
    Ok(pub_key_blob)
}
