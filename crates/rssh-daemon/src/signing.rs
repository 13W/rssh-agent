use ed25519_dalek::{Signer, SigningKey};
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
use rsa::sha2::{Sha256, Sha512};
use rsa::{BigUint, RsaPrivateKey, signature::SignatureEncoding};
use rssh_proto::wire;

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
            let n = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA n".to_string())?;
            let e = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA e".to_string())?;
            let d = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA d".to_string())?;
            let _iqmp = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA iqmp".to_string())?;
            let p = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA p".to_string())?;
            let q = wire::read_string(key_data, &mut offset)
                .ok_or_else(|| "Failed to read RSA q".to_string())?;

            // Convert components to BigUint
            let n_big = BigUint::from_bytes_be(&n);
            let e_big = BigUint::from_bytes_be(&e);
            let d_big = BigUint::from_bytes_be(&d);
            let p_big = BigUint::from_bytes_be(&p);
            let q_big = BigUint::from_bytes_be(&q);

            // Create RSA private key
            let primes = vec![p_big, q_big];
            let private_key = RsaPrivateKey::from_components(n_big, e_big, d_big, primes)
                .map_err(|e| format!("Failed to create RSA key: {}", e))?;

            // Determine signature algorithm and create signature
            let (sig_type, signature_bytes) = if flags & 0x04 != 0 {
                // RSA SHA-512
                let signing_key = RsaSigningKey::<Sha512>::new(private_key);
                let signature: RsaSignature = signing_key.sign(data_to_sign);
                ("rsa-sha2-512", signature.to_bytes().to_vec())
            } else if flags & 0x02 != 0 {
                // RSA SHA-256
                let signing_key = RsaSigningKey::<Sha256>::new(private_key);
                let signature: RsaSignature = signing_key.sign(data_to_sign);
                ("rsa-sha2-256", signature.to_bytes().to_vec())
            } else {
                // Default to SHA-512
                let signing_key = RsaSigningKey::<Sha512>::new(private_key);
                let signature: RsaSignature = signing_key.sign(data_to_sign);
                ("rsa-sha2-512", signature.to_bytes().to_vec())
            };

            // Build SSH signature blob
            let mut sig_blob = Vec::new();
            wire::write_string(&mut sig_blob, sig_type.as_bytes());
            wire::write_string(&mut sig_blob, &signature_bytes);

            Ok(sig_blob)
        }
        _ => Err(format!(
            "Unsupported key type for signing: {}",
            key_type_str
        )),
    }
}
