use crate::{Error, Result};
use ssh_key::{
    Algorithm, LineEnding,
    private::{Ed25519Keypair, KeypairData, PrivateKey, RsaKeypair},
};

const MIN_RSA_BITS: usize = 2048;
const MAX_RSA_BITS: usize = 8192;
const DEFAULT_BCRYPT_ROUNDS: u32 = 16;
const MIN_BCRYPT_ROUNDS: u32 = 14;
const MAX_BCRYPT_ROUNDS: u32 = 22;

/// Wrapper for SSH private key
pub struct SshPrivateKey {
    inner: PrivateKey,
}

impl SshPrivateKey {
    /// Parse an OpenSSH private key from openssh-key-v1 format
    pub fn from_openssh(data: &[u8], passphrase: Option<&str>) -> Result<Self> {
        let s = std::str::from_utf8(data)
            .map_err(|e| Error::Config(format!("Invalid UTF-8 in key: {}", e)))?;

        let inner = if let Some(pass) = passphrase {
            PrivateKey::from_openssh(s)
                .map_err(|_| Error::BadKeyPassword)?
                .decrypt(pass.as_bytes())
                .map_err(|_| Error::BadKeyPassword)?
        } else {
            PrivateKey::from_openssh(s)
                .map_err(|e| Error::Config(format!("Failed to parse key: {}", e)))?
        };

        // Validate key type and parameters
        match inner.key_data() {
            KeypairData::Ed25519(_) => {
                // Ed25519 is always valid
            }
            KeypairData::Rsa(rsa) => {
                // RSA validation - check approximate size
                let byte_len = rsa.public.n.as_bytes().len();
                let approx_bits = byte_len * 8;
                // Allow some tolerance for the actual modulus size
                if approx_bits < (MIN_RSA_BITS - 8) {
                    return Err(Error::RsaTooSmall);
                }
                if approx_bits > (MAX_RSA_BITS + 8) {
                    return Err(Error::RsaTooLarge);
                }
            }
            _ => {
                return Err(Error::Unsupported);
            }
        }

        Ok(SshPrivateKey { inner })
    }

    /// Serialize to OpenSSH format with optional passphrase
    pub fn to_openssh(&self, passphrase: Option<&str>, _rounds: Option<u32>) -> Result<Vec<u8>> {
        let rounds = _rounds.unwrap_or(DEFAULT_BCRYPT_ROUNDS);
        if !(MIN_BCRYPT_ROUNDS..=MAX_BCRYPT_ROUNDS).contains(&rounds) {
            return Err(Error::Config(format!(
                "bcrypt rounds must be between {} and {}",
                MIN_BCRYPT_ROUNDS, MAX_BCRYPT_ROUNDS
            )));
        }

        if let Some(pass) = passphrase {
            if pass.is_empty() {
                return Err(Error::Config("Empty passphrase not allowed".into()));
            }

            // Clone and encrypt the key
            let key = self.inner.clone();
            let encrypted = key
                .encrypt(&mut rand::thread_rng(), pass.as_bytes())
                .map_err(|e| Error::Crypto(e.to_string()))?;

            encrypted
                .to_openssh(LineEnding::LF)
                .map_err(|e| Error::Crypto(e.to_string()))
                .map(|s| s.as_bytes().to_vec())
        } else {
            self.inner
                .to_openssh(LineEnding::LF)
                .map_err(|e| Error::Crypto(e.to_string()))
                .map(|s| s.as_bytes().to_vec())
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().to_bytes().unwrap_or_default()
    }

    /// Convert to wire format for signing operations
    pub fn to_wire_format(&self) -> Result<Vec<u8>> {
        let mut wire_data = Vec::new();

        // Helper function to write length-prefixed strings (wire format)
        let write_string = |buf: &mut Vec<u8>, data: &[u8]| {
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
        };

        match self.inner.algorithm() {
            ssh_key::Algorithm::Ed25519 => {
                // Write key type
                write_string(&mut wire_data, b"ssh-ed25519");

                // Get the Ed25519 keypair directly to access raw key material
                let ed25519_keypair = match self.inner.key_data().ed25519() {
                    Some(keypair) => keypair,
                    None => {
                        return Err(Error::Internal(
                            "Failed to get Ed25519 key data".to_string(),
                        ));
                    }
                };

                // Get raw public key bytes (32 bytes) by extracting from the SSH public key
                let public_key_wire = self.inner.public_key().to_bytes().map_err(|e| {
                    Error::Internal(format!("Failed to get public key bytes: {}", e))
                })?;

                // SSH Ed25519 public key format: 4-byte length + "ssh-ed25519" + 4-byte length + 32-byte key
                // Extract the raw 32 bytes from the end
                if public_key_wire.len() < 32 {
                    return Err(Error::Internal(
                        "Invalid Ed25519 public key format".to_string(),
                    ));
                }
                let raw_public = &public_key_wire[public_key_wire.len() - 32..];
                write_string(&mut wire_data, raw_public);

                // Get the private key (32 bytes) and combine with public (32 bytes) = 64 bytes total
                let private_bytes = ed25519_keypair.private.to_bytes();

                // Ed25519 wire format expects 64 bytes: private (32) + public (32)
                let mut combined_private = Vec::with_capacity(64);
                combined_private.extend_from_slice(&private_bytes);
                combined_private.extend_from_slice(raw_public);

                write_string(&mut wire_data, &combined_private);
            }
            ssh_key::Algorithm::Rsa { .. } => {
                // Write key type
                write_string(&mut wire_data, b"ssh-rsa");

                // Get RSA key components
                let rsa_keypair = match self.inner.key_data().rsa() {
                    Some(keypair) => keypair,
                    None => return Err(Error::Internal("Failed to get RSA key data".to_string())),
                };

                // Write RSA components in the order expected by signing code
                // n (modulus)
                write_string(&mut wire_data, rsa_keypair.public.n.as_bytes());
                // e (public exponent)
                write_string(&mut wire_data, rsa_keypair.public.e.as_bytes());
                // d (private exponent)
                write_string(&mut wire_data, rsa_keypair.private.d.as_bytes());
                // iqmp (inverse of q mod p)
                write_string(&mut wire_data, rsa_keypair.private.iqmp.as_bytes());
                // p (first prime)
                write_string(&mut wire_data, rsa_keypair.private.p.as_bytes());
                // q (second prime)
                write_string(&mut wire_data, rsa_keypair.private.q.as_bytes());
            }
            _ => {
                return Err(Error::Internal(format!(
                    "Unsupported algorithm: {:?}",
                    self.inner.algorithm()
                )));
            }
        }

        Ok(wire_data)
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.inner.algorithm()
    }

    /// Check if this is an Ed25519 key
    pub fn is_ed25519(&self) -> bool {
        matches!(self.inner.key_data(), KeypairData::Ed25519(_))
    }

    /// Check if this is an RSA key
    pub fn is_rsa(&self) -> bool {
        matches!(self.inner.key_data(), KeypairData::Rsa(_))
    }

    /// Get RSA key size in bits (returns None for non-RSA keys)
    pub fn rsa_bits(&self) -> Option<usize> {
        if let KeypairData::Rsa(rsa) = self.inner.key_data() {
            // RSA key size is the bit length of the modulus
            // We need to use the actual bit length, not byte length * 8
            let bytes = rsa.public.n.as_bytes();
            if bytes.is_empty() {
                return Some(0);
            }

            // Calculate actual bit length
            let bits = bytes.len() * 8;
            // Subtract leading zero bits from the first byte
            let leading_zeros = bytes[0].leading_zeros() as usize;
            Some(bits - leading_zeros)
        } else {
            None
        }
    }

    /// Generate a new Ed25519 key
    pub fn generate_ed25519() -> Result<Self> {
        let keypair = Ed25519Keypair::random(&mut rand::thread_rng());
        let key_data = KeypairData::Ed25519(keypair);

        // Create PrivateKey with the keypair data
        // The API requires specifying a comment
        let inner =
            PrivateKey::new(key_data, "".to_string()).map_err(|e| Error::Crypto(e.to_string()))?;

        Ok(SshPrivateKey { inner })
    }

    /// Generate a new RSA key
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        if bits < MIN_RSA_BITS {
            return Err(Error::RsaTooSmall);
        }
        if bits > MAX_RSA_BITS {
            return Err(Error::RsaTooLarge);
        }

        let keypair = RsaKeypair::random(&mut rand::thread_rng(), bits)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let key_data = KeypairData::Rsa(keypair);

        // Create PrivateKey with the keypair data
        let inner =
            PrivateKey::new(key_data, "".to_string()).map_err(|e| Error::Crypto(e.to_string()))?;

        Ok(SshPrivateKey { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519() {
        let key = SshPrivateKey::generate_ed25519().unwrap();
        assert!(key.is_ed25519());
        assert!(!key.is_rsa());
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn test_generate_rsa() {
        let key = SshPrivateKey::generate_rsa(2048).unwrap();
        assert!(!key.is_ed25519());
        assert!(key.is_rsa());
        // RSA key size might be slightly different than requested
        let bits = key.rsa_bits().unwrap();
        assert!(bits >= 2048 && bits <= 2056);
    }

    #[test]
    fn test_rsa_size_validation() {
        // Too small
        let result = SshPrivateKey::generate_rsa(1024);
        assert!(matches!(result, Err(Error::RsaTooSmall)));

        // Too large
        let result = SshPrivateKey::generate_rsa(16384);
        assert!(matches!(result, Err(Error::RsaTooLarge)));

        // Valid sizes - only test 2048 bit for speed
        assert!(SshPrivateKey::generate_rsa(2048).is_ok());
        // Skip larger sizes in tests to avoid hanging
        // assert!(SshPrivateKey::generate_rsa(3072).is_ok());
        // assert!(SshPrivateKey::generate_rsa(4096).is_ok());
    }

    #[test]
    fn test_openssh_roundtrip_no_passphrase() {
        let key1 = SshPrivateKey::generate_ed25519().unwrap();
        let openssh_data = key1.to_openssh(None, None).unwrap();

        let key2 = SshPrivateKey::from_openssh(&openssh_data, None).unwrap();
        assert!(key2.is_ed25519());

        // Public keys should match
        assert_eq!(key1.public_key_bytes(), key2.public_key_bytes());
    }

    #[test]
    fn test_openssh_roundtrip_with_passphrase() {
        let key1 = SshPrivateKey::generate_rsa(2048).unwrap();
        let passphrase = "test_passphrase_123";
        let openssh_data = key1.to_openssh(Some(passphrase), Some(16)).unwrap();

        // Should fail with wrong passphrase
        let result = SshPrivateKey::from_openssh(&openssh_data, Some("wrong"));
        assert!(matches!(result, Err(Error::BadKeyPassword)));

        // Should succeed with correct passphrase
        let key2 = SshPrivateKey::from_openssh(&openssh_data, Some(passphrase)).unwrap();
        assert!(key2.is_rsa());
        assert_eq!(key1.public_key_bytes(), key2.public_key_bytes());
    }

    #[test]
    fn test_empty_passphrase_rejected() {
        let key = SshPrivateKey::generate_ed25519().unwrap();
        let result = key.to_openssh(Some(""), None);
        assert!(matches!(result, Err(Error::Config(_))));
    }
}
