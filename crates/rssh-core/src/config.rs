use crate::{Error, Result, kdf::derive_key_with_domain};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SENTINEL_PLAINTEXT: &[u8] = b"ok";
const KDF_DOMAIN: &str = "rssh-agent:v1:config";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: String,
    pub sentinel: Sentinel,
    pub settings: Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sentinel {
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
pub struct Settings {
    pub storage_dir: PathBuf,
    pub fingerprint_ui: String,
    pub allow_rsa_sha1: bool,
}

impl Config {
    /// Create a new config with sentinel AEAD("ok")
    pub fn new_with_sentinel<P: AsRef<Path>>(
        storage_dir: P,
        master_password: &str,
    ) -> Result<Self> {
        let storage_dir = storage_dir.as_ref().to_path_buf();

        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 24];
        use chacha20poly1305::aead::rand_core::RngCore;
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive key using Argon2id
        let key = derive_key_with_domain(KDF_DOMAIN, master_password, &salt, 256, 3, 1)?;

        // Encrypt sentinel
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*key).map_err(|e| Error::Crypto(e.to_string()))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, SENTINEL_PLAINTEXT)
            .map_err(|e| Error::Crypto(e.to_string()))?;

        Ok(Config {
            version: "rssh-config/v1".to_string(),
            sentinel: Sentinel {
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
            },
            settings: Settings {
                storage_dir,
                fingerprint_ui: "sha256".to_string(),
                allow_rsa_sha1: false,
            },
        })
    }

    /// Verify the sentinel with the given master password
    pub fn verify_sentinel(&self, master_password: &str) -> bool {
        if self.sentinel.kdf.name != "argon2id" {
            return false;
        }
        if self.sentinel.aead.name != "xchacha20poly1305" {
            return false;
        }

        let Ok(salt) = BASE64.decode(&self.sentinel.kdf.salt_b64) else {
            return false;
        };
        let Ok(nonce_bytes) = BASE64.decode(&self.sentinel.aead.nonce_b64) else {
            return false;
        };
        let Ok(ciphertext) = BASE64.decode(&self.sentinel.ciphertext_b64) else {
            return false;
        };

        if nonce_bytes.len() != 24 {
            return false;
        }

        let Ok(key) = derive_key_with_domain(
            KDF_DOMAIN,
            master_password,
            &salt,
            self.sentinel.kdf.mib,
            self.sentinel.kdf.t,
            self.sentinel.kdf.p,
        ) else {
            return false;
        };

        let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&*key) else {
            return false;
        };

        let nonce = XNonce::from_slice(&nonce_bytes);
        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext.as_ref()) {
            plaintext == SENTINEL_PLAINTEXT
        } else {
            false
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_roundtrip_serialization() {
        let temp = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp.path(), "test_password_12345").unwrap();

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, "rssh-config/v1");
        assert_eq!(parsed.settings.fingerprint_ui, "sha256");
        assert_eq!(parsed.settings.allow_rsa_sha1, false);
        assert_eq!(parsed.sentinel.kdf.name, "argon2id");
        assert_eq!(parsed.sentinel.aead.name, "xchacha20poly1305");
    }

    #[test]
    fn test_verify_sentinel_correct_password() {
        let temp = TempDir::new().unwrap();
        let password = "correct_horse_battery_staple";
        let config = Config::new_with_sentinel(temp.path(), password).unwrap();

        assert!(config.verify_sentinel(password));
    }

    #[test]
    fn test_verify_sentinel_wrong_password() {
        let temp = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp.path(), "correct_password").unwrap();

        assert!(!config.verify_sentinel("wrong_password"));
    }

    #[test]
    fn test_reject_malformed_config() {
        let json = r#"{
            "version": "rssh-config/v1",
            "sentinel": {
                "kdf": {
                    "name": "invalid",
                    "mib": 256,
                    "t": 3,
                    "p": 1,
                    "salt_b64": "dGVzdA=="
                },
                "aead": {
                    "name": "xchacha20poly1305",
                    "nonce_b64": "dGVzdA=="
                },
                "ciphertext_b64": "dGVzdA=="
            },
            "settings": {
                "storage_dir": "/tmp",
                "fingerprint_ui": "sha256",
                "allow_rsa_sha1": false
            }
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert!(!config.verify_sentinel("any_password"));
    }

    #[test]
    fn test_reject_missing_fields() {
        let json = r#"{
            "version": "rssh-config/v1",
            "sentinel": {
                "kdf": {
                    "name": "argon2id"
                }
            }
        }"#;

        let result: std::result::Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
