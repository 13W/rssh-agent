use crate::{Error, Result};
use argon2::{Argon2, Params, Version};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KDF_DOMAIN: &str = "rssh-agent:v1:mem";
const MAX_LOADED_KEYS: usize = 1024;
#[allow(dead_code)]
const MAX_UNLOCK_ATTEMPTS: u32 = 3;
#[allow(dead_code)]
const COOLDOWN_DURATION: Duration = Duration::from_secs(60);

/// Encrypted key data stored in RAM
#[derive(Clone)]
struct EncryptedKey {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    description: String,
    fingerprint: String,
    key_type: String,
    has_cert: bool,
    confirm: bool,
    lifetime_expires_at: Option<Instant>,
    is_external: bool, // true if added via ssh-add, false if managed by rssh-agent
    #[allow(dead_code)]
    created: Instant,
}

/// Memory key for encrypting keys at rest in RAM
#[derive(ZeroizeOnDrop)]
struct MemKey {
    key: [u8; 32],
    salt: [u8; 32],
}

/// Anti-bruteforce state
struct BruteforceProtection {
    attempts: u32,
    last_failure: Option<Instant>,
    cooldown_until: Option<Instant>,
}

/// RAM store for SSH keys
pub struct RamStore {
    inner: Arc<RwLock<RamStoreInner>>,
}

struct RamStoreInner {
    mem_key: Option<MemKey>,
    keys: HashMap<String, EncryptedKey>,
    bruteforce: BruteforceProtection,
    insertion_order: Vec<String>,
}

impl RamStore {
    /// Create a new RAM store
    pub fn new() -> Self {
        RamStore {
            inner: Arc::new(RwLock::new(RamStoreInner {
                mem_key: None,
                keys: HashMap::new(),
                bruteforce: BruteforceProtection {
                    attempts: 0,
                    last_failure: None,
                    cooldown_until: None,
                },
                insertion_order: Vec::new(),
            })),
        }
    }

    /// Check if the store is locked
    pub fn is_locked(&self) -> bool {
        let inner = self.inner.read().unwrap();
        inner.mem_key.is_none()
    }

    /// Lock the store, zeroizing the memory key
    pub fn lock(&self) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        if let Some(mut mem_key) = inner.mem_key.take() {
            mem_key.key.zeroize();
            mem_key.salt.zeroize();
        }
        Ok(())
    }

    /// Unlock the store with the master password
    pub fn unlock(&self, master_password: &str) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        // Check cooldown
        if let Some(cooldown_until) = inner.bruteforce.cooldown_until {
            if Instant::now() < cooldown_until {
                return Err(Error::WrongPassword);
            }
            inner.bruteforce.cooldown_until = None;
            inner.bruteforce.attempts = 0;
        }

        // Generate random salt for this session
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        // Derive memory key
        let key = derive_mem_key(master_password, &salt)?;

        // Store the key
        inner.mem_key = Some(MemKey { key, salt });
        inner.bruteforce.attempts = 0;
        inner.bruteforce.last_failure = None;

        Ok(())
    }

    /// Load a key from disk into RAM
    pub fn load_key(
        &self,
        fingerprint: &str,
        key_data: &[u8],
        description: String,
        key_type: String,
        has_cert: bool,
    ) -> Result<()> {
        self.load_key_internal(
            fingerprint,
            key_data,
            description,
            key_type,
            has_cert,
            false,
        )
    }

    /// Load an external key (from ssh-add) into RAM
    pub fn load_external_key(
        &self,
        fingerprint: &str,
        key_data: &[u8],
        description: String,
        key_type: String,
        has_cert: bool,
    ) -> Result<()> {
        self.load_key_internal(fingerprint, key_data, description, key_type, has_cert, true)
    }

    /// Internal method to load a key with external flag
    fn load_key_internal(
        &self,
        fingerprint: &str,
        key_data: &[u8],
        description: String,
        key_type: String,
        has_cert: bool,
        is_external: bool,
    ) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        // Check if unlocked
        let mem_key = inner.mem_key.as_ref().ok_or(Error::NeedMasterUnlock)?;

        // Check limits
        if inner.keys.len() >= MAX_LOADED_KEYS {
            return Err(Error::TooManyKeys);
        }

        // Check for duplicates
        if inner.keys.contains_key(fingerprint) {
            return Err(Error::AlreadyLoaded);
        }

        // Generate nonce
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt the key data
        let cipher = XChaCha20Poly1305::new_from_slice(&mem_key.key)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let nonce_obj = XNonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_obj, key_data)
            .map_err(|e| Error::Crypto(e.to_string()))?;

        // Store encrypted key
        let encrypted_key = EncryptedKey {
            nonce,
            ciphertext,
            description,
            fingerprint: fingerprint.to_string(),
            key_type,
            has_cert,
            confirm: false,
            lifetime_expires_at: None,
            is_external,
            created: Instant::now(),
        };

        inner.keys.insert(fingerprint.to_string(), encrypted_key);
        inner.insertion_order.push(fingerprint.to_string());

        Ok(())
    }

    /// Unload a key from RAM
    pub fn unload_key(&self, fingerprint: &str) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        if inner.mem_key.is_none() {
            return Err(Error::NeedMasterUnlock);
        }

        if inner.keys.remove(fingerprint).is_none() {
            return Err(Error::NotLoaded);
        }

        inner.insertion_order.retain(|fp| fp != fingerprint);

        Ok(())
    }

    /// List all loaded keys
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let inner = self.inner.read().unwrap();

        if inner.mem_key.is_none() {
            return Err(Error::NeedMasterUnlock);
        }

        let mut keys = Vec::new();
        for fp in &inner.insertion_order {
            if let Some(key) = inner.keys.get(fp) {
                keys.push(KeyInfo {
                    fingerprint: key.fingerprint.clone(),
                    description: key.description.clone(),
                    key_type: key.key_type.clone(),
                    has_cert: key.has_cert,
                    confirm: key.confirm,
                    lifetime_expires_at: key.lifetime_expires_at,
                    is_external: key.is_external,
                });
            }
        }

        Ok(keys)
    }

    /// Get raw key data for an external key (for importing)
    pub fn get_external_key_data(&self, fingerprint: &str) -> Result<Vec<u8>> {
        let inner = self.inner.read().unwrap();

        // Check if unlocked
        let mem_key = inner.mem_key.as_ref().ok_or(Error::NeedMasterUnlock)?;

        // Find the key
        let encrypted_key = inner.keys.get(fingerprint).ok_or(Error::NotFound)?;

        // Check if it's external
        if !encrypted_key.is_external {
            return Err(Error::NotExternal);
        }

        // Decrypt the key data
        let cipher = XChaCha20Poly1305::new_from_slice(&mem_key.key)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let nonce = XNonce::from_slice(&encrypted_key.nonce);

        cipher
            .decrypt(nonce, encrypted_key.ciphertext.as_ref())
            .map_err(|e| Error::Crypto(e.to_string()))
    }

    /// Mark a key as internal (no longer external) after importing
    pub fn mark_key_as_internal(&self, fingerprint: &str) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        // Check if unlocked
        if inner.mem_key.is_none() {
            return Err(Error::NeedMasterUnlock);
        }

        // Find and update the key
        match inner.keys.get_mut(fingerprint) {
            Some(key) => {
                key.is_external = false;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Decrypt a key temporarily for signing
    pub fn with_key<F, R>(&self, fingerprint: &str, f: F) -> Result<R>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        let inner = self.inner.read().unwrap();

        let mem_key = inner.mem_key.as_ref().ok_or(Error::NeedMasterUnlock)?;

        let encrypted_key = inner.keys.get(fingerprint).ok_or(Error::NotFound)?;

        // Check lifetime
        if let Some(expires_at) = encrypted_key.lifetime_expires_at {
            if Instant::now() >= expires_at {
                // Key has expired, we should remove it
                drop(inner);
                self.unload_key(fingerprint)?;
                return Err(Error::NotFound);
            }
        }

        // Decrypt the key
        let cipher = XChaCha20Poly1305::new_from_slice(&mem_key.key)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let nonce = XNonce::from_slice(&encrypted_key.nonce);
        let mut plaintext = cipher
            .decrypt(nonce, encrypted_key.ciphertext.as_ref())
            .map_err(|e| Error::Crypto(e.to_string()))?;

        // Use the key
        let result = f(&plaintext);

        // Zeroize the plaintext
        plaintext.zeroize();

        result
    }

    /// Set constraints for a key
    pub fn set_constraints(
        &self,
        fingerprint: &str,
        confirm: bool,
        lifetime_secs: Option<u64>,
    ) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        if inner.mem_key.is_none() {
            return Err(Error::NeedMasterUnlock);
        }

        let key = inner.keys.get_mut(fingerprint).ok_or(Error::NotFound)?;

        key.confirm = confirm;
        key.lifetime_expires_at =
            lifetime_secs.map(|secs| Instant::now() + Duration::from_secs(secs));

        Ok(())
    }

    /// Update description for a key
    pub fn update_description(&self, fingerprint: &str, description: String) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        if inner.mem_key.is_none() {
            return Err(Error::NeedMasterUnlock);
        }

        let key = inner.keys.get_mut(fingerprint).ok_or(Error::NotFound)?;

        key.description = description;

        Ok(())
    }

    /// Clear all keys from RAM
    pub fn clear_all(&self) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        if inner.mem_key.is_none() {
            return Err(Error::NeedMasterUnlock);
        }

        inner.keys.clear();
        inner.insertion_order.clear();

        Ok(())
    }
}

/// Information about a loaded key
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub description: String,
    pub key_type: String,
    pub has_cert: bool,
    pub confirm: bool,
    pub lifetime_expires_at: Option<Instant>,
    pub is_external: bool,
}

fn derive_mem_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(
        256 * 1024, // 256 MiB
        3,          // 3 iterations
        1,          // 1 thread
        Some(32),
    )
    .map_err(|e| Error::Crypto(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    let mut context = Vec::from(KDF_DOMAIN.as_bytes());
    context.extend_from_slice(salt);

    argon2
        .hash_password_into(password.as_bytes(), &context, &mut key)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_unlock() {
        let store = RamStore::new();
        assert!(store.is_locked());

        store.unlock("test_password").unwrap();
        assert!(!store.is_locked());

        store.lock().unwrap();
        assert!(store.is_locked());
    }

    #[test]
    fn test_operations_require_unlock() {
        let store = RamStore::new();

        // Should fail when locked
        let result = store.load_key("fp", b"data", "desc".into(), "ed25519".into(), false);
        assert!(matches!(result, Err(Error::NeedMasterUnlock)));

        let result = store.list_keys();
        assert!(matches!(result, Err(Error::NeedMasterUnlock)));

        // Should work after unlock
        store.unlock("password").unwrap();

        store
            .load_key("fp", b"data", "desc".into(), "ed25519".into(), false)
            .unwrap();
        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_max_keys_limit() {
        let store = RamStore::new();
        store.unlock("password").unwrap();

        // Load max keys
        for i in 0..MAX_LOADED_KEYS {
            let fp = format!("fp{}", i);
            store
                .load_key(&fp, b"data", "desc".into(), "rsa".into(), false)
                .unwrap();
        }

        // Next one should fail
        let result = store.load_key("extra", b"data", "desc".into(), "rsa".into(), false);
        assert!(matches!(result, Err(Error::TooManyKeys)));
    }

    #[test]
    fn test_duplicate_rejection() {
        let store = RamStore::new();
        store.unlock("password").unwrap();

        store
            .load_key("fp1", b"data", "desc".into(), "ed25519".into(), false)
            .unwrap();

        let result = store.load_key("fp1", b"other", "desc2".into(), "ed25519".into(), false);
        assert!(matches!(result, Err(Error::AlreadyLoaded)));
    }

    #[test]
    fn test_with_key() {
        let store = RamStore::new();
        store.unlock("password").unwrap();

        let data = b"secret_key_data";
        store
            .load_key("fp1", data, "desc".into(), "ed25519".into(), false)
            .unwrap();

        let result = store
            .with_key("fp1", |key_data| {
                assert_eq!(key_data, data);
                Ok(42)
            })
            .unwrap();

        assert_eq!(result, 42);
    }
}
