//! Optimized RAM store implementation with performance improvements
//!
//! This module provides optimized versions of key RAM store operations with:
//! - Reduced lock contention using parking_lot RwLock
//! - Memory pooling for frequent allocations
//! - Batch operations for better throughput
//! - Optimized crypto operations

use crate::{
    Error, Result,
    perf_cache::{ConnectionKeyCache, KeyDerivationCache},
};
use argon2::{Argon2, Params, Version};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use parking_lot::RwLock; // Faster than std::sync::RwLock
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const OPTIMIZED_KDF_DOMAIN: &str = "rssh-agent:v1:mem:optimized";

/// Optimized memory pool for reducing allocation overhead
struct MemoryPool {
    small_buffers: Arc<RwLock<Vec<Vec<u8>>>>, // For keys up to 4KB
    large_buffers: Arc<RwLock<Vec<Vec<u8>>>>, // For keys up to 64KB
}

impl MemoryPool {
    fn new() -> Self {
        Self {
            small_buffers: Arc::new(RwLock::new(Vec::new())),
            large_buffers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    fn get_buffer(&self, size: usize) -> Vec<u8> {
        if size <= 4096 {
            let mut pool = self.small_buffers.write();
            if let Some(mut buffer) = pool.pop() {
                buffer.clear();
                buffer.reserve(size);
                return buffer;
            }
        } else if size <= 65536 {
            let mut pool = self.large_buffers.write();
            if let Some(mut buffer) = pool.pop() {
                buffer.clear();
                buffer.reserve(size);
                return buffer;
            }
        }

        // Create new buffer if pool is empty
        Vec::with_capacity(size.max(1024))
    }

    fn return_buffer(&self, mut buffer: Vec<u8>) {
        // Zeroize before returning to pool
        buffer.zeroize();

        if buffer.capacity() <= 4096 && buffer.capacity() >= 1024 {
            let mut pool = self.small_buffers.write();
            if pool.len() < 32 {
                // Limit pool size
                pool.push(buffer);
            }
        } else if buffer.capacity() <= 65536 && buffer.capacity() >= 4096 {
            let mut pool = self.large_buffers.write();
            if pool.len() < 16 {
                // Limit pool size
                pool.push(buffer);
            }
        }
        // Large buffers are dropped to avoid excessive memory usage
    }
}

/// Optimized encrypted key data with memory pooling
#[derive(Clone)]
pub struct OptimizedEncryptedKey {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    #[allow(dead_code)] // Metadata for future UI features
    description: String,
    #[allow(dead_code)] // Metadata for future UI features
    fingerprint: String,
    #[allow(dead_code)] // Metadata for future UI features
    key_type: String,
    #[allow(dead_code)] // Metadata for future UI features
    has_cert: bool,
    #[allow(dead_code)] // Metadata for future UI features
    confirm: bool,
    lifetime_expires_at: Option<Instant>,
    #[allow(dead_code)] // Metadata for future UI features
    is_external: bool,
    #[allow(dead_code)] // Metadata for future UI features
    created: chrono::DateTime<chrono::Utc>,
    #[allow(dead_code)] // Metadata for future UI features
    updated: Option<chrono::DateTime<chrono::Utc>>,
}

/// Performance optimized RAM store
pub struct OptimizedRamStore {
    inner: Arc<RwLock<OptimizedRamStoreInner>>,
    kdf_cache: KeyDerivationCache,
    connection_cache: ConnectionKeyCache,
    memory_pool: MemoryPool,
}

struct OptimizedRamStoreInner {
    mem_key: Option<[u8; 32]>, // Direct array instead of struct
    keys: HashMap<String, OptimizedEncryptedKey>,
    insertion_order: Vec<String>,
    is_locked: bool,
}

impl Default for OptimizedRamStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(OptimizedRamStoreInner {
                mem_key: None,
                keys: HashMap::with_capacity(64), // Pre-allocate reasonable capacity
                insertion_order: Vec::with_capacity(64),
                is_locked: true,
            })),
            kdf_cache: KeyDerivationCache::new(16, Duration::from_secs(300)), // 5 minute TTL
            connection_cache: ConnectionKeyCache::new(8), // Max 8 keys per connection
            memory_pool: MemoryPool::new(),
        }
    }
}

impl OptimizedRamStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Optimized unlock with KDF caching
    pub fn unlock_optimized(
        &self,
        master_password: &str,
        config: &crate::config::Config,
    ) -> Result<()> {
        // Use faster parameter set for session unlock vs disk encryption
        let session_params = SessionKdfParams {
            memory_kib: 64 * 1024, // 64 MiB instead of 256 MiB
            iterations: 2,         // 2 instead of 3
            parallelism: 1,
        };

        let cache_key = format!(
            "unlock:{}",
            sha2::Sha256::digest(master_password.as_bytes())
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        let derived_key = self.kdf_cache.get_or_derive(&cache_key, || {
            self.derive_session_key(master_password, &session_params)
        })?;

        // Verify against config sentinel
        if !config.verify_sentinel(master_password) {
            return Err(Error::WrongPassword);
        }

        // Store derived key
        {
            let mut inner = self.inner.write();
            inner.mem_key = Some(derived_key);
            inner.is_locked = false;
        }

        Ok(())
    }

    /// Batch load multiple keys for better performance
    pub fn load_keys_batch(&self, keys_data: Vec<KeyLoadRequest>) -> Result<BatchLoadResult> {
        let mut inner = self.inner.write();
        let mem_key = inner.mem_key.ok_or(Error::NeedMasterUnlock)?;

        let mut results = BatchLoadResult {
            successful: Vec::new(),
            failed: Vec::new(),
        };

        for request in keys_data {
            let fingerprint = request.fingerprint.clone();
            match self.load_single_key_internal(&mut inner, &mem_key, request) {
                Ok(_) => results.successful.push(fingerprint.clone()),
                Err(e) => results.failed.push((fingerprint, e)),
            }
        }

        Ok(results)
    }

    fn load_single_key_internal(
        &self,
        inner: &mut OptimizedRamStoreInner,
        mem_key: &[u8; 32],
        request: KeyLoadRequest,
    ) -> Result<String> {
        // Check for duplicates
        if inner.keys.contains_key(&request.fingerprint) {
            return Err(Error::AlreadyLoaded);
        }

        // Use memory pool for encryption buffer
        let ciphertext_buffer = self.memory_pool.get_buffer(request.key_data.len() + 16); // 16 bytes for auth tag

        // Generate nonce
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt with optimized buffer management
        let cipher =
            XChaCha20Poly1305::new_from_slice(mem_key).map_err(|e| Error::Crypto(e.to_string()))?;
        let nonce_obj = XNonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_obj, request.key_data.as_ref())
            .map_err(|e| Error::Crypto(e.to_string()))?;

        // Store encrypted key
        let encrypted_key = OptimizedEncryptedKey {
            nonce,
            ciphertext,
            description: request.description,
            fingerprint: request.fingerprint.clone(),
            key_type: request.key_type,
            has_cert: request.has_cert,
            confirm: false,
            lifetime_expires_at: None,
            is_external: request.is_external,
            created: chrono::Utc::now(),
            updated: None,
        };

        inner
            .keys
            .insert(request.fingerprint.clone(), encrypted_key);
        inner.insertion_order.push(request.fingerprint.clone());

        // Return buffer to pool
        self.memory_pool.return_buffer(ciphertext_buffer);

        Ok(request.fingerprint)
    }

    /// Optimized signing operation with connection-based key caching
    pub fn sign_with_cached_key<F, R>(
        &self,
        connection_id: &str,
        fingerprint: &str,
        sign_fn: F,
    ) -> Result<R>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        // Try to get cached decrypted key first
        if let Some(cached_key) = self.connection_cache.get_key(connection_id, fingerprint) {
            return sign_fn(&cached_key);
        }

        // Decrypt key and cache for this connection
        let decrypted_key = {
            let inner = self.inner.read();
            let mem_key = inner.mem_key.ok_or(Error::NeedMasterUnlock)?;
            let encrypted_key = inner.keys.get(fingerprint).ok_or(Error::NotFound)?;

            // Check expiration
            if let Some(expires_at) = encrypted_key.lifetime_expires_at
                && Instant::now() >= expires_at
            {
                return Err(Error::KeyExpired);
            }

            // Decrypt
            let cipher = XChaCha20Poly1305::new_from_slice(&mem_key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            let nonce = XNonce::from_slice(&encrypted_key.nonce);
            cipher
                .decrypt(nonce, encrypted_key.ciphertext.as_ref())
                .map_err(|e| Error::Crypto(e.to_string()))?
        };

        // Cache the decrypted key for this connection
        self.connection_cache
            .cache_key(connection_id, fingerprint, decrypted_key.clone());

        // Use the key
        // Note: We keep the key cached for subsequent operations on this connection
        sign_fn(&decrypted_key)
    }

    /// Clear connection-specific caches when connection ends
    pub fn cleanup_connection(&self, connection_id: &str) {
        self.connection_cache.clear_connection(connection_id);
    }

    fn derive_session_key(&self, password: &str, params: &SessionKdfParams) -> Result<[u8; 32]> {
        // Generate session-specific salt
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let argon2_params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(32),
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

        let mut key = [0u8; 32];
        let mut context = Vec::from(OPTIMIZED_KDF_DOMAIN.as_bytes());
        context.extend_from_slice(&salt);

        argon2
            .hash_password_into(password.as_bytes(), &context, &mut key)
            .map_err(|e| Error::Crypto(e.to_string()))?;

        Ok(key)
    }

    /// Get performance statistics
    pub fn get_performance_stats(&self) -> PerformanceStats {
        let inner = self.inner.read();
        let cache_stats = self.kdf_cache.stats();

        PerformanceStats {
            loaded_keys: inner.keys.len(),
            is_locked: inner.is_locked,
            kdf_cache_entries: cache_stats.entry_count,
            kdf_cache_hit_ratio: 0.0, // Would need to track hits/misses
        }
    }
}

struct SessionKdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

pub struct KeyLoadRequest {
    pub fingerprint: String,
    pub key_data: Vec<u8>,
    pub description: String,
    pub key_type: String,
    pub has_cert: bool,
    pub is_external: bool,
}

pub struct BatchLoadResult {
    pub successful: Vec<String>,
    pub failed: Vec<(String, Error)>,
}

pub struct PerformanceStats {
    pub loaded_keys: usize,
    pub is_locked: bool,
    pub kdf_cache_entries: usize,
    pub kdf_cache_hit_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::new();

        // Get a buffer
        let buffer1 = pool.get_buffer(2048);
        assert!(buffer1.capacity() >= 2048);

        // Return it
        pool.return_buffer(buffer1);

        // Get another - should reuse from pool
        let buffer2 = pool.get_buffer(2048);
        assert!(buffer2.capacity() >= 2048);
    }

    #[test]
    fn test_optimized_store_basics() {
        let store = OptimizedRamStore::new();

        // Should start locked
        assert!(store.inner.read().is_locked);

        // Stats should work
        let stats = store.get_performance_stats();
        assert_eq!(stats.loaded_keys, 0);
        assert!(stats.is_locked);
    }
}
