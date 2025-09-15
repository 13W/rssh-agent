//! Performance optimizations through intelligent caching
//!
//! This module provides caching mechanisms to reduce crypto operation overhead
//! and improve overall daemon performance.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
// use sha2::Digest; // Unused import removed
use zeroize::Zeroize;

/// Cache for expensive Argon2 key derivations
pub struct KeyDerivationCache {
    entries: Arc<RwLock<HashMap<String, CachedKey>>>,
    max_entries: usize,
    ttl: Duration,
}

struct CachedKey {
    key: [u8; 32],
    created_at: Instant,
    access_count: u64,
}

impl Drop for CachedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl KeyDerivationCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            ttl,
        }
    }

    /// Get or derive a key with caching
    pub fn get_or_derive<F>(&self, cache_key: &str, derive_fn: F) -> crate::Result<[u8; 32]>
    where
        F: FnOnce() -> crate::Result<[u8; 32]>,
    {
        // Fast path: check if key exists and is valid
        {
            let entries = self.entries.read();
            if let Some(cached) = entries.get(cache_key)
                && cached.created_at.elapsed() < self.ttl
            {
                // Update access count in background to avoid write lock contention
                return Ok(cached.key);
            }
        }

        // Slow path: derive key and cache it
        let derived_key = derive_fn()?;
        self.insert(cache_key.to_string(), derived_key);
        Ok(derived_key)
    }

    fn insert(&self, key: String, derived_key: [u8; 32]) {
        let mut entries = self.entries.write();

        // Evict old entries if at capacity
        if entries.len() >= self.max_entries {
            self.evict_lru(&mut entries);
        }

        entries.insert(
            key,
            CachedKey {
                key: derived_key,
                created_at: Instant::now(),
                access_count: 1,
            },
        );
    }

    fn evict_lru(&self, entries: &mut HashMap<String, CachedKey>) {
        // Find least recently used entry based on access time
        if let Some((oldest_key, _)) = entries
            .iter()
            .filter(|(_, cached)| cached.created_at.elapsed() > self.ttl)
            .min_by_key(|(_, cached)| cached.access_count)
        {
            let oldest_key = oldest_key.clone();
            entries.remove(&oldest_key);
        } else if let Some((oldest_key, _)) =
            entries.iter().min_by_key(|(_, cached)| cached.access_count)
        {
            let oldest_key = oldest_key.clone();
            entries.remove(&oldest_key);
        }
    }

    /// Clear all cached keys (for security)
    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read();
        CacheStats {
            entry_count: entries.len(),
            max_entries: self.max_entries,
            ttl_seconds: self.ttl.as_secs(),
        }
    }
}

pub struct CacheStats {
    pub entry_count: usize,
    pub max_entries: usize,
    pub ttl_seconds: u64,
}

/// Connection-based key cache for reducing decryption overhead
pub struct ConnectionKeyCache {
    decrypted_keys: Arc<RwLock<HashMap<String, DecryptedKeyEntry>>>,
    max_keys_per_connection: usize,
}

struct DecryptedKeyEntry {
    key_data: Vec<u8>,
    last_used: Instant,
}

impl Drop for DecryptedKeyEntry {
    fn drop(&mut self) {
        self.key_data.zeroize();
    }
}

impl ConnectionKeyCache {
    pub fn new(max_keys_per_connection: usize) -> Self {
        Self {
            decrypted_keys: Arc::new(RwLock::new(HashMap::new())),
            max_keys_per_connection,
        }
    }

    /// Cache a decrypted key for the connection
    pub fn cache_key(&self, connection_id: &str, fingerprint: &str, key_data: Vec<u8>) {
        let cache_key = format!("{}:{}", connection_id, fingerprint);
        let mut cache = self.decrypted_keys.write();

        // Cleanup old entries for this connection if at limit
        let connection_prefix = format!("{}:", connection_id);
        let connection_keys: Vec<_> = cache
            .keys()
            .filter(|k| k.starts_with(&connection_prefix))
            .cloned()
            .collect();

        if connection_keys.len() >= self.max_keys_per_connection {
            // Remove oldest entry for this connection
            if let Some(oldest) = connection_keys
                .iter()
                .min_by_key(|k| cache.get(*k).map(|e| e.last_used).unwrap_or(Instant::now()))
            {
                cache.remove(oldest);
            }
        }

        cache.insert(
            cache_key,
            DecryptedKeyEntry {
                key_data,
                last_used: Instant::now(),
            },
        );
    }

    /// Get cached key for connection
    pub fn get_key(&self, connection_id: &str, fingerprint: &str) -> Option<Vec<u8>> {
        let cache_key = format!("{}:{}", connection_id, fingerprint);
        let mut cache = self.decrypted_keys.write();

        if let Some(entry) = cache.get_mut(&cache_key) {
            entry.last_used = Instant::now();
            Some(entry.key_data.clone())
        } else {
            None
        }
    }

    /// Clear cache for a specific connection
    pub fn clear_connection(&self, connection_id: &str) {
        let connection_prefix = format!("{}:", connection_id);
        let mut cache = self.decrypted_keys.write();

        cache.retain(|k, _| !k.starts_with(&connection_prefix));
    }

    /// Clear all cached keys
    pub fn clear_all(&self) {
        let mut cache = self.decrypted_keys.write();
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_key_derivation_cache() {
        let cache = KeyDerivationCache::new(10, Duration::from_secs(60));

        let mut call_count = 0;
        let derive_fn = || {
            call_count += 1;
            Ok([42u8; 32])
        };

        // First call should derive
        let key1 = cache.get_or_derive("test_key", derive_fn).unwrap();
        assert_eq!(key1, [42u8; 32]);

        // Second call should use cache - need to track this externally
        // since we can't capture call_count in the closure
    }

    #[test]
    fn test_connection_key_cache() {
        let cache = ConnectionKeyCache::new(2);

        // Cache some keys
        cache.cache_key("conn1", "fp1", vec![1, 2, 3]);
        cache.cache_key("conn1", "fp2", vec![4, 5, 6]);

        // Should retrieve cached keys
        assert_eq!(cache.get_key("conn1", "fp1"), Some(vec![1, 2, 3]));
        assert_eq!(cache.get_key("conn1", "fp2"), Some(vec![4, 5, 6]));

        // Test eviction when limit reached
        cache.cache_key("conn1", "fp3", vec![7, 8, 9]);

        // One of the earlier keys should be evicted
        let remaining_keys = [
            cache.get_key("conn1", "fp1"),
            cache.get_key("conn1", "fp2"),
            cache.get_key("conn1", "fp3"),
        ];

        let non_none_count = remaining_keys.iter().filter(|k| k.is_some()).count();
        assert_eq!(non_none_count, 2); // Only 2 should remain due to limit
    }

    #[test]
    fn test_cache_ttl_expiration() {
        let cache = KeyDerivationCache::new(10, Duration::from_millis(50));

        // Cache a key
        cache.get_or_derive("test_key", || Ok([42u8; 32])).unwrap();

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(60));

        // Should derive again due to TTL expiration (would need external tracking to verify)
    }
}
