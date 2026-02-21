use crate::{Error, Result};
use argon2::{Argon2, Params, Version};

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KDF_DOMAIN: &str = "rssh-agent:v1:mem";
const MAX_LOADED_KEYS: usize = 1024;
// Anti-bruteforce protection constants
const MAX_UNLOCK_ATTEMPTS: u32 = 5; // Maximum attempts before permanent lockout
const BASE_DELAY_SECS: u64 = 1; // Base delay for exponential backoff
const MAX_DELAY_SECS: u64 = 300;

// Lifetime expiry management constants
const CLEANUP_INTERVAL_SECS: u64 = 60; // Check for expired keys every 60 seconds
const CLEANUP_BATCH_SIZE: usize = 10; // Maximum keys to cleanup per batch
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 300; // 5 minutes tolerance for clock changes

/// Type alias for confirmation function to reduce complexity
#[allow(dead_code)] // Used in with_key_confirmed function
type ConfirmFn = Box<dyn Fn(&str, &str, &str) -> Result<bool>>;

/// Type alias for notification function (info-only, no approval needed)
#[allow(dead_code)] // Used in with_key_confirmed function  
type NotifyFn = Box<dyn Fn(&str, &str, &str) -> Result<()>>;

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
    notification: bool,
    lifetime_expires_at: Option<Instant>, // Keep as Instant for lifetime expiration logic
    is_external: bool, // true if added via ssh-add, false if managed by rssh-agent
    created: chrono::DateTime<chrono::Utc>, // Use DateTime for serialization compatibility
    updated: Option<chrono::DateTime<chrono::Utc>>, // None for keys that haven't been updated since creation
    public_key: Vec<u8>, // Cached public key blob for listing without decryption
}

/// Memory key for encrypting keys at rest in RAM
#[derive(ZeroizeOnDrop)]
struct MemKey {
    key: [u8; 32],
    salt: [u8; 32],
}

/// Anti-bruteforce protection with exponential backoff
#[derive(Debug)]
struct BruteforceProtection {
    /// Number of consecutive failed attempts
    attempts: u32,
    /// Timestamp of last failed attempt
    last_failure: Option<Instant>,
    /// Current backoff delay in seconds
    current_delay: u64,
    /// Maximum number of attempts before permanent lockout
    max_attempts: u32,
    /// Base delay for exponential backoff (seconds)
    base_delay: u64,
    /// Maximum delay cap (seconds)
    max_delay: u64,
}

impl BruteforceProtection {
    fn new() -> Self {
        Self {
            attempts: 0,
            last_failure: None,
            current_delay: BASE_DELAY_SECS,
            max_attempts: MAX_UNLOCK_ATTEMPTS,
            base_delay: BASE_DELAY_SECS,
            max_delay: MAX_DELAY_SECS,
        }
    }

    /// Check if we're currently in a rate-limited state
    fn is_rate_limited(&self) -> Option<u64> {
        if let Some(last_failure) = self.last_failure {
            let elapsed = last_failure.elapsed().as_secs();
            if elapsed < self.current_delay {
                return Some(self.current_delay - elapsed);
            }
        }
        None
    }

    /// Check if permanently locked out (too many attempts)
    fn is_permanently_locked(&self) -> bool {
        self.attempts >= self.max_attempts
    }

    /// Record a failed password attempt
    fn record_failure(&mut self) {
        self.attempts += 1;
        self.last_failure = Some(Instant::now());

        // Exponential backoff: double the delay each time, capped at max
        self.current_delay = (self.current_delay * 2).min(self.max_delay);

        tracing::warn!(
            "Password verification failed - attempt {}/{}, next attempt in {}s",
            self.attempts,
            self.max_attempts,
            self.current_delay
        );
    }

    /// Reset protection state after successful unlock
    fn reset(&mut self) {
        self.attempts = 0;
        self.last_failure = None;
        self.current_delay = self.base_delay;
        tracing::debug!("Bruteforce protection reset after successful unlock");
    }

    /// Get security status for logging
    fn security_status(&self) -> String {
        if self.is_permanently_locked() {
            format!("LOCKED_OUT (attempts: {})", self.attempts)
        } else if let Some(remaining) = self.is_rate_limited() {
            format!(
                "RATE_LIMITED ({}s remaining, attempts: {})",
                remaining, self.attempts
            )
        } else {
            format!("OK (attempts: {})", self.attempts)
        }
    }
}

/// Cleanup task management
pub struct CleanupTask {
    shutdown_flag: Arc<AtomicBool>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl CleanupTask {
    fn new() -> Self {
        Self {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            task_handle: None,
        }
    }

    fn is_running(&self) -> bool {
        self.task_handle
            .as_ref()
            .map(|handle| !handle.is_finished())
            .unwrap_or(false)
    }

    fn shutdown(&mut self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
        }
    }
}

/// RAM store for SSH keys
pub struct RamStore {
    inner: Arc<RwLock<RamStoreInner>>,
    cleanup_task: Arc<RwLock<CleanupTask>>,
}

struct RamStoreInner {
    mem_key: Option<MemKey>,
    keys: HashMap<String, EncryptedKey>,
    bruteforce: BruteforceProtection,
    insertion_order: Vec<String>,
    last_cleanup: Instant,
    last_system_time: std::time::SystemTime,
    /// Persistent salt for MemKey - preserved across lock/unlock cycles
    /// to ensure encrypted keys remain accessible after unlock
    persistent_salt: Option<[u8; 32]>,
}

impl Default for RamStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RamStore {
    /// Create a new RAM store
    pub fn new() -> Self {
        let now = Instant::now();
        let system_time = std::time::SystemTime::now();
        RamStore {
            inner: Arc::new(RwLock::new(RamStoreInner {
                mem_key: None,
                keys: HashMap::new(),
                bruteforce: BruteforceProtection::new(),
                insertion_order: Vec::new(),
                last_cleanup: now,
                last_system_time: system_time,
                persistent_salt: None,
            })),
            cleanup_task: Arc::new(RwLock::new(CleanupTask::new())),
        }
    }

    /// Check if the store is locked
    pub fn is_locked(&self) -> bool {
        let inner = self.inner.read().unwrap();
        inner.mem_key.is_none()
    }

    /// Lock the store, zeroizing the memory key
    pub fn lock(&self) -> Result<()> {
        // Stop cleanup task when locking
        self.stop_cleanup_task();

        let mut inner = self.inner.write().unwrap();

        if let Some(mut mem_key) = inner.mem_key.take() {
            mem_key.key.zeroize();
            mem_key.salt.zeroize();
        }
        Ok(())
    }

    /// Start the background cleanup task (only if in tokio runtime context)
    pub fn start_cleanup_task(&self) {
        // Check if we're in a tokio runtime context
        let runtime_handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(_) => {
                // Not in a tokio runtime context - likely in tests
                tracing::debug!("Not starting cleanup task - no tokio runtime available");
                return;
            }
        };

        let inner_clone = self.inner.clone();

        // Check if task is already running
        {
            let mut cleanup_task = self.cleanup_task.write().unwrap();
            if cleanup_task.is_running() {
                return;
            }

            // Start new cleanup task
            let shutdown_flag = cleanup_task.shutdown_flag.clone();
            let task_handle = runtime_handle.spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                while !shutdown_flag.load(Ordering::Relaxed) {
                    tokio::select! {
                        _ = interval.tick() => {
                            if let Err(e) = Self::cleanup_expired_keys_internal(&inner_clone) {
                                tracing::warn!("Cleanup task encountered error: {}", e);
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {
                            // Allow for responsive shutdown
                            if shutdown_flag.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                }
                tracing::debug!("Cleanup task shutting down");
            });

            cleanup_task.task_handle = Some(task_handle);
        }

        tracing::info!("Started background key expiry cleanup task");
    }

    /// Stop the background cleanup task
    pub fn stop_cleanup_task(&self) {
        let mut cleanup_task = self.cleanup_task.write().unwrap();
        cleanup_task.shutdown();
        tracing::debug!("Stopped background key expiry cleanup task");
    }

    /// Manually trigger cleanup of expired keys (on-demand cleanup)
    pub fn cleanup_expired_keys(&self) -> Result<usize> {
        Self::cleanup_expired_keys_internal(&self.inner)
    }

    /// Internal cleanup implementation
    fn cleanup_expired_keys_internal(inner_arc: &Arc<RwLock<RamStoreInner>>) -> Result<usize> {
        let mut inner = inner_arc.write().unwrap();

        if inner.mem_key.is_none() {
            // Store is locked, no cleanup needed
            return Ok(0);
        }

        let now = Instant::now();
        let system_now = std::time::SystemTime::now();

        // Check for significant clock changes (system suspend/resume, time adjustment)
        let time_diff = system_now
            .duration_since(inner.last_system_time)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_else(|e| -(e.duration().as_secs() as i64));

        let monotonic_diff = now.duration_since(inner.last_cleanup).as_secs() as i64;
        let clock_skew = time_diff - monotonic_diff;

        if clock_skew.abs() > CLOCK_SKEW_TOLERANCE_SECS {
            tracing::warn!(
                "Detected significant clock change: {}s skew. Adjusting expiry times.",
                clock_skew
            );

            // Adjust all expiry times by the clock skew to handle system time changes
            for key in inner.keys.values_mut() {
                if let Some(expires_at) = &mut key.lifetime_expires_at {
                    if clock_skew < 0 {
                        // Clock went backwards - extend expiry times
                        *expires_at += Duration::from_secs((-clock_skew) as u64);
                    } else if clock_skew > 0 {
                        // Clock went forwards - reduce expiry times (but not below current time)
                        let reduction = Duration::from_secs(clock_skew as u64);
                        if let Some(reduced_time) = expires_at.checked_sub(reduction) {
                            *expires_at = reduced_time.max(now);
                        } else {
                            *expires_at = now; // If underflow, set to current time
                        }
                    }
                }
            }
        }

        // Update timestamps
        inner.last_cleanup = now;
        inner.last_system_time = system_now;

        // Find expired keys
        let mut expired_keys = Vec::new();
        for (fingerprint, key) in &inner.keys {
            if let Some(expires_at) = key.lifetime_expires_at
                && now >= expires_at
            {
                expired_keys.push(fingerprint.clone());
                if expired_keys.len() >= CLEANUP_BATCH_SIZE {
                    break; // Limit batch size to prevent blocking
                }
            }
        }

        if expired_keys.is_empty() {
            return Ok(0);
        }

        // Remove expired keys with proper zeroization
        let expired_count = expired_keys.len();
        for fingerprint in expired_keys {
            if let Some(mut key) = inner.keys.remove(&fingerprint) {
                // Zeroize the encrypted key data
                key.ciphertext.zeroize();
                key.nonce.zeroize();
                key.description.zeroize();

                // Remove from insertion order
                inner.insertion_order.retain(|fp| fp != &fingerprint);

                tracing::info!(
                    "Expired key removed: type={}, fingerprint={}",
                    key.key_type,
                    &fingerprint[..12] // Only log partial fingerprint for security
                );
            }
        }

        tracing::debug!("Cleaned up {} expired keys", expired_count);
        Ok(expired_count)
    }

    /// Unlock the store with the master password, with anti-bruteforce protection
    pub fn unlock(&self, master_password: &str, config: &crate::config::Config) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        // Check if permanently locked out
        if inner.bruteforce.is_permanently_locked() {
            tracing::error!(
                "Unlock attempt blocked - permanently locked out after {} failed attempts",
                inner.bruteforce.attempts
            );
            return Err(Error::RateLimited(u64::MAX)); // Indicate permanent lockout
        }

        // Check rate limiting
        if let Some(remaining_secs) = inner.bruteforce.is_rate_limited() {
            tracing::warn!(
                "Unlock attempt blocked - rate limited for {} more seconds (attempt {}/{})",
                remaining_secs,
                inner.bruteforce.attempts,
                inner.bruteforce.max_attempts
            );
            return Err(Error::RateLimited(remaining_secs));
        }

        // Log security status before verification attempt
        tracing::debug!(
            "Password verification attempt - security status: {}",
            inner.bruteforce.security_status()
        );

        // Verify password against config sentinel
        if !config.verify_sentinel(master_password) {
            // Record the failed attempt
            inner.bruteforce.record_failure();

            tracing::error!(
                "Password verification failed - security status: {}",
                inner.bruteforce.security_status()
            );

            return Err(Error::WrongPassword);
        }

        // Password is correct - proceed with unlock
        tracing::info!("Password verified successfully, unlocking store");

        // Use persistent salt if available, otherwise generate new one
        let salt = if let Some(existing_salt) = inner.persistent_salt {
            tracing::debug!("Reusing persistent salt for MemKey consistency");
            existing_salt
        } else {
            // First unlock - generate new salt and store it persistently
            let mut new_salt = [0u8; 32];
            OsRng.fill_bytes(&mut new_salt);
            inner.persistent_salt = Some(new_salt);
            tracing::debug!("Generated new persistent salt for MemKey");
            new_salt
        };

        // Derive memory key
        let key = derive_mem_key(master_password, &salt)?;

        // Store the key
        inner.mem_key = Some(MemKey { key, salt });

        // Reset bruteforce protection on successful unlock
        inner.bruteforce.reset();

        // Update timestamps for cleanup tracking
        inner.last_cleanup = Instant::now();
        inner.last_system_time = std::time::SystemTime::now();

        // Drop the write lock before starting cleanup task
        drop(inner);

        // Start the cleanup task now that we're unlocked
        self.start_cleanup_task();

        tracing::info!("Store unlocked successfully");
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

    #[allow(clippy::too_many_arguments)]
    /// Load a key into RAM with default constraints applied
    pub fn load_key_with_defaults(
        &self,
        fingerprint: &str,
        key_data: &[u8],
        description: String,
        key_type: String,
        has_cert: bool,
        default_confirm: bool,
        default_notification: bool,
        default_lifetime_seconds: Option<u64>,
    ) -> Result<()> {
        // First load the key normally
        self.load_key_internal(
            fingerprint,
            key_data,
            description,
            key_type,
            has_cert,
            false, // is_external = false for keys from disk
        )?;

        // Apply default constraints if any are specified
        if default_confirm || default_notification || default_lifetime_seconds.is_some() {
            self.set_constraints(
                fingerprint,
                default_confirm,
                default_notification,
                default_lifetime_seconds,
            )?;
        }

        Ok(())
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

        // Extract public key for caching
        // Try to parse as wire format first (fastest and most common for external keys)
        let public_key = match crate::keyfile::parse_wire_key_fingerprint(key_data) {
            Ok(_) => {
                // If it parses as wire format, we need to extract the public key blob
                crate::wire::extract_public_key(key_data).unwrap_or_default()
            }
            Err(_) => {
                // If not wire format, try OpenSSH format (for password-protected keys)
                // Note: If it's encrypted OpenSSH format, we might not be able to get the public key
                // without the password. In that case, we'll store an empty public key
                // and list_keys will have to handle it (maybe show as "unknown" or fail gracefully)
                if let Ok(ssh_key) = crate::openssh::SshPrivateKey::from_openssh(key_data, None) {
                    ssh_key.public_key_bytes()
                } else {
                    Vec::new()
                }
            }
        };

        // Store encrypted key
        let encrypted_key = EncryptedKey {
            nonce,
            ciphertext,
            description,
            fingerprint: fingerprint.to_string(),
            key_type,
            has_cert,
            confirm: false,
            notification: false,
            lifetime_expires_at: None,
            is_external,
            created: chrono::Utc::now(),
            updated: None, // No update yet since this is creation
            public_key,
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
                // Use cached public key if available
                let public_key = if !key.public_key.is_empty() {
                    key.public_key.clone()
                } else {
                    // Fallback for legacy keys or keys where extraction failed
                    // We can't easily decrypt here without async/blocking issues or perf hit
                    // For now, return empty and let caller handle it or it will show as invalid
                    Vec::new()
                };

                keys.push(KeyInfo {
                    fingerprint: key.fingerprint.clone(),
                    description: key.description.clone(),
                    key_type: key.key_type.clone(),
                    has_cert: key.has_cert,
                    confirm: key.confirm,
                    notification: key.notification,
                    lifetime_expires_at: key.lifetime_expires_at,
                    is_external: key.is_external,
                    created: key.created,
                    updated: key.updated,
                    public_key,
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

        // Check lifetime first, before cleanup
        if let Some(expires_at) = encrypted_key.lifetime_expires_at
            && Instant::now() >= expires_at
        {
            tracing::info!(
                "Key access denied - expired: type={}, fingerprint={}",
                encrypted_key.key_type,
                &fingerprint[..12]
            );
            // Key has expired, we should remove it
            drop(inner);
            self.unload_key(fingerprint)?;
            return Err(Error::KeyExpired);
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

    /// Decrypt a key temporarily for signing with confirmation or notification prompt if needed
    pub fn with_key_confirmed<F, R>(
        &self,
        fingerprint: &str,
        f: F,
        confirm_fn: Option<ConfirmFn>,
    ) -> Result<R>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        let inner = self.inner.read().unwrap();

        let mem_key = inner.mem_key.as_ref().ok_or(Error::NeedMasterUnlock)?;

        let encrypted_key = inner.keys.get(fingerprint).ok_or(Error::NotFound)?;

        // Check lifetime first, before cleanup
        if let Some(expires_at) = encrypted_key.lifetime_expires_at
            && Instant::now() >= expires_at
        {
            tracing::info!(
                "Key access denied - expired: type={}, fingerprint={}",
                encrypted_key.key_type,
                &fingerprint[..12]
            );
            // Key has expired, we should remove it
            drop(inner);
            self.unload_key(fingerprint)?;
            return Err(Error::KeyExpired);
        }

        // Check constraints - confirm takes precedence over notification
        if encrypted_key.confirm {
            if let Some(confirm_fn) = confirm_fn {
                let description = &encrypted_key.description;
                let key_type = &encrypted_key.key_type;
                if !confirm_fn(fingerprint, description, key_type)? {
                    return Err(Error::ConfirmationDenied);
                }
            } else {
                // If confirm is required but no confirm function provided, deny
                return Err(Error::ConfirmationDenied);
            }
        } else if encrypted_key.notification {
            // Only show notification if confirm is not enabled (confirm takes precedence)
            if let Some(confirm_fn) = confirm_fn {
                let description = &encrypted_key.description;
                let key_type = &encrypted_key.key_type;
                // For notification, we call the function but don't check the return value
                // This allows the function to show a notification without requiring approval
                let _ = confirm_fn(fingerprint, description, key_type);
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

    /// Decrypt a key temporarily for signing with separate confirmation and notification callbacks
    pub fn with_key_confirmed_notify<F, R>(
        &self,
        fingerprint: &str,
        f: F,
        confirm_fn: Option<ConfirmFn>,
        notify_fn: Option<NotifyFn>,
    ) -> Result<R>
    where
        F: FnOnce(&[u8]) -> Result<R>,
    {
        let inner = self.inner.read().unwrap();

        let mem_key = inner.mem_key.as_ref().ok_or(Error::NeedMasterUnlock)?;

        let encrypted_key = inner.keys.get(fingerprint).ok_or(Error::NotFound)?;

        // Check lifetime first, before cleanup
        if let Some(expires_at) = encrypted_key.lifetime_expires_at
            && Instant::now() >= expires_at
        {
            tracing::info!(
                "Key access denied - expired: type={}, fingerprint={}",
                encrypted_key.key_type,
                &fingerprint[..12]
            );
            // Key has expired, we should remove it
            drop(inner);
            self.unload_key(fingerprint)?;
            return Err(Error::KeyExpired);
        }

        // Check constraints - confirm takes precedence over notification
        if encrypted_key.confirm {
            if let Some(confirm_fn) = confirm_fn {
                let description = &encrypted_key.description;
                let key_type = &encrypted_key.key_type;
                if !confirm_fn(fingerprint, description, key_type)? {
                    return Err(Error::ConfirmationDenied);
                }
            } else {
                // If confirm is required but no confirm function provided, deny
                return Err(Error::ConfirmationDenied);
            }
        } else if encrypted_key.notification {
            // Only show notification if confirm is not enabled (confirm takes precedence)
            if let Some(notify_fn) = notify_fn {
                let description = &encrypted_key.description;
                let key_type = &encrypted_key.key_type;
                // For notification, use the notification callback which doesn't require approval
                let _ = notify_fn(fingerprint, description, key_type);
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
        notification: bool,
        lifetime_secs: Option<u64>,
    ) -> Result<()> {
        let mut inner = self.inner.write().unwrap();

        if inner.mem_key.is_none() {
            return Err(Error::NeedMasterUnlock);
        }

        let key = inner.keys.get_mut(fingerprint).ok_or(Error::NotFound)?;

        key.confirm = confirm;
        key.notification = notification;
        key.lifetime_expires_at =
            lifetime_secs.map(|secs| Instant::now() + Duration::from_secs(secs));
        key.updated = Some(chrono::Utc::now()); // Mark as updated

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
        key.updated = Some(chrono::Utc::now()); // Mark as updated

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

    /// Shutdown the RAM store and cleanup tasks
    pub fn shutdown(&self) {
        // Stop the cleanup task
        self.stop_cleanup_task();

        // Lock the store to zeroize sensitive data
        if let Err(e) = self.lock() {
            tracing::warn!("Failed to lock RAM store during shutdown: {}", e);
        }

        tracing::debug!("RAM store shutdown completed");
    }
}

/// Information about a loaded key
#[derive(Clone, Debug)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub description: String,
    pub key_type: String,
    pub has_cert: bool,
    pub confirm: bool,
    pub notification: bool,
    pub lifetime_expires_at: Option<Instant>, // Keep as Instant for lifetime expiration logic
    pub is_external: bool,
    pub created: chrono::DateTime<chrono::Utc>, // Use DateTime for serialization compatibility
    pub updated: Option<chrono::DateTime<chrono::Utc>>, // None for keys that haven't been updated since creation
    pub public_key: Vec<u8>,
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

    fn create_test_config(password: &str) -> crate::config::Config {
        // Use a simpler approach with a static path for testing
        use std::path::PathBuf;
        let temp_dir = PathBuf::from("/tmp");
        crate::config::Config::new_with_sentinel(&temp_dir, password).unwrap()
    }

    #[test]
    fn test_lock_unlock() {
        let store = RamStore::new();
        assert!(store.is_locked());

        let config = create_test_config("test_password");
        store.unlock("test_password", &config).unwrap();
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
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

        store
            .load_key("fp", b"data", "desc".into(), "ed25519".into(), false)
            .unwrap();
        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_max_keys_limit() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

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
    fn test_confirm_constraint() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

        // Load a key
        store
            .load_key("fp1", b"data", "test key".into(), "ed25519".into(), false)
            .unwrap();

        // Set confirm constraint
        store.set_constraints("fp1", true, false, None).unwrap();

        // Test with confirmation function that approves
        let approve_fn =
            Box::new(|_fp: &str, _desc: &str, _key_type: &str| -> Result<bool> { Ok(true) });

        let result = store.with_key_confirmed(
            "fp1",
            |_key_data| Ok("signed".to_string()),
            Some(approve_fn),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "signed");

        // Test with confirmation function that denies
        let deny_fn =
            Box::new(|_fp: &str, _desc: &str, _key_type: &str| -> Result<bool> { Ok(false) });

        let result =
            store.with_key_confirmed("fp1", |_key_data| Ok("signed".to_string()), Some(deny_fn));
        assert!(matches!(result, Err(Error::ConfirmationDenied)));

        // Test without confirmation function when confirm is required
        let result = store.with_key_confirmed("fp1", |_key_data| Ok("signed".to_string()), None);
        assert!(matches!(result, Err(Error::ConfirmationDenied)));

        // Test key without confirm constraint - should work even without confirmation function
        store
            .load_key("fp2", b"data", "test key 2".into(), "ed25519".into(), false)
            .unwrap();

        let result = store.with_key_confirmed("fp2", |_key_data| Ok("signed".to_string()), None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "signed");
    }

    #[test]
    fn test_duplicate_rejection() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

        store
            .load_key("fp1", b"data", "desc".into(), "ed25519".into(), false)
            .unwrap();

        let result = store.load_key("fp1", b"other", "desc2".into(), "ed25519".into(), false);
        assert!(matches!(result, Err(Error::AlreadyLoaded)));
    }

    #[test]
    fn test_with_key() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

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

    #[test]
    fn test_lifetime_expiry() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

        // Load a key
        store
            .load_key("fp1", b"data", "test key".into(), "ed25519".into(), false)
            .unwrap();

        // Set a very short lifetime (1 second)
        store.set_constraints("fp1", false, false, Some(1)).unwrap();

        // Key should be accessible initially
        let result = store.with_key("fp1", |_| Ok("success".to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");

        // Wait for expiry
        std::thread::sleep(Duration::from_secs(2));

        // Key should now be expired and return KeyExpired error
        let result = store.with_key("fp1", |_| Ok("should not work".to_string()));
        assert!(matches!(result, Err(Error::KeyExpired)));

        // Key should be automatically removed
        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_manual_cleanup_expired_keys() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

        // Load multiple keys
        store
            .load_key("fp1", b"data1", "key1".into(), "ed25519".into(), false)
            .unwrap();
        store
            .load_key("fp2", b"data2", "key2".into(), "ed25519".into(), false)
            .unwrap();
        store
            .load_key("fp3", b"data3", "key3".into(), "ed25519".into(), false)
            .unwrap();

        // Set lifetimes - some expired, some not
        store.set_constraints("fp1", false, false, Some(1)).unwrap(); // Will expire
        store.set_constraints("fp2", false, false, None).unwrap(); // No expiry
        store.set_constraints("fp3", false, false, Some(1)).unwrap(); // Will expire

        // Wait for expiry
        std::thread::sleep(Duration::from_secs(2));

        // Check initial count
        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 3); // All keys still present

        // Manual cleanup should remove expired keys
        let cleaned_count = store.cleanup_expired_keys().unwrap();
        assert_eq!(cleaned_count, 2); // Should remove fp1 and fp3

        // Check remaining keys
        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 1); // Only fp2 should remain
        assert_eq!(keys[0].fingerprint, "fp2");
    }

    #[test]
    fn test_clock_skew_handling() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

        // Load a key with very long lifetime (10 hours)
        store
            .load_key("fp1", b"data", "test key".into(), "ed25519".into(), false)
            .unwrap();
        store
            .set_constraints("fp1", false, false, Some(36000))
            .unwrap(); // 10 hours

        // Verify key is accessible
        let result = store.with_key("fp1", |_| Ok("initial".to_string()));
        assert!(result.is_ok());

        // Simulate clock skew by manipulating the internal state
        // This test verifies that the cleanup system can detect and handle time changes
        {
            let mut inner = store.inner.write().unwrap();
            // Simulate system time going backwards by a large amount but less than expiry time
            inner.last_system_time = std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(7200)) // 2 hours ago (less than 10 hour expiry)
                .unwrap();
        }

        // Trigger cleanup - should detect clock skew and adjust expiry times
        let cleaned_count = store.cleanup_expired_keys().unwrap();
        // Should not clean up keys due to clock skew protection extending expiry times
        assert_eq!(cleaned_count, 0);

        // Key should still be accessible after clock skew handling
        let result = store.with_key("fp1", |_| Ok("post_skew".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_cleanup_task_lifecycle() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = RamStore::new();
            let config = create_test_config("password");
            store.unlock("password", &config).unwrap();

            // Cleanup task should be started after unlock
            {
                let cleanup_task = store.cleanup_task.read().unwrap();
                assert!(cleanup_task.is_running());
            }

            // Stop the cleanup task
            store.stop_cleanup_task();

            // Task should be stopped
            {
                let cleanup_task = store.cleanup_task.read().unwrap();
                assert!(!cleanup_task.is_running());
            }

            // Shutdown should also stop the task
            store.start_cleanup_task();
            store.shutdown();

            {
                let cleanup_task = store.cleanup_task.read().unwrap();
                assert!(!cleanup_task.is_running());
            }
        });
    }

    #[test]
    fn test_expired_key_zeroization() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

        // Load a key with secret data
        let secret_data = b"very_secret_key_material_123456";
        store
            .load_key(
                "fp1",
                secret_data,
                "secret key".into(),
                "ed25519".into(),
                false,
            )
            .unwrap();

        // Set very short lifetime
        store.set_constraints("fp1", false, false, Some(1)).unwrap();

        // Wait for expiry
        std::thread::sleep(Duration::from_secs(2));

        // Trigger cleanup - this should zeroize the key data
        let cleaned_count = store.cleanup_expired_keys().unwrap();
        assert_eq!(cleaned_count, 1);

        // Verify key is gone
        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 0);

        // Note: We can't directly verify memory was zeroized without unsafe code,
        // but the test ensures the cleanup process completes and removes the key
    }

    #[test]
    fn test_confirmed_key_expiry() {
        let store = RamStore::new();
        let config = create_test_config("password");
        store.unlock("password", &config).unwrap();

        // Load a key
        store
            .load_key("fp1", b"data", "test key".into(), "ed25519".into(), false)
            .unwrap();

        // Set confirm constraint and short lifetime
        store.set_constraints("fp1", true, false, Some(1)).unwrap();

        // Create confirmation function
        let confirm_fn = Box::new(|_fp: &str, _desc: &str, _key_type: &str| -> Result<bool> {
            Ok(true) // Always approve
        });

        // Key should be accessible with confirmation initially
        let result =
            store.with_key_confirmed("fp1", |_| Ok("confirmed".to_string()), Some(confirm_fn));
        assert!(result.is_ok());

        // Wait for expiry
        std::thread::sleep(Duration::from_secs(2));

        // Create new confirmation function for expired key test
        let confirm_fn2 = Box::new(|_fp: &str, _desc: &str, _key_type: &str| -> Result<bool> {
            Ok(true) // Should not be called due to expiry
        });

        // Key should now be expired and return KeyExpired error (not ConfirmationDenied)
        let result = store.with_key_confirmed(
            "fp1",
            |_| Ok("should not work".to_string()),
            Some(confirm_fn2),
        );
        assert!(matches!(result, Err(Error::KeyExpired)));
    }

    #[test]
    fn test_lock_unlock_aead_fix() {
        // This test verifies the fix for the lock/unlock AEAD bug.
        // Problem: lock would zeroize MemKey but leave encrypted keys in RAM,
        // then unlock would create a new MemKey with different salt, causing AEAD
        // decryption failures when trying to access the old encrypted keys.
        // Solution: Use persistent salt across lock/unlock cycles so MemKey remains consistent.

        let store = RamStore::new();
        let config = create_test_config("test_password");

        // Initial unlock
        store.unlock("test_password", &config).unwrap();
        assert!(!store.is_locked());

        // Load a test key
        let test_key_data = b"test_key_data_for_aead_bug_test";
        store
            .load_external_key(
                "test_fp",
                test_key_data,
                "Test key".to_string(),
                "ed25519".to_string(),
                false,
            )
            .unwrap();

        // Verify key is accessible
        let result = store.with_key("test_fp", |data| {
            assert_eq!(data, test_key_data);
            Ok(())
        });
        assert!(result.is_ok(), "Key should be accessible after load");

        // Lock the store (does NOT clear keys - only zeroizes MemKey)
        store.lock().unwrap();
        assert!(store.is_locked());

        // Unlock again (should reuse persistent salt for MemKey consistency)
        store.unlock("test_password", &config).unwrap();
        assert!(!store.is_locked());

        // With the fix: Keys should remain accessible after unlock because
        // persistent salt ensures MemKey consistency across lock/unlock cycles
        let result = store.with_key("test_fp", |data| {
            assert_eq!(data, test_key_data);
            Ok(())
        });
        assert!(
            result.is_ok(),
            "Key should remain accessible after lock/unlock cycle"
        );

        // Test multiple lock/unlock cycles to ensure robustness
        for i in 1..=3 {
            store.lock().unwrap();
            assert!(store.is_locked());

            store.unlock("test_password", &config).unwrap();
            assert!(!store.is_locked());

            let result = store.with_key("test_fp", |data| {
                assert_eq!(data, test_key_data);
                Ok(format!("cycle_{}", i))
            });
            assert!(
                result.is_ok(),
                "Key should remain accessible after cycle {}",
                i
            );
            assert_eq!(result.unwrap(), format!("cycle_{}", i));
        }

        // Verify we can still load and access new keys after multiple cycles
        store
            .load_external_key(
                "new_fp",
                b"new_key_data_after_unlock",
                "New key".to_string(),
                "ed25519".to_string(),
                false,
            )
            .unwrap();

        let result = store.with_key("new_fp", |data| {
            assert_eq!(data, b"new_key_data_after_unlock");
            Ok(())
        });
        assert!(result.is_ok(), "New key should be accessible after unlock");
    }
}

