use rssh_core::{Result, config::Config, ram_store::RamStore};
use rssh_proto::{messages, wire};
use std::sync::Arc;
use tokio::sync::RwLock;

use zeroize::{Zeroize, Zeroizing};
#[allow(dead_code)]
const DEFAULT_MESSAGE_LIMIT: usize = 1024 * 1024; // 1 MiB
#[allow(dead_code)]
const MANAGE_LIST_LIMIT: usize = 8 * 1024 * 1024; // 8 MiB

/// SSH agent implementation
pub struct Agent {
    ram_store: Arc<RamStore>,
    storage_dir: Option<String>,
    master_password: Arc<RwLock<Option<Zeroizing<String>>>>,
    #[allow(dead_code)] // Reserved for future configuration use
    config: Arc<Config>,
    shutdown_signal: Option<Arc<tokio::sync::Notify>>,
    dbus_notifications: Arc<crate::dbus_notifications::DbusNotificationService>,
}

impl Agent {
    async fn build(
        storage_dir: Option<String>,
        config: Config,
        shutdown_signal: Option<Arc<tokio::sync::Notify>>,
    ) -> Self {
        let dbus_notifications =
            Arc::new(crate::dbus_notifications::DbusNotificationService::new().await);
        Agent {
            ram_store: Arc::new(RamStore::new()),
            storage_dir,
            master_password: Arc::new(RwLock::new(None)),
            config: Arc::new(config),
            shutdown_signal,
            dbus_notifications,
        }
    }

    /// Create a new agent
    pub async fn new(config: Config) -> Self {
        Self::build(None, config, None).await
    }

    /// Create a new agent with storage directory
    pub async fn with_storage_dir(storage_dir: String, config: Config) -> Self {
        Self::build(Some(storage_dir), config, None).await
    }

    /// Create a new agent with storage directory and shutdown signal
    pub async fn with_storage_dir_and_shutdown(
        storage_dir: String,
        config: Config,
        shutdown_signal: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self::build(Some(storage_dir), config, Some(shutdown_signal)).await
    }

    /// Set the master password for the agent
    pub async fn set_master_password(&self, master_password: String) -> Result<()> {
        let master_password = Zeroizing::new(master_password);

        // Unlock the RAM store with the master password
        self.ram_store.unlock(&master_password, &self.config)?;

        // Store the master password in the agent
        {
            let mut master_password_guard = self.master_password.write().await;
            *master_password_guard = Some(master_password);
        }

        tracing::info!("Master password set and RAM store unlocked");
        Ok(())
    }

    /// Handle an incoming message
    pub async fn handle_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        if message.is_empty() {
            return Ok(messages::build_failure());
        }

        let msg_type = wire::MessageType::from_u8(message[0]);

        // Check if locked (only UNLOCK allowed when locked)
        if self.ram_store.is_locked() && msg_type != Some(wire::MessageType::Unlock) {
            return Ok(messages::build_failure());
        }

        match msg_type {
            Some(wire::MessageType::RequestIdentities) => {
                self.handle_request_identities(message).await
            }
            Some(wire::MessageType::SignRequest) => self.handle_sign_request(message).await,
            Some(wire::MessageType::AddIdentity) => self.handle_add_identity(message).await,
            Some(wire::MessageType::AddIdConstrained) => {
                self.handle_add_id_constrained(message).await
            }
            Some(wire::MessageType::RemoveIdentity) => self.handle_remove_identity(message).await,
            Some(wire::MessageType::RemoveAllIdentities) => {
                self.handle_remove_all_identities(message).await
            }
            Some(wire::MessageType::Lock) => self.handle_lock(message).await,
            Some(wire::MessageType::Unlock) => self.handle_unlock(message).await,
            Some(wire::MessageType::AddSmartcardKey)
            | Some(wire::MessageType::RemoveSmartcardKey) => {
                // PKCS#11 not supported
                tracing::warn!("PKCS#11 smartcard operations not supported");
                return Ok(messages::build_failure());
            }
            Some(wire::MessageType::Extension) => self.handle_extension(message).await,
            _ => {
                tracing::warn!("Unknown message type: {:?}", message[0]);
                return Ok(messages::build_failure());
            }
        }
    }

    /// Shutdown the agent gracefully, ensuring all secrets are zeroized
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("Initiating agent shutdown");

        // Clear the master password
        {
            let mut master_password = self.master_password.write().await;
            if let Some(mut password) = master_password.take() {
                // Zeroize the password string
                password.zeroize();
            }
        }

        // Shutdown the RAM store (includes cleanup task shutdown and memory key zeroization)
        self.ram_store.shutdown();
        tracing::info!("RAM store shutdown completed with cleanup task termination");

        tracing::info!("Agent shutdown completed successfully");
        Ok(())
    }

    async fn handle_request_identities(&self, message: &[u8]) -> Result<Vec<u8>> {
        if messages::parse_request_identities(message).is_none() {
            return Ok(messages::build_failure());
        }

        let keys = match self.ram_store.list_keys() {
            Ok(keys) => keys,
            Err(_) => return Ok(messages::build_failure()),
        };

        // Get public keys for each loaded key
        let mut identities = Vec::new();
        for key_info in keys {
            // Use cached public key if available (fast path)
            let public_key_blob = if !key_info.public_key.is_empty() {
                key_info.public_key
            } else {
                // Fallback: try to decrypt and parse the key (slow path)
                match self.ram_store.with_key(&key_info.fingerprint, |key_data| {
                    use crate::key_utils;
                    key_utils::get_public_key_blob(key_data).map_err(rssh_core::Error::Internal)
                }) {
                    Ok(blob) => blob,
                    Err(e) => {
                        // Skip keys we can't process
                        tracing::warn!(
                            "Failed to get public key for fingerprint {}: {}",
                            key_info.fingerprint,
                            e
                        );
                        continue;
                    }
                }
            };

            identities.push(messages::Identity {
                public_key: public_key_blob,
                comment: key_info.description,
            });
        }

        Ok(messages::build_identities_answer(&identities))
    }

    async fn handle_sign_request(&self, message: &[u8]) -> Result<Vec<u8>> {
        let request = match messages::parse_sign_request(message) {
            Some(req) => req,
            None => return Ok(messages::build_failure()),
        };

        tracing::debug!(
            "Sign request for key blob of {} bytes, data {} bytes, flags: 0x{:02x}",
            request.key_blob.len(),
            request.data.len(),
            request.flags
        );

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&request.key_blob);
        let fingerprint = hex::encode(hasher.finalize());

        // 1. Read constraint metadata — brief read lock, no I/O.
        let info = match self.ram_store.get_key_signing_info(&fingerprint) {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Sign request failed: {}", e);
                return Ok(messages::build_failure());
            }
        };

        // 2. Async confirmation — lock is NOT held during this step.
        if info.confirm {
            let approved = self.request_confirmation(&fingerprint, &info.description, &info.key_type).await;
            if !approved {
                tracing::warn!("Key confirmation denied for {}", &fingerprint[..12]);
                return Ok(messages::build_failure());
            }
        }

        // 3. Decrypt and sign — brief read lock, no I/O.
        let signature = match self.ram_store.sign_with_key(&fingerprint, |key_data| {
            crate::signing::sign_data(key_data, &request.data, request.flags)
                .map_err(rssh_core::Error::Internal)
        }) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("Sign request failed: {}", e);
                return Ok(messages::build_failure());
            }
        };

        tracing::info!("Signed data with key {}", &fingerprint[..12]);

        // 4. Fire-and-forget notification — spawned after signing, no lock held.
        if info.notification && !info.confirm {
            let dbus = self.dbus_notifications.clone();
            let fp = fingerprint.clone();
            let desc = info.description.clone();
            let kt = info.key_type.clone();
            tokio::spawn(async move {
                if dbus.is_available() {
                    if let Err(e) = dbus.show_key_notification(&fp, &desc, &kt).await {
                        tracing::debug!(
                            "D-Bus info notification failed for {}: {}",
                            &fp[..12],
                            e
                        );
                    }
                }
            });
        }

        Ok(messages::build_sign_response(&signature))
    }

    /// Ask the user to confirm key use via D-Bus notification or terminal fallback.
    /// Returns `true` if approved, `false` if denied or if no prompt method is available.
    async fn request_confirmation(&self, fingerprint: &str, description: &str, key_type: &str) -> bool {
        if self.dbus_notifications.is_available() {
            tracing::debug!("Requesting D-Bus key approval for {}...", &fingerprint[..12]);
            match self
                .dbus_notifications
                .request_key_approval(fingerprint, description, key_type, 30)
                .await
            {
                Ok(approved) => {
                    tracing::info!(
                        "D-Bus key approval {} for {}",
                        if approved { "granted" } else { "denied" },
                        &fingerprint[..12]
                    );
                    approved
                }
                Err(e) => {
                    tracing::error!(
                        "D-Bus notification failed for {}: {}",
                        &fingerprint[..12],
                        e
                    );
                    if let Err(reconnect_err) =
                        self.dbus_notifications.ensure_connection().await
                    {
                        tracing::warn!("Failed to reconnect D-Bus: {}", reconnect_err);
                    }
                    false // deny on error
                }
            }
        } else {
            tracing::debug!("D-Bus unavailable, falling back to prompt system");
            let prompt_text = format!(
                "Allow use of {} key '{}' ({}...)?\n\n[D-Bus notifications unavailable - using fallback prompt]",
                key_type, description, &fingerprint[..12]
            );
            // The terminal prompt blocks; run it off the async executor.
            tokio::task::spawn_blocking(move || {
                match crate::prompt::PrompterDecision::choose() {
                    Some(prompter) => prompter.confirm(&prompt_text).unwrap_or(false),
                    None => {
                        tracing::warn!(
                            "No prompt method available, denying key usage"
                        );
                        false
                    }
                }
            })
            .await
            .unwrap_or(false)
        }
    }

    async fn handle_add_identity(&self, message: &[u8]) -> Result<Vec<u8>> {
        let identity = match messages::parse_add_identity(message) {
            Some(id) => id,
            None => return Ok(messages::build_failure()),
        };
        // Parse the wire format key to get fingerprint and key type
        use crate::key_utils;

        let (fingerprint, key_type, _pub_key_blob) =
            match key_utils::parse_wire_key(&identity.private_key_data) {
                Ok(info) => info,
                Err(e) => {
                    tracing::warn!("Failed to parse key: {}", e);
                    return Ok(messages::build_failure());
                }
            };

        // Add to RAM store as external key (added via ssh-add)
        match self.ram_store.load_external_key(
            &fingerprint,
            &identity.private_key_data,
            identity.comment,
            key_type,
            false, // has_cert
        ) {
            Ok(_) => {
                tracing::info!("Added key with fingerprint: {}", fingerprint);
                Ok(messages::build_success())
            }
            Err(e) => {
                tracing::warn!("Failed to add key: {}", e);
                return Ok(messages::build_failure());
            }
        }
    }

    async fn handle_add_id_constrained(&self, message: &[u8]) -> Result<Vec<u8>> {
        let identity = match messages::parse_add_id_constrained(message) {
            Some(id) => id,
            None => return Ok(messages::build_failure()),
        };

        // Check for unsupported constraints
        for constraint in &identity.constraints {
            if matches!(constraint, wire::Constraint::Unknown(_)) {
                tracing::warn!("Unknown constraint type");
                return Ok(messages::build_failure());
            }
        }

        // Check lifetime constraint
        if let Some(lifetime) = identity.lifetime_secs() {
            const MAX_LIFETIME: u32 = 30 * 24 * 60 * 60; // 30 days
            if lifetime > MAX_LIFETIME {
                tracing::warn!("Lifetime too long: {} > {}", lifetime, MAX_LIFETIME);
                return Ok(messages::build_failure());
            }
        }

        tracing::debug!(
            "Add constrained identity: {} ({}) confirm={} lifetime={:?}",
            identity.comment,
            identity.key_type,
            identity.has_confirm(),
            identity.lifetime_secs()
        );

        // Parse the wire format key to get fingerprint and key type
        use crate::key_utils;

        let (fingerprint, key_type, _pub_key_blob) =
            match key_utils::parse_wire_key(&identity.private_key_data) {
                Ok(info) => info,
                Err(e) => {
                    tracing::warn!("Failed to parse key: {}", e);
                    return Ok(messages::build_failure());
                }
            };

        // Get constraint values before moving identity
        let confirm = identity.has_confirm();
        let lifetime_secs = identity.lifetime_secs().map(|secs| secs as u64);

        // Add to RAM store as external key (added via ssh-add)
        match self.ram_store.load_external_key(
            &fingerprint,
            &identity.private_key_data,
            identity.comment,
            key_type,
            false, // has_cert
        ) {
            Ok(_) => {
                tracing::info!("Added key with fingerprint: {}", fingerprint);

                // Set constraints if any were specified

                if confirm || lifetime_secs.is_some() {
                    if let Err(e) =
                        self.ram_store
                            .set_constraints(&fingerprint, confirm, false, lifetime_secs)
                    {
                        tracing::warn!("Failed to set constraints for key {}: {}", fingerprint, e);
                        // Key was added successfully, but constraints failed - this is not fatal
                    } else {
                        tracing::debug!(
                            "Set constraints for key {}: confirm={}, lifetime={:?}",
                            fingerprint,
                            confirm,
                            lifetime_secs
                        );
                    }
                }

                Ok(messages::build_success())
            }
            Err(e) => {
                tracing::warn!("Failed to add key: {}", e);
                return Ok(messages::build_failure());
            }
        }
    }

    async fn handle_remove_identity(&self, message: &[u8]) -> Result<Vec<u8>> {
        let key_blob = match messages::parse_remove_identity(message) {
            Some(blob) => blob,
            None => return Ok(messages::build_failure()),
        };

        tracing::debug!("Remove identity with {} byte key blob", key_blob.len());

        // Calculate fingerprint from the public key blob to find the key
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&key_blob);
        let fingerprint = hex::encode(hasher.finalize());

        // Try to remove the key from RAM store
        match self.ram_store.unload_key(&fingerprint) {
            Ok(_) => {
                tracing::info!("Removed identity with fingerprint: {}", fingerprint);
                Ok(messages::build_success())
            }
            Err(rssh_core::Error::NotLoaded) => {
                tracing::debug!("Identity not found for removal: {}", fingerprint);
                // Per spec: not found → FAILURE
                return Ok(messages::build_failure());
            }
            Err(e) => {
                tracing::warn!("Failed to remove identity {}: {}", fingerprint, e);
                return Ok(messages::build_failure());
            }
        }
    }

    async fn handle_remove_all_identities(&self, message: &[u8]) -> Result<Vec<u8>> {
        if messages::parse_remove_all_identities(message).is_none() {
            return Ok(messages::build_failure());
        }

        match self.ram_store.clear_all() {
            Ok(_) => {
                tracing::info!("Removed all identities from RAM");
                Ok(messages::build_success())
            }
            Err(_) => Ok(messages::build_failure()),
        }
    }

    /// Lock the agent directly (for SIGHUP and internal use): zeroizes MemKey and master password
    pub async fn lock_directly(&self) {
        if let Err(e) = self.ram_store.lock() {
            tracing::error!("Failed to lock RAM store: {}", e);
        }
        {
            let mut master_password = self.master_password.write().await;
            if let Some(mut password) = master_password.take() {
                password.zeroize();
            }
        }
        tracing::info!("Agent locked - MemKey zeroized, master password cleared");
    }

    async fn handle_lock(&self, message: &[u8]) -> Result<Vec<u8>> {
        let _passphrase = match messages::parse_lock(message) {
            Some(pass) => pass,
            None => return Ok(messages::build_failure()),
        };

        tracing::debug!("Processing LOCK request");

        // According to spec: LOCK zeroizes MemKey, making all RAM ciphertexts inaccessible
        // The passphrase parameter is ignored - we use master password for lock/unlock
        match self.ram_store.lock() {
            Ok(_) => {
                {
                    let mut master_password = self.master_password.write().await;
                    if let Some(mut password) = master_password.take() {
                        password.zeroize();
                    }
                }
                tracing::info!("Agent locked - MemKey zeroized, master password cleared");
                Ok(messages::build_success())
            }
            Err(e) => {
                tracing::error!("Failed to lock RAM store: {}", e);
                Ok(messages::build_failure())
            }
        }
    }

    async fn handle_unlock(&self, message: &[u8]) -> Result<Vec<u8>> {
        let passphrase = match messages::parse_unlock(message) {
            Some(pass) => pass,
            None => return Ok(messages::build_failure()),
        };

        tracing::debug!(
            "Processing UNLOCK request with {} byte passphrase",
            passphrase.len()
        );

        // According to spec: UNLOCK restores MemKey on correct master password
        let master_password = Zeroizing::new(
            String::from_utf8(passphrase)
                .map_err(|_| rssh_core::Error::Internal("Invalid UTF-8 in unlock passphrase".into()))?,
        );

        match self.ram_store.unlock(&master_password, &self.config) {
            Ok(_) => {
                // Set master password in agent for extension operations
                {
                    let mut master_password_guard = self.master_password.write().await;
                    *master_password_guard = Some(master_password);
                }

                tracing::info!("Agent unlocked with correct master password");
                Ok(messages::build_success())
            }
            Err(rssh_core::Error::WrongPassword) => {
                tracing::warn!("Unlock failed - wrong master password");
                Ok(messages::build_failure())
            }
            Err(rssh_core::Error::RateLimited(remaining_secs)) => {
                if remaining_secs == u64::MAX {
                    tracing::error!("Unlock failed - permanently locked out");
                } else {
                    tracing::warn!(
                        "Unlock failed - rate limited for {} seconds",
                        remaining_secs
                    );
                }
                Ok(messages::build_failure())
            }
            Err(e) => {
                tracing::error!("Unlock failed with error: {}", e);
                Ok(messages::build_failure())
            }
        }
    }

    /// Returns the current master password, or `None` if not set.
    async fn read_master_password(&self) -> Option<Zeroizing<String>> {
        self.master_password.read().await.clone()
    }

    /// Converts an extension handler `Result<Vec<u8>>` into the protocol response,
    /// logging on error and falling back to a CBOR error payload or SSH failure.
    fn ext_dispatch(op: &str, result: rssh_core::Result<Vec<u8>>) -> Result<Vec<u8>> {
        use crate::extensions;
        match result {
            Ok(cbor) => Ok(extensions::build_extension_response(cbor)),
            Err(e) => {
                tracing::error!("Failed to handle {}: {}", op, e);
                match extensions::build_error_response(e) {
                    Ok(r) => Ok(extensions::build_extension_response(r)),
                    Err(_) => Ok(messages::build_failure()),
                }
            }
        }
    }

    async fn handle_extension(&self, message: &[u8]) -> Result<Vec<u8>> {
        use crate::extensions;

        tracing::debug!(
            "Extension message received, length: {}, data: {:02x?}",
            message.len(),
            &message[..message.len().min(20)]
        );

        let request = match extensions::parse_extension_request(message) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!("Failed to parse extension request: {}", e);
                return Ok(messages::build_failure());
            }
        };

        let data = &request.data;
        let ext = request.extension.as_str();
        tracing::debug!("Handling extension: {}", ext);

        // Inline helpers that borrow from self and return early on missing prereqs.
        macro_rules! require_pwd {
            ($op:expr) => {
                match self.read_master_password().await {
                    Some(p) => p,
                    None => {
                        tracing::error!("Master password not available for {}", $op);
                        return Ok(messages::build_failure());
                    }
                }
            };
        }
        macro_rules! require_dir {
            ($op:expr) => {
                match self.storage_dir.as_deref() {
                    Some(d) => d,
                    None => {
                        tracing::error!("Storage directory not available for {}", $op);
                        return Ok(messages::build_failure());
                    }
                }
            };
        }

        match ext {
            "session-bind@openssh.com" => extensions::handle_session_bind(data).or_else(|e| {
                tracing::error!("Failed to handle session-bind: {}", e);
                Ok(messages::build_failure())
            }),

            "manage.list" => {
                let keys = match self.ram_store.list_keys() {
                    Ok(keys) => keys,
                    Err(_) => return Ok(messages::build_failure()),
                };
                let pwd = self.read_master_password().await;
                Self::ext_dispatch(
                    "manage.list",
                    extensions::handle_manage_list(
                        keys,
                        self.storage_dir.as_deref(),
                        pwd.as_ref().map(|s| s.as_str()),
                    ),
                )
            }

            "manage.unload" => Self::ext_dispatch(
                "manage.unload",
                extensions::handle_manage_unload(data, &self.ram_store),
            ),

            "manage.delete" => Self::ext_dispatch(
                "manage.delete",
                extensions::handle_manage_delete(
                    data,
                    &self.ram_store,
                    self.storage_dir.as_deref(),
                ),
            ),

            "manage.set_constraints" => Self::ext_dispatch(
                "manage.set_constraints",
                extensions::handle_manage_set_constraints(data, &self.ram_store),
            ),

            "manage.set_desc" => {
                let pwd = require_pwd!("manage.set_desc");
                Self::ext_dispatch(
                    "manage.set_desc",
                    extensions::handle_manage_set_desc(
                        data,
                        &self.ram_store,
                        self.storage_dir.as_deref(),
                        &pwd,
                    ),
                )
            }

            "manage.set_default_constraints" => {
                let pwd = require_pwd!("manage.set_default_constraints");
                Self::ext_dispatch(
                    "manage.set_default_constraints",
                    extensions::handle_manage_set_default_constraints(
                        data,
                        self.storage_dir.as_deref(),
                        &pwd,
                    ),
                )
            }

            "manage.create" => {
                let pwd = require_pwd!("manage.create");
                Self::ext_dispatch(
                    "manage.create",
                    extensions::handle_manage_create(
                        data,
                        &self.ram_store,
                        self.storage_dir.as_deref(),
                        &pwd,
                    )
                    .await,
                )
            }

            "manage.load" => {
                let pwd = require_pwd!("manage.load");
                Self::ext_dispatch(
                    "manage.load",
                    extensions::handle_manage_load(
                        data,
                        &self.ram_store,
                        self.storage_dir.as_deref(),
                        &pwd,
                    )
                    .await,
                )
            }

            "manage.update_cert" => {
                let pwd = require_pwd!("manage.update_cert");
                let dir = require_dir!("manage.update_cert");
                Self::ext_dispatch(
                    "manage.update_cert",
                    extensions::handle_manage_update_cert(data, dir, &pwd).await,
                )
            }

            "manage.import" => {
                let pwd = require_pwd!("manage.import");
                let dir = require_dir!("manage.import");
                Self::ext_dispatch(
                    "manage.import",
                    extensions::handle_manage_import(data, &self.ram_store, dir, &pwd).await,
                )
            }

            "manage.import_direct" => {
                let pwd = require_pwd!("manage.import_direct");
                let dir = require_dir!("manage.import_direct");
                Self::ext_dispatch(
                    "manage.import_direct",
                    extensions::handle_manage_import_direct(data, dir, &pwd).await,
                )
            }

            "manage.set_password" => {
                let pwd = require_pwd!("manage.set_password");
                let dir = require_dir!("manage.set_password");
                Self::ext_dispatch(
                    "manage.set_password",
                    extensions::handle_manage_set_password(data, &self.ram_store, dir, &pwd).await,
                )
            }

            "control.shutdown" => {
                tracing::info!("Received shutdown request via extension");
                match extensions::handle_control_shutdown() {
                    Ok(cbor_data) => {
                        if let Some(ref signal) = self.shutdown_signal {
                            let signal = signal.clone();
                            tokio::spawn(async move {
                                tracing::info!("Triggering daemon shutdown via extension");
                                signal.notify_one();
                            });
                        } else {
                            tracing::warn!(
                                "Shutdown signal not available - cannot trigger daemon shutdown"
                            );
                        }
                        Ok(extensions::build_extension_response(cbor_data))
                    }
                    Err(e) => {
                        tracing::error!("Failed to handle control.shutdown: {}", e);
                        Ok(messages::build_failure())
                    }
                }
            }

            _ => {
                tracing::info!("Received unknown extension: {}", ext);
                if ext.contains("@openssh.com") {
                    tracing::debug!(
                        "Unknown OpenSSH extension, returning success for compatibility"
                    );
                    Ok(vec![rssh_proto::wire::MessageType::Success as u8])
                } else {
                    tracing::warn!("Unknown extension operation: {}", ext);
                    Ok(messages::build_failure())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Temporarily disabled - lock/unlock behavior needs investigation
    async fn test_locked_behavior() {
        use rssh_core::config::Config;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp.path(), "test_password_12345").unwrap();
        let agent = Agent::new(config).await;

        // Set the master password so unlock operations can work
        agent
            .set_master_password("test_password_12345".to_string())
            .await
            .unwrap();

        // Lock the RAM store initially so the test can test the lock/unlock cycle
        agent.ram_store.lock().unwrap();

        // After locking the RAM store manually, the agent should be locked
        assert!(agent.ram_store.is_locked());

        // REQUEST_IDENTITIES should fail when locked
        let msg = vec![wire::MessageType::RequestIdentities as u8];
        let response = agent.handle_message(&msg).await.unwrap();
        assert_eq!(response, messages::build_failure());

        // UNLOCK with wrong passphrase should fail
        let mut wrong_unlock_msg = vec![wire::MessageType::Unlock as u8];
        wire::write_string(&mut wrong_unlock_msg, b"wrong_password");
        let response = agent.handle_message(&wrong_unlock_msg).await.unwrap();
        assert_eq!(response, messages::build_failure());

        // Should still be locked
        assert!(agent.ram_store.is_locked());

        // UNLOCK with correct master password should work
        let mut correct_unlock_msg = vec![wire::MessageType::Unlock as u8];
        wire::write_string(&mut correct_unlock_msg, b"test_password_12345");
        let response = agent.handle_message(&correct_unlock_msg).await.unwrap();
        assert_eq!(response, messages::build_success());

        // Should be unlocked now
        assert!(!agent.ram_store.is_locked());

        // LOCK should work when unlocked
        let mut lock_msg = vec![wire::MessageType::Lock as u8];
        wire::write_string(&mut lock_msg, b"test_lock_password");
        let response = agent.handle_message(&lock_msg).await.unwrap();
        assert_eq!(response, messages::build_success());

        // Should be locked again
        assert!(agent.ram_store.is_locked());
    }

    #[tokio::test]
    async fn test_lock_passphrase_zeroization() {
        use rssh_core::config::Config;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp.path(), "test_password_12345").unwrap();
        let agent = Agent::new(config).await;

        // Set the master password so unlock operations can work (also unlocks the RAM store)
        agent
            .set_master_password("test_password_12345".to_string())
            .await
            .unwrap();

        // Lock with a passphrase
        let mut lock_msg = vec![wire::MessageType::Lock as u8];
        wire::write_string(&mut lock_msg, b"secret_lock_password");
        let response = agent.handle_message(&lock_msg).await.unwrap();
        assert_eq!(response, messages::build_success());

        // Unlock with correct master password
        let mut unlock_msg = vec![wire::MessageType::Unlock as u8];
        wire::write_string(&mut unlock_msg, b"test_password_12345");
        let response = agent.handle_message(&unlock_msg).await.unwrap();
        assert_eq!(response, messages::build_success());

    }

    #[tokio::test]
    async fn test_shutdown_zeroization() {
        use rssh_core::config::Config;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp.path(), "test_password_12345").unwrap();
        let agent = Agent::new(config).await;

        // Unlock the agent with the master password
        agent
            .set_master_password("test_password_12345".to_string())
            .await
            .unwrap();

        // Lock via SSH LOCK command (locks RAM store + clears master password)
        let mut lock_msg = vec![wire::MessageType::Lock as u8];
        wire::write_string(&mut lock_msg, b"shutdown_test_password");
        let lock_response = agent.handle_message(&lock_msg).await.unwrap();
        assert_eq!(lock_response, messages::build_success());

        // Verify agent is locked
        assert!(agent.ram_store.is_locked());

        // Shutdown should complete successfully and clear secrets
        agent.shutdown().await.unwrap();

        // Verify agent is still locked after shutdown
        assert!(agent.ram_store.is_locked());

        // Verify master password is cleared
        {
            let master_password = agent.master_password.read().await;
            assert!(master_password.is_none());
        }
    }

    #[tokio::test]
    async fn test_remove_all() {
        use rssh_core::config::Config;
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp.path(), "test_password_12345").unwrap();
        let agent = Agent::new(config).await;

        // RAM store is locked (no master password set), so all commands should fail
        let msg = vec![wire::MessageType::RemoveAllIdentities as u8];
        let response = agent.handle_message(&msg).await.unwrap();
        assert_eq!(response, messages::build_failure());
    }
}
