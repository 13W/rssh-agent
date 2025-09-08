use rssh_core::{Result, ram_store::RamStore};
use rssh_proto::{messages, wire};
use std::sync::Arc;
use tokio::sync::RwLock;

#[allow(dead_code)]
const DEFAULT_MESSAGE_LIMIT: usize = 1024 * 1024; // 1 MiB
#[allow(dead_code)]
const MANAGE_LIST_LIMIT: usize = 8 * 1024 * 1024; // 8 MiB

/// SSH agent implementation
pub struct Agent {
    ram_store: Arc<RamStore>,
    locked: Arc<RwLock<bool>>,
    storage_dir: Option<String>,
    master_password: Arc<RwLock<Option<String>>>,
}

impl Agent {
    /// Create a new agent
    pub fn new() -> Self {
        Agent {
            ram_store: Arc::new(RamStore::new()),
            locked: Arc::new(RwLock::new(true)), // Start locked
            storage_dir: None,
            master_password: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a new agent with storage directory
    pub fn with_storage_dir(storage_dir: String) -> Self {
        Agent {
            ram_store: Arc::new(RamStore::new()),
            locked: Arc::new(RwLock::new(true)), // Start locked
            storage_dir: Some(storage_dir),
            master_password: Arc::new(RwLock::new(None)),
        }
    }

    /// Handle an incoming message
    pub async fn handle_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        if message.is_empty() {
            return Ok(messages::build_failure());
        }

        let msg_type = wire::MessageType::from_u8(message[0]);

        // Check if locked (only UNLOCK allowed when locked)
        if *self.locked.read().await {
            if msg_type != Some(wire::MessageType::Unlock) {
                return Ok(messages::build_failure());
            }
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
                Ok(messages::build_failure())
            }
            Some(wire::MessageType::Extension) => self.handle_extension(message).await,
            _ => {
                tracing::warn!("Unknown message type: {:?}", message[0]);
                Ok(messages::build_failure())
            }
        }
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
            // We need to get the actual public key data
            // For now, we'll need to decrypt and parse the key
            match self.ram_store.with_key(&key_info.fingerprint, |key_data| {
                use crate::key_utils;
                key_utils::get_public_key_blob(key_data).map_err(|e| rssh_core::Error::Internal(e))
            }) {
                Ok(public_key_blob) => {
                    identities.push(messages::Identity {
                        public_key: public_key_blob,
                        comment: key_info.description,
                    });
                }
                Err(e) => {
                    // Skip keys we can't process
                    tracing::warn!(
                        "Failed to get public key for fingerprint {}: {}",
                        key_info.fingerprint,
                        e
                    );
                }
            }
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

        // Calculate fingerprint from the key blob to find the key
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&request.key_blob);
        let fingerprint = hex::encode(hasher.finalize());

        // Find and sign with the key
        match self.ram_store.with_key(&fingerprint, |key_data| {
            use crate::signing;
            signing::sign_data(key_data, &request.data, request.flags)
                .map_err(|e| rssh_core::Error::Internal(e))
        }) {
            Ok(signature) => {
                tracing::info!("Signed data with key {}", fingerprint);
                Ok(messages::build_sign_response(&signature))
            }
            Err(e) => {
                tracing::warn!("Failed to sign with key {}: {}", fingerprint, e);
                Ok(messages::build_failure())
            }
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
                return Ok(messages::build_success());
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
                    if let Err(e) = self.ram_store.set_constraints(&fingerprint, confirm, lifetime_secs) {
                        tracing::warn!("Failed to set constraints for key {}: {}", fingerprint, e);
                        // Key was added successfully, but constraints failed - this is not fatal
                    } else {
                        tracing::debug!("Set constraints for key {}: confirm={}, lifetime={:?}", 
                                      fingerprint, confirm, lifetime_secs);
                    }
                }
                
                return Ok(messages::build_success());
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
                Ok(messages::build_failure())
            }
            Err(e) => {
                tracing::warn!("Failed to remove identity {}: {}", fingerprint, e);
                Ok(messages::build_failure())
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

    async fn handle_lock(&self, message: &[u8]) -> Result<Vec<u8>> {
        let _passphrase = match messages::parse_lock(message) {
            Some(pass) => pass,
            None => return Ok(messages::build_failure()),
        };

        // Note: OpenSSH ignores the lock passphrase

        match self.ram_store.lock() {
            Ok(_) => {
                // Clear the stored master password when locking
                {
                    let mut master_password = self.master_password.write().await;
                    *master_password = None;
                }
                
                let mut locked = self.locked.write().await;
                *locked = true;
                tracing::info!("Agent locked");
                Ok(messages::build_success())
            }
            Err(_) => Ok(messages::build_failure()),
        }
    }

    async fn handle_unlock(&self, message: &[u8]) -> Result<Vec<u8>> {
        let passphrase = match messages::parse_unlock(message) {
            Some(pass) => pass,
            None => return Ok(messages::build_failure()),
        };

        let passphrase_str = String::from_utf8_lossy(&passphrase);

        match self.ram_store.unlock(&passphrase_str) {
            Ok(_) => {
                // Store the master password for management operations
                {
                    let mut master_password = self.master_password.write().await;
                    *master_password = Some(passphrase_str.into_owned());
                }
                
                let mut locked = self.locked.write().await;
                *locked = false;
                tracing::info!("Agent unlocked");
                Ok(messages::build_success())
            }
            Err(e) => {
                tracing::warn!("Unlock failed: {}", e);
                Ok(messages::build_failure())
            }
        }
    }

    async fn handle_extension(&self, message: &[u8]) -> Result<Vec<u8>> {
        use crate::extensions;

        tracing::debug!("Extension message received");

        // Parse the extension request
        let request = match extensions::parse_extension_request(message) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!("Failed to parse extension request: {}", e);
                return Ok(messages::build_failure());
            }
        };

        // Handle different extension operations
        match request.extension.as_str() {
            "manage.list" => {
                // Get list of keys
                let keys = match self.ram_store.list_keys() {
                    Ok(keys) => keys,
                    Err(_) => return Ok(messages::build_failure()),
                };

                // Get master password for reading disk key metadata
                let master_password = {
                    let master_password_guard = self.master_password.read().await;
                    master_password_guard.clone()
                };

                match extensions::handle_manage_list(keys, self.storage_dir.as_deref(), master_password.as_deref()) {
                    Ok(cbor_data) => Ok(extensions::build_extension_response(cbor_data)),
                    Err(e) => {
                        tracing::error!("Failed to handle manage.list: {}", e);
                        Ok(messages::build_failure())
                    }
                }
            }
            "control.shutdown" => {
                tracing::info!("Received shutdown request via extension");

                // Send success response first
                match extensions::handle_control_shutdown() {
                    Ok(cbor_data) => {
                        // Signal shutdown (this would need to be connected to the daemon)
                        // For now, just return success
                        Ok(extensions::build_extension_response(cbor_data))
                    }
                    Err(e) => {
                        tracing::error!("Failed to handle control.shutdown: {}", e);
                        Ok(messages::build_failure())
                    }
                }
            }
            "manage.load" => {
                // Get master password for disk operations
                let master_password = {
                    let master_password_guard = self.master_password.read().await;
                    match master_password_guard.as_ref() {
                        Some(password) => password.clone(),
                        None => {
                            tracing::error!("Master password not available for manage.load");
                            return Ok(messages::build_failure());
                        }
                    }
                };

                // Handle load request
                match extensions::handle_manage_load(
                    &request.data,
                    &self.ram_store,
                    self.storage_dir.as_deref(),
                    &master_password,
                )
                .await
                {
                    Ok(cbor_data) => Ok(extensions::build_extension_response(cbor_data)),
                    Err(e) => {
                        tracing::error!("Failed to handle manage.load: {}", e);
                        match extensions::build_error_response(e) {
                            Ok(error_cbor) => Ok(extensions::build_extension_response(error_cbor)),
                            Err(_) => Ok(messages::build_failure()),
                        }
                    }
                }
            }
            "manage.import" => {
                tracing::info!("Received import request via extension");
                
                // Get master password for disk operations
                let master_password = {
                    let master_password_guard = self.master_password.read().await;
                    match master_password_guard.as_ref() {
                        Some(password) => password.clone(),
                        None => {
                            tracing::error!("Master password not available for manage.import");
                            return Ok(messages::build_failure());
                        }
                    }
                };

                // Parse CBOR data to get fingerprint and other params
                match extensions::handle_manage_import(&request.data, &self.ram_store, &master_password).await {
                    Ok(cbor_data) => Ok(extensions::build_extension_response(cbor_data)),
                    Err(e) => {
                        tracing::error!("Failed to handle manage.import: {}", e);
                        // Return error in CBOR format
                        match extensions::build_error_response(e) {
                            Ok(cbor_data) => Ok(extensions::build_extension_response(cbor_data)),
                            Err(_) => Ok(messages::build_failure()),
                        }
                    }
                }
            }
            _ => {
                tracing::warn!("Unknown extension operation: {}", request.extension);
                Ok(messages::build_failure())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_locked_behavior() {
        let agent = Agent::new();

        // Should be locked initially
        assert!(*agent.locked.read().await);

        // REQUEST_IDENTITIES should fail when locked
        let msg = vec![wire::MessageType::RequestIdentities as u8];
        let response = agent.handle_message(&msg).await.unwrap();
        assert_eq!(response, messages::build_failure());

        // UNLOCK should work when locked
        let mut unlock_msg = vec![wire::MessageType::Unlock as u8];
        wire::write_string(&mut unlock_msg, b"password");
        let response = agent.handle_message(&unlock_msg).await.unwrap();
        assert_eq!(response, messages::build_success());

        // Should be unlocked now
        assert!(!*agent.locked.read().await);

        // REQUEST_IDENTITIES should work when unlocked
        let response = agent.handle_message(&msg).await.unwrap();
        assert_eq!(response[0], wire::MessageType::IdentitiesAnswer as u8);
    }

    #[tokio::test]
    async fn test_remove_all() {
        let agent = Agent::new();

        // Unlock first
        let mut unlock_msg = vec![wire::MessageType::Unlock as u8];
        wire::write_string(&mut unlock_msg, b"password");
        agent.handle_message(&unlock_msg).await.unwrap();

        // Remove all identities
        let msg = vec![wire::MessageType::RemoveAllIdentities as u8];
        let response = agent.handle_message(&msg).await.unwrap();
        assert_eq!(response, messages::build_success());
    }
}
