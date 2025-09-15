use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionRequest {
    pub extension: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionResponse {
    pub success: bool,
    pub data: Vec<u8>,
}

/// Common key data structure used by both daemon and TUI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedKey {
    pub fp_sha256_hex: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub format: String,
    pub description: String,
    pub source: String, // "internal" | "external"
    pub loaded: bool,
    pub has_disk: bool,
    pub has_cert: bool,
    pub constraints: serde_json::Value, // Object with confirm and lifetime_expires_at
    pub created: Option<String>,
    pub updated: Option<String>,
}

/// Response for manage.list operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageListResponse {
    pub ok: bool,
    pub keys: Vec<ManagedKey>,
}

/// Response for manage operations that just return success/failure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageOperationResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub key_type: String,
    pub comment: String,
    pub locked: bool,
    pub last_used: Option<u64>,
    pub use_count: u64,
    pub constraints: Vec<String>,
}

/// Request for manage.create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageCreateRequest {
    pub key_type: String, // "ed25519" or "rsa"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<u32>, // For RSA keys (2048, 3072, 4096, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_load_to_ram")]
    pub load_to_ram: bool, // Whether to load the key to RAM after creation
}

fn default_load_to_ram() -> bool {
    true
}

/// Response for manage.create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageCreateResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>, // Base64 encoded public key
}

/// Request for manage.delete operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageDeleteRequest {
    pub fp_sha256_hex: String,
}

/// Response for manage.delete operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageDeleteResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}
