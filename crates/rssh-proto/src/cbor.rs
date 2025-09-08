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
    pub fingerprint: String,
    pub key_type: String,
    pub comment: String,
    pub locked: bool,
    pub last_used: Option<u64>,
    pub use_count: u64,
    pub constraints: Vec<String>,
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
