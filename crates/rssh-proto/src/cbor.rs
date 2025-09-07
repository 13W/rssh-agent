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
