use rssh_core::wire;

/// Parse key components from wire format and calculate fingerprint
pub fn parse_wire_key(key_data: &[u8]) -> Result<(String, String, Vec<u8>), String> {
    let parsed = wire::parse_wire_key(key_data).map_err(|e| e.to_string())?;
    Ok((parsed.fingerprint, parsed.key_type, parsed.public_key_blob))
}

/// Extract public key blob for identity listing
pub fn get_public_key_blob(key_data: &[u8]) -> Result<Vec<u8>, String> {
    let parsed = wire::parse_wire_key(key_data).map_err(|e| e.to_string())?;
    Ok(parsed.public_key_blob)
}
