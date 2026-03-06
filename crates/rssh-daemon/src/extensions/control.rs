use rssh_core::Result;

use super::cbor_success;

/// Handle control.shutdown extension
pub fn handle_control_shutdown() -> Result<Vec<u8>> {
    let response_data = serde_json::json!({
        "ok": true
    });

    cbor_success(response_data)
}

/// Handle session-bind@openssh.com extension
pub fn handle_session_bind(data: &[u8]) -> Result<Vec<u8>> {
    // Parse session-bind data according to OpenSSH PROTOCOL.agent specification:
    // string hostkey
    // string session identifier
    // string signature
    // bool is_forwarding

    tracing::debug!(
        "Handling session-bind@openssh.com extension, data length: {}",
        data.len()
    );

    let mut offset = 0;

    // For now, we'll implement a basic validation that just parses the structure
    // without performing cryptographic verification. In a full implementation,
    // this would verify the signature and maintain session binding state.

    // Read hostkey string
    if data.len() < offset + 4 {
        tracing::warn!("session-bind: insufficient data for hostkey length");
        return Ok(build_session_bind_failure("insufficient data for hostkey"));
    }

    let hostkey_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + hostkey_len {
        tracing::warn!("session-bind: insufficient data for hostkey");
        return Ok(build_session_bind_failure("insufficient hostkey data"));
    }

    let _hostkey = &data[offset..offset + hostkey_len];
    offset += hostkey_len;
    tracing::debug!("session-bind: hostkey length: {}", hostkey_len);

    // Read session identifier string
    if data.len() < offset + 4 {
        tracing::warn!("session-bind: insufficient data for session ID length");
        return Ok(build_session_bind_failure(
            "insufficient data for session ID",
        ));
    }

    let session_id_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + session_id_len {
        tracing::warn!("session-bind: insufficient data for session ID");
        return Ok(build_session_bind_failure("insufficient session ID data"));
    }

    let _session_id = &data[offset..offset + session_id_len];
    offset += session_id_len;
    tracing::debug!("session-bind: session ID length: {}", session_id_len);

    // Read signature string
    if data.len() < offset + 4 {
        tracing::warn!("session-bind: insufficient data for signature length");
        return Ok(build_session_bind_failure(
            "insufficient data for signature",
        ));
    }

    let signature_len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if data.len() < offset + signature_len {
        tracing::warn!("session-bind: insufficient data for signature");
        return Ok(build_session_bind_failure("insufficient signature data"));
    }

    let _signature = &data[offset..offset + signature_len];
    offset += signature_len;
    tracing::debug!("session-bind: signature length: {}", signature_len);

    // Read is_forwarding boolean
    if data.len() < offset + 1 {
        tracing::warn!("session-bind: insufficient data for is_forwarding flag");
        return Ok(build_session_bind_failure(
            "insufficient data for forwarding flag",
        ));
    }

    let is_forwarding = data[offset] != 0;
    tracing::debug!("session-bind: is_forwarding: {}", is_forwarding);

    // TODO: In a full implementation, this would:
    // 1. Verify the signature using the hostkey and session identifier
    // 2. Check for duplicate session identifiers
    // 3. Prevent rebinding of connections used for authentication
    // 4. Store the binding for use in key constraint validation

    // For now, we accept all session-bind requests and return success
    // This provides OpenSSH compatibility without the security enforcement
    tracing::info!(
        "session-bind: Successfully processed session binding (validation not yet implemented)"
    );

    Ok(build_session_bind_failure("not yet implemented"))
}

/// Build failure response for session-bind extension
fn build_session_bind_failure(reason: &str) -> Vec<u8> {
    tracing::warn!("session-bind: Returning failure: {}", reason);
    vec![rssh_proto::wire::MessageType::Failure as u8]
}
