use crate::wire::{self, Constraint, MessageType};

// SSH Agent Protocol Constants
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
pub const SSH_AGENT_EXTENSION_RESPONSE: u8 = 29;

/// Identity information for REQUEST_IDENTITIES response
#[derive(Debug, Clone)]
pub struct Identity {
    pub public_key: Vec<u8>,
    pub comment: String,
}

/// Parse a REQUEST_IDENTITIES message
pub fn parse_request_identities(data: &[u8]) -> Option<()> {
    if data.len() != 1 || data[0] != MessageType::RequestIdentities as u8 {
        return None;
    }
    Some(())
}

/// Build an IDENTITIES_ANSWER message
pub fn build_identities_answer(identities: &[Identity]) -> Vec<u8> {
    let mut buf = Vec::new();
    wire::write_u8(&mut buf, MessageType::IdentitiesAnswer as u8);
    wire::write_u32(&mut buf, identities.len() as u32);

    for identity in identities {
        wire::write_string(&mut buf, &identity.public_key);
        wire::write_string(&mut buf, identity.comment.as_bytes());
    }

    buf
}

/// Parse a SIGN_REQUEST message
pub fn parse_sign_request(data: &[u8]) -> Option<SignRequest> {
    let mut offset = 0;

    let msg_type = wire::read_u8(data, &mut offset)?;
    if msg_type != MessageType::SignRequest as u8 {
        return None;
    }

    let key_blob = wire::read_string(data, &mut offset)?;
    let data_to_sign = wire::read_string(data, &mut offset)?;
    let flags = wire::read_u32(data, &mut offset).unwrap_or(0);

    Some(SignRequest {
        key_blob,
        data: data_to_sign,
        flags,
    })
}

#[derive(Debug)]
pub struct SignRequest {
    pub key_blob: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u32,
}

impl SignRequest {
    pub fn wants_rsa_sha256(&self) -> bool {
        self.flags & 0x02 != 0
    }

    pub fn wants_rsa_sha512(&self) -> bool {
        self.flags & 0x04 != 0
    }
}

/// Build a SIGN_RESPONSE message
pub fn build_sign_response(signature: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    wire::write_u8(&mut buf, MessageType::SignResponse as u8);
    wire::write_string(&mut buf, signature);
    buf
}

/// Parse an ADD_IDENTITY message
pub fn parse_add_identity(data: &[u8]) -> Option<AddIdentity> {
    let mut offset = 0;

    let msg_type = wire::read_u8(data, &mut offset)?;
    if msg_type != MessageType::AddIdentity as u8 {
        return None;
    }

    parse_add_identity_common(data, &mut offset, false)
}

/// Parse an ADD_ID_CONSTRAINED message
pub fn parse_add_id_constrained(data: &[u8]) -> Option<AddIdentity> {
    let mut offset = 0;

    let msg_type = wire::read_u8(data, &mut offset)?;
    if msg_type != MessageType::AddIdConstrained as u8 {
        return None;
    }

    parse_add_identity_common(data, &mut offset, true)
}

fn parse_add_identity_common(
    data: &[u8],
    offset: &mut usize,
    constrained: bool,
) -> Option<AddIdentity> {
    let key_type = wire::read_string(data, offset)?;
    let key_type_str = std::str::from_utf8(&key_type).ok()?;

    // Read the key components based on key type
    // We'll store all the components together to reconstruct later
    let mut key_components = Vec::new();

    match key_type_str {
        "ssh-ed25519" => {
            // Ed25519: public key (32 bytes) + private key (64 bytes)
            let pub_key = wire::read_string(data, offset)?;
            let priv_key = wire::read_string(data, offset)?;

            // Store the key type and components with proper length prefixes
            key_components.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&key_type);
            key_components.extend_from_slice(&(pub_key.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&pub_key);
            key_components.extend_from_slice(&(priv_key.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&priv_key);
        }
        "ssh-rsa" => {
            // RSA: n, e, d, iqmp, p, q
            let n = wire::read_string(data, offset)?;
            let e = wire::read_string(data, offset)?;
            let d = wire::read_string(data, offset)?;
            let iqmp = wire::read_string(data, offset)?;
            let p = wire::read_string(data, offset)?;
            let q = wire::read_string(data, offset)?;

            // Store all RSA components with proper length prefixes
            key_components.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&key_type);
            key_components.extend_from_slice(&(n.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&n);
            key_components.extend_from_slice(&(e.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&e);
            key_components.extend_from_slice(&(d.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&d);
            key_components.extend_from_slice(&(iqmp.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&iqmp);
            key_components.extend_from_slice(&(p.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&p);
            key_components.extend_from_slice(&(q.len() as u32).to_be_bytes());
            key_components.extend_from_slice(&q);
        }
        _ => return None,
    };

    let private_key = key_components;

    let comment = wire::read_string(data, offset)?;
    let comment_str = String::from_utf8_lossy(&comment).into_owned();

    let mut constraints = Vec::new();
    if constrained {
        while *offset < data.len() {
            let constraint_type = wire::read_u8(data, offset)?;
            let constraint = match constraint_type {
                1 => {
                    // Lifetime constraint
                    let lifetime = wire::read_u32(data, offset)?;
                    Constraint::Lifetime(lifetime)
                }
                2 => Constraint::Confirm,
                x => Constraint::Unknown(x),
            };
            constraints.push(constraint);
        }
    }

    Some(AddIdentity {
        key_type: key_type_str.to_string(),
        private_key_data: private_key,
        comment: comment_str,
        constraints,
    })
}

#[derive(Debug)]
pub struct AddIdentity {
    pub key_type: String,
    pub private_key_data: Vec<u8>,
    pub comment: String,
    pub constraints: Vec<Constraint>,
}

impl AddIdentity {
    pub fn has_confirm(&self) -> bool {
        self.constraints
            .iter()
            .any(|c| matches!(c, Constraint::Confirm))
    }

    pub fn lifetime_secs(&self) -> Option<u32> {
        self.constraints.iter().find_map(|c| {
            if let Constraint::Lifetime(secs) = c {
                Some(*secs)
            } else {
                None
            }
        })
    }
}

/// Parse a REMOVE_IDENTITY message
pub fn parse_remove_identity(data: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;

    let msg_type = wire::read_u8(data, &mut offset)?;
    if msg_type != MessageType::RemoveIdentity as u8 {
        return None;
    }

    wire::read_string(data, &mut offset)
}

/// Parse a REMOVE_ALL_IDENTITIES message
pub fn parse_remove_all_identities(data: &[u8]) -> Option<()> {
    if data.len() != 1 || data[0] != MessageType::RemoveAllIdentities as u8 {
        return None;
    }
    Some(())
}

/// Parse a LOCK message
pub fn parse_lock(data: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;

    let msg_type = wire::read_u8(data, &mut offset)?;
    if msg_type != MessageType::Lock as u8 {
        return None;
    }

    wire::read_string(data, &mut offset)
}

/// Parse an UNLOCK message
pub fn parse_unlock(data: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;

    let msg_type = wire::read_u8(data, &mut offset)?;
    if msg_type != MessageType::Unlock as u8 {
        return None;
    }

    wire::read_string(data, &mut offset)
}

/// Build a SUCCESS message
pub fn build_success() -> Vec<u8> {
    vec![MessageType::Success as u8]
}

/// Build a FAILURE message
pub fn build_failure() -> Vec<u8> {
    vec![MessageType::Failure as u8]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_identities() {
        let msg = vec![MessageType::RequestIdentities as u8];
        assert!(parse_request_identities(&msg).is_some());

        let bad_msg = vec![MessageType::SignRequest as u8];
        assert!(parse_request_identities(&bad_msg).is_none());
    }

    #[test]
    fn test_identities_answer() {
        let identities = vec![
            Identity {
                public_key: b"fake_key_1".to_vec(),
                comment: "key1".to_string(),
            },
            Identity {
                public_key: b"fake_key_2".to_vec(),
                comment: "key2".to_string(),
            },
        ];

        let msg = build_identities_answer(&identities);
        assert_eq!(msg[0], MessageType::IdentitiesAnswer as u8);

        let mut offset = 1;
        let count = wire::read_u32(&msg, &mut offset).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_sign_request() {
        let mut msg = vec![MessageType::SignRequest as u8];
        wire::write_string(&mut msg, b"key_blob");
        wire::write_string(&mut msg, b"data_to_sign");
        wire::write_u32(&mut msg, 0x06); // RSA SHA-256 and SHA-512 flags

        let req = parse_sign_request(&msg).unwrap();
        assert_eq!(req.key_blob, b"key_blob");
        assert_eq!(req.data, b"data_to_sign");
        assert!(req.wants_rsa_sha256());
        assert!(req.wants_rsa_sha512());
    }

    #[test]
    fn test_success_failure() {
        let success = build_success();
        assert_eq!(success, vec![MessageType::Success as u8]);

        let failure = build_failure();
        assert_eq!(failure, vec![MessageType::Failure as u8]);
    }
}
