use crate::{Error, Result};
use argon2::{Argon2, Params, Version};
use zeroize::Zeroizing;

/// Derive a 32-byte key from a password using Argon2id with a domain-separated context.
/// The context fed to Argon2 is `domain || salt`, binding the key to its purpose.
pub(crate) fn derive_key_with_domain(
    domain: &str,
    password: &str,
    salt: &[u8],
    memory_mib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(
        memory_mib * 1024, // MiB to KiB
        iterations,
        parallelism,
        Some(32),
    )
    .map_err(|e| Error::Crypto(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    let mut context = Vec::from(domain.as_bytes());
    context.extend_from_slice(salt);

    argon2
        .hash_password_into(password.as_bytes(), &context, key.as_mut())
        .map_err(|e| Error::Crypto(e.to_string()))?;

    Ok(key)
}
