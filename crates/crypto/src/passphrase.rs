//! Passphrase → key derivation for the local store (Argon2id).

use zeroize::Zeroizing;

use crate::{CryptoError, Result};

pub const SALT_LEN: usize = 16;

/// Argon2id with 64 MiB memory, 3 passes, 1 lane (OWASP-recommended baseline).
pub fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| CryptoError::Malformed)?;
    derive_with(passphrase, salt, params)
}

/// Cheap parameters so tests don't spend seconds in Argon2. Never use for real data.
#[doc(hidden)]
pub fn derive_key_insecure_for_tests(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(8, 1, 1, Some(32)).map_err(|_| CryptoError::Malformed)?;
    derive_with(passphrase, salt, params)
}

fn derive_with(passphrase: &[u8], salt: &[u8], params: argon2::Params) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| CryptoError::Malformed)?;
    Ok(key)
}
