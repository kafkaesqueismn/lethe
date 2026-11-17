//! Thin, misuse-resistant wrappers around the underlying primitives.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// Fill a fixed-size array from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HKDF-SHA256 expand into a fixed-size output.
pub fn hkdf<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; N];
    hk.expand(info, &mut out).expect("HKDF output length is valid");
    out
}

/// XChaCha20-Poly1305 encryption. The 24-byte nonce is safe to pick at random.
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad: ad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers")
}

pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: ad })
        .map_err(|_| CryptoError::Decrypt)
}

/// Encrypt with a fresh random nonce, prepended to the output.
pub fn seal_random(key: &[u8; KEY_LEN], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let nonce = random_bytes::<NONCE_LEN>();
    let mut out = nonce.to_vec();
    out.extend(seal(key, &nonce, plaintext, ad));
    out
}

pub fn open_random(key: &[u8; KEY_LEN], data: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Malformed);
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    open(key, nonce.try_into().unwrap(), ct, ad)
}

/// An X25519 key pair. Serializes as the 32-byte secret (only ever stored encrypted).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DhKeyPair {
    secret: [u8; 32],
}

impl DhKeyPair {
    pub fn generate() -> Self {
        Self { secret: x25519_dalek::StaticSecret::random_from_rng(OsRng).to_bytes() }
    }

    pub fn public(&self) -> [u8; 32] {
        let s = x25519_dalek::StaticSecret::from(self.secret);
        x25519_dalek::PublicKey::from(&s).to_bytes()
    }

    /// Diffie-Hellman. Rejects all-zero output (low-order peer key).
    pub fn dh(&self, their_public: &[u8; 32]) -> Result<[u8; 32]> {
        let s = x25519_dalek::StaticSecret::from(self.secret);
        let shared = s.diffie_hellman(&x25519_dalek::PublicKey::from(*their_public));
        if !shared.was_contributory() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(shared.to_bytes())
    }
}

impl std::fmt::Debug for DhKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DhKeyPair(pub={:02x?}..)", &self.public()[..4])
    }
}

/// An Ed25519 key pair used to authorize queue commands at the relay.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SigningKeyPair {
    secret: [u8; 32],
}

impl SigningKeyPair {
    pub fn generate() -> Self {
        Self { secret: ed25519_dalek::SigningKey::generate(&mut OsRng).to_bytes() }
    }

    pub fn public(&self) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&self.secret).verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        ed25519_dalek::SigningKey::from_bytes(&self.secret).sign(msg).to_bytes().to_vec()
    }
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKeyPair(pub={:02x?}..)", &self.public()[..4])
    }
}

/// Strict Ed25519 verification (rejects malleable / small-order signatures).
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public).map_err(|_| CryptoError::InvalidKey)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| CryptoError::InvalidKey)?;
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| CryptoError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_agrees() {
        let a = DhKeyPair::generate();
        let b = DhKeyPair::generate();
        assert_eq!(a.dh(&b.public()).unwrap(), b.dh(&a.public()).unwrap());
    }

    #[test]
    fn dh_rejects_low_order_point() {
        let a = DhKeyPair::generate();
        assert_eq!(a.dh(&[0u8; 32]), Err(CryptoError::InvalidKey));
    }

    #[test]
    fn sign_verify() {
        let k = SigningKeyPair::generate();
        let sig = k.sign(b"hello");
        verify(&k.public(), b"hello", &sig).unwrap();
        assert!(verify(&k.public(), b"hellp", &sig).is_err());
        assert!(verify(&SigningKeyPair::generate().public(), b"hello", &sig).is_err());
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = random_bytes::<32>();
        let mut ct = seal_random(&key, b"secret", b"ad");
        assert_eq!(open_random(&key, &ct, b"ad").unwrap(), b"secret");
        assert!(open_random(&key, &ct, b"other ad").is_err());
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(open_random(&key, &ct, b"ad").is_err());
    }
}
