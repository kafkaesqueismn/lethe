//! Cryptographic core of niche.
//!
//! Everything here composes audited RustCrypto / dalek primitives; no primitive is
//! implemented by hand. The protocol pieces are:
//!
//! * [`x3dh`]: an X3DH-style handshake with no long-term identity keys. Trust comes
//!   from the out-of-band invitation link, as in SimpleX.
//! * [`ratchet`]: the Signal Double Ratchet (forward secrecy + post-compromise security).
//! * [`pad`]: fixed-size padding so ciphertext length reveals nothing.
//! * [`primitives`]: X25519, Ed25519, XChaCha20-Poly1305, HKDF wrappers.
//! * [`passphrase`]: Argon2id key derivation for the local encrypted store.

pub mod pad;
pub mod passphrase;
pub mod primitives;
pub mod ratchet;
pub mod x3dh;

pub use primitives::{DhKeyPair, SigningKeyPair};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid key or signature")]
    InvalidKey,
    #[error("too many skipped messages")]
    TooManySkipped,
    #[error("malformed data")]
    Malformed,
    #[error("message too large for padding block")]
    TooLarge,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
