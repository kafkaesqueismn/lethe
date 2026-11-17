//! X3DH-style key agreement with no long-term identities.
//!
//! The *inviter* (Alice) puts two X25519 public keys `ik_a`, `ek_a` in the one-time
//! invitation link. The *joiner* (Bob) generates `ik_b`, `ek_b` and computes
//!
//! ```text
//! DH1 = DH(ik_b, ek_a)   DH2 = DH(ek_b, ik_a)   DH3 = DH(ek_b, ek_a)
//! SK  = HKDF(salt = 0^32, ikm = 0xFF^32 || DH1 || DH2 || DH3, info = "niche x3dh v1")
//! AD  = ik_a || ik_b
//! ```
//!
//! Authentication comes from the invitation travelling over a channel the two
//! people trust (in person, QR code, another messenger). `ek_a` doubles as
//! Alice's first Double Ratchet key, just as Signal reuses the signed prekey.

use crate::primitives::{hkdf, DhKeyPair};
use crate::ratchet::Ratchet;
use crate::Result;

const INFO: &[u8] = b"niche x3dh v1";

/// Alice's secret half of an invitation.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct InviterKeys {
    pub ik: DhKeyPair,
    pub ek: DhKeyPair,
}

impl InviterKeys {
    pub fn generate() -> Self {
        Self { ik: DhKeyPair::generate(), ek: DhKeyPair::generate() }
    }

    /// The public keys that go into the invitation link: `(ik_a, ek_a)`.
    pub fn public(&self) -> ([u8; 32], [u8; 32]) {
        (self.ik.public(), self.ek.public())
    }

    /// Complete the handshake when Bob's confirmation arrives. Alice becomes the
    /// ratchet *receiver*: she can't send until she has decrypted Bob's first message.
    pub fn accept(self, ik_b: &[u8; 32], ek_b: &[u8; 32]) -> Result<Ratchet> {
        let dh1 = self.ek.dh(ik_b)?;
        let dh2 = self.ik.dh(ek_b)?;
        let dh3 = self.ek.dh(ek_b)?;
        let sk = derive(&dh1, &dh2, &dh3);
        let ad = ad(&self.ik.public(), ik_b);
        Ok(Ratchet::init_receiver(sk, self.ek.clone(), ad))
    }
}

/// The joiner's public `(ik_b, ek_b)`, sent in the confirmation message.
pub type JoinerPublic = ([u8; 32], [u8; 32]);

/// Bob's side: returns his public keys and a ratchet ready to encrypt.
pub fn join(ik_a: &[u8; 32], ek_a: &[u8; 32]) -> Result<(JoinerPublic, Ratchet)> {
    let ik = DhKeyPair::generate();
    let ek = DhKeyPair::generate();
    let dh1 = ik.dh(ek_a)?;
    let dh2 = ek.dh(ik_a)?;
    let dh3 = ek.dh(ek_a)?;
    let sk = derive(&dh1, &dh2, &dh3);
    let ratchet = Ratchet::init_sender(sk, *ek_a, ad(ik_a, &ik.public()))?;
    Ok(((ik.public(), ek.public()), ratchet))
}

fn derive(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32]) -> [u8; 32] {
    let mut ikm = zeroize::Zeroizing::new([0u8; 128]);
    ikm[..32].fill(0xff);
    ikm[32..64].copy_from_slice(dh1);
    ikm[64..96].copy_from_slice(dh2);
    ikm[96..].copy_from_slice(dh3);
    hkdf(&[0u8; 32], ikm.as_ref(), INFO)
}

fn ad(ik_a: &[u8; 32], ik_b: &[u8; 32]) -> Vec<u8> {
    [ik_a.as_slice(), ik_b.as_slice()].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_produces_working_ratchets() {
        let alice = InviterKeys::generate();
        let (ik_a, ek_a) = alice.public();
        let ((ik_b, ek_b), mut bob) = join(&ik_a, &ek_a).unwrap();
        let mut alice = alice.accept(&ik_b, &ek_b).unwrap();

        let m = bob.encrypt(b"hi alice");
        assert_eq!(alice.decrypt(&m).unwrap(), b"hi alice");
        let r = alice.encrypt(b"hi bob");
        assert_eq!(bob.decrypt(&r).unwrap(), b"hi bob");
    }

    #[test]
    fn wrong_invitation_keys_fail() {
        let alice = InviterKeys::generate();
        let mallory = InviterKeys::generate();
        let (ik_m, ek_m) = mallory.public();
        let ((ik_b, ek_b), mut bob) = join(&ik_m, &ek_m).unwrap();
        let mut alice = alice.accept(&ik_b, &ek_b).unwrap();
        assert!(alice.decrypt(&bob.encrypt(b"x")).is_err());
    }
}
