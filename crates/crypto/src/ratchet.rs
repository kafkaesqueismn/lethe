//! Signal Double Ratchet (https://signal.org/docs/specifications/doubleratchet/).
//!
//! * KDF_RK: HKDF-SHA256(salt = RK, ikm = DH out, info) -> (RK', CK)
//! * KDF_CK: HMAC-SHA256(CK, 0x01) = MK, HMAC-SHA256(CK, 0x02) = CK'
//! * Message encryption: HKDF(MK) -> (key, nonce), XChaCha20-Poly1305, AD = AD_x3dh || header
//!
//! Decryption is transactional: the state only changes if the message authenticates,
//! so forged, replayed or corrupted messages can't desync the session.
//!
//! The header (ratchet public key + counters) is sent in the clear inside the
//! relay-encrypted envelope; header encryption is a planned improvement.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::primitives::{hkdf, open, seal, DhKeyPair};
use crate::{CryptoError, Result};

/// Maximum message keys skipped within one chain (bounds work for a malicious counter).
pub const MAX_SKIP: u32 = 1000;
/// Maximum stored skipped keys overall; the oldest are dropped first.
pub const MAX_STORED_SKIPPED: usize = 2000;

const RK_INFO: &[u8] = b"lethe ratchet rk v1";
const MK_INFO: &[u8] = b"lethe ratchet mk v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    dh: [u8; 32],
    n: u32,
    mk: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Ratchet {
    dhs: DhKeyPair,
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: Vec<SkippedKey>,
    ad: Vec<u8>,
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.rk.zeroize();
        self.cks.zeroize();
        self.ckr.zeroize();
    }
}

impl Ratchet {
    /// For the party that sends first and already knows the peer's ratchet key.
    pub fn init_sender(sk: [u8; 32], their_ratchet: [u8; 32], ad: Vec<u8>) -> Result<Self> {
        let dhs = DhKeyPair::generate();
        let (rk, cks) = kdf_rk(&sk, &dhs.dh(&their_ratchet)?);
        Ok(Self { dhs, dhr: Some(their_ratchet), rk, cks: Some(cks), ckr: None, ns: 0, nr: 0, pn: 0, skipped: vec![], ad })
    }

    /// For the party whose ratchet key the sender already has.
    pub fn init_receiver(sk: [u8; 32], our_ratchet: DhKeyPair, ad: Vec<u8>) -> Self {
        Self { dhs: our_ratchet, dhr: None, rk: sk, cks: None, ckr: None, ns: 0, nr: 0, pn: 0, skipped: vec![], ad }
    }

    /// Whether this side can encrypt yet. A receiver must decrypt one message first.
    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    /// Encrypt a message. Panics if `can_send()` is false, which is a caller bug.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> RatchetMessage {
        let cks = self.cks.as_mut().expect("ratchet cannot send before receiving the first message");
        let mk = kdf_ck(cks);
        let header = Header { dh: self.dhs.public(), pn: self.pn, n: self.ns };
        self.ns += 1;
        let ciphertext = encrypt_with(&mk, plaintext, &self.ad, &header);
        RatchetMessage { header, ciphertext }
    }

    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        let mut next = self.clone();
        let pt = next.decrypt_inner(msg)?;
        *self = next;
        Ok(pt)
    }

    fn decrypt_inner(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>> {
        let h = &msg.header;
        if let Some(i) = self.skipped.iter().position(|k| k.dh == h.dh && k.n == h.n) {
            let key = self.skipped.remove(i);
            return decrypt_with(&key.mk, &msg.ciphertext, &self.ad, h);
        }
        if self.dhr != Some(h.dh) {
            self.skip_until(h.pn)?;
            self.dh_ratchet(h)?;
        }
        self.skip_until(h.n)?;
        let ckr = self.ckr.as_mut().ok_or(CryptoError::Decrypt)?;
        let mk = kdf_ck(ckr);
        self.nr += 1;
        decrypt_with(&mk, &msg.ciphertext, &self.ad, h)
    }

    fn skip_until(&mut self, until: u32) -> Result<()> {
        let Some(ckr) = self.ckr.as_mut() else { return Ok(()) };
        if until > self.nr.saturating_add(MAX_SKIP) {
            return Err(CryptoError::TooManySkipped);
        }
        let dh = self.dhr.expect("receiving chain implies a remote key");
        while self.nr < until {
            let mk = kdf_ck(ckr);
            self.skipped.push(SkippedKey { dh, n: self.nr, mk });
            self.nr += 1;
        }
        if self.skipped.len() > MAX_STORED_SKIPPED {
            let excess = self.skipped.len() - MAX_STORED_SKIPPED;
            self.skipped.drain(..excess);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, h: &Header) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(h.dh);
        let (rk, ckr) = kdf_rk(&self.rk, &self.dhs.dh(&h.dh)?);
        self.rk = rk;
        self.ckr = Some(ckr);
        self.dhs = DhKeyPair::generate();
        let (rk, cks) = kdf_rk(&self.rk, &self.dhs.dh(&h.dh)?);
        self.rk = rk;
        self.cks = Some(cks);
        Ok(())
    }
}

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let out: [u8; 64] = hkdf(rk, dh_out, RK_INFO);
    (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
}

/// Advance a chain key in place and return the message key.
fn kdf_ck(ck: &mut [u8; 32]) -> [u8; 32] {
    let hmac = |byte: u8| -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(ck).expect("HMAC accepts any key length");
        m.update(&[byte]);
        m.finalize().into_bytes().into()
    };
    let mk = hmac(0x01);
    *ck = hmac(0x02);
    mk
}

fn message_ad(ad: &[u8], h: &Header) -> Vec<u8> {
    let mut out = ad.to_vec();
    out.extend_from_slice(&h.dh);
    out.extend_from_slice(&h.pn.to_be_bytes());
    out.extend_from_slice(&h.n.to_be_bytes());
    out
}

fn key_nonce(mk: &[u8; 32]) -> ([u8; 32], [u8; 24]) {
    let out: [u8; 56] = hkdf(&[0u8; 32], mk, MK_INFO);
    (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
}

fn encrypt_with(mk: &[u8; 32], pt: &[u8], ad: &[u8], h: &Header) -> Vec<u8> {
    let (k, n) = key_nonce(mk);
    seal(&k, &n, pt, &message_ad(ad, h))
}

fn decrypt_with(mk: &[u8; 32], ct: &[u8], ad: &[u8], h: &Header) -> Result<Vec<u8>> {
    let (k, n) = key_nonce(mk);
    open(&k, &n, ct, &message_ad(ad, h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh;

    fn pair() -> (Ratchet, Ratchet) {
        let inv = x3dh::InviterKeys::generate();
        let (ik, ek) = inv.public();
        let ((ik_b, ek_b), bob) = x3dh::join(&ik, &ek).unwrap();
        (inv.accept(&ik_b, &ek_b).unwrap(), bob)
    }

    #[test]
    fn long_conversation_alternating_and_bursts() {
        let (mut a, mut b) = pair();
        assert!(!a.can_send());
        for round in 0..20u32 {
            for i in 0..(round % 4 + 1) {
                let m = b.encrypt(format!("b{round}.{i}").as_bytes());
                assert_eq!(a.decrypt(&m).unwrap(), format!("b{round}.{i}").as_bytes());
            }
            for i in 0..(round % 3 + 1) {
                let m = a.encrypt(format!("a{round}.{i}").as_bytes());
                assert_eq!(b.decrypt(&m).unwrap(), format!("a{round}.{i}").as_bytes());
            }
        }
    }

    #[test]
    fn out_of_order_across_ratchet_steps() {
        let (mut a, mut b) = pair();
        let b0 = b.encrypt(b"b0");
        let b1 = b.encrypt(b"b1");
        let b2 = b.encrypt(b"b2");
        assert_eq!(a.decrypt(&b2).unwrap(), b"b2");
        let a0 = a.encrypt(b"a0");
        assert_eq!(b.decrypt(&a0).unwrap(), b"a0");
        let b3 = b.encrypt(b"b3"); // new ratchet step
        assert_eq!(a.decrypt(&b3).unwrap(), b"b3");
        assert_eq!(a.decrypt(&b0).unwrap(), b"b0");
        assert_eq!(a.decrypt(&b1).unwrap(), b"b1");
    }

    #[test]
    fn replay_is_rejected_and_state_survives() {
        let (mut a, mut b) = pair();
        let m = b.encrypt(b"once");
        assert_eq!(a.decrypt(&m).unwrap(), b"once");
        assert!(a.decrypt(&m).is_err());
        let m2 = b.encrypt(b"twice");
        assert_eq!(a.decrypt(&m2).unwrap(), b"twice");
    }

    #[test]
    fn tampering_is_rejected_and_state_survives() {
        let (mut a, mut b) = pair();
        let m = b.encrypt(b"hello");
        let mut bad = m.clone();
        bad.ciphertext[0] ^= 1;
        assert_eq!(a.decrypt(&bad), Err(CryptoError::Decrypt));
        let mut bad_header = m.clone();
        bad_header.header.n = 5;
        assert!(a.decrypt(&bad_header).is_err());
        assert_eq!(a.decrypt(&m).unwrap(), b"hello");
    }

    #[test]
    fn huge_skip_is_rejected() {
        let (mut a, mut b) = pair();
        let mut m = b.encrypt(b"x");
        m.header.n = MAX_SKIP + 10;
        assert_eq!(a.decrypt(&m), Err(CryptoError::TooManySkipped));
    }

    #[test]
    fn state_serializes() {
        let (mut a, mut b) = pair();
        let m = b.encrypt(b"before");
        a.decrypt(&m).unwrap();
        let bytes = postcard::to_stdvec(&a).unwrap();
        let mut a2: Ratchet = postcard::from_bytes(&bytes).unwrap();
        let r = a2.encrypt(b"after restore");
        assert_eq!(b.decrypt(&r).unwrap(), b"after restore");
    }
}
