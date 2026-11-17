//! The niche relay protocol, modelled on SimpleX SMP.
//!
//! A relay hosts **simplex (one-way) queues**. Each queue has two unrelated random IDs:
//! the *recipient ID*, known only to the recipient, and the *sender ID*, given to the
//! sender inside an invitation. The relay never learns who is talking to whom: there
//! are no accounts, and a conversation is just two queues, usually on different relays.
//!
//! Every frame on the wire is exactly [`BLOCK_SIZE`] bytes (inside TLS 1.3 + WebSocket),
//! so traffic shape doesn't reveal message sizes or command types.

mod addr;

pub use addr::{AddrError, RelayAddr};

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
/// Size of every frame in either direction.
pub const BLOCK_SIZE: usize = 16 * 1024;
/// Max `SEND` body; leaves room for framing and the relay's re-encryption tag.
pub const MAX_BODY: usize = 15 * 1024 + 512;
/// Size of the padded plaintext the client puts inside the end-to-end ratchet.
pub const E2E_BLOCK: usize = 15 * 1024;

pub type QueueId = [u8; 24];
pub type MsgId = [u8; 24];
pub type SessionId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// Create a queue. Recipient supplies its Ed25519 auth key and an X25519 key used
    /// to encrypt delivered messages between relay and recipient.
    New { recipient_key: [u8; 32], recipient_dh: [u8; 32] },
    /// Recipient: lock the queue so only `sender_key` can send (signed `Send`).
    Key { sender_key: [u8; 32] },
    /// Recipient: subscribe to deliveries on this connection.
    Sub,
    /// Recipient: acknowledge (delete) the delivered message; the next one follows.
    Ack { msg_id: MsgId },
    /// Recipient: delete the queue and all its messages.
    Del,
    /// Sender: enqueue a message. Must be signed once the queue is secured.
    Send { body: Vec<u8> },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFrame {
    pub corr_id: u64,
    /// Recipient ID for recipient commands, sender ID for `Send`, zeros for `New`/`Ping`.
    pub entity: QueueId,
    /// Ed25519 signature over [`signed_bytes`].
    pub sig: Option<Vec<u8>>,
    pub cmd: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Unknown queue, bad signature, or wrong key. Deliberately indistinguishable so
    /// the relay can't be probed for which queue IDs exist.
    Auth,
    /// Queue is full.
    Quota,
    /// `Ack` for a message that isn't the one currently delivered.
    NoMsg,
    /// Body too large or malformed command.
    Syntax,
    /// Recipient key reused (queue IDs must be unlinkable).
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Ids { recipient_id: QueueId, sender_id: QueueId, server_dh: [u8; 32] },
    Ok,
    /// A delivered message. `body` is encrypted by the relay to the recipient's
    /// queue DH key (nonce = `msg_id`), so it differs from what the sender sent.
    Msg { msg_id: MsgId, ts: u64, body: Vec<u8> },
    /// Another connection subscribed to this queue; this one no longer receives it.
    End,
    Pong,
    Err(ErrorCode),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerFrame {
    /// First frame on every connection. `session_id` is mixed into every signature,
    /// so signed commands can't be replayed on another connection.
    Hello { version: u16, session_id: SessionId },
    /// `corr_id == 0` marks a push (`Msg`, `End`) not tied to a request.
    Reply { corr_id: u64, entity: QueueId, resp: Response },
}

/// Bytes covered by a command signature.
pub fn signed_bytes(session_id: &SessionId, corr_id: u64, entity: &QueueId, cmd: &Command) -> Vec<u8> {
    postcard::to_stdvec(&(b"niche-cmd-v1", session_id, corr_id, entity, cmd)).expect("serializable")
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too large")]
    TooLarge,
    #[error("malformed frame")]
    Malformed,
}

/// Serialize and pad to exactly [`BLOCK_SIZE`].
pub fn encode_block<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let raw = postcard::to_stdvec(value).map_err(|_| FrameError::Malformed)?;
    niche_crypto::pad::pad(&raw, BLOCK_SIZE).map_err(|_| FrameError::TooLarge)
}

pub fn decode_block<T: for<'de> Deserialize<'de>>(block: &[u8]) -> Result<T, FrameError> {
    if block.len() != BLOCK_SIZE {
        return Err(FrameError::Malformed);
    }
    let raw = niche_crypto::pad::unpad(block).map_err(|_| FrameError::Malformed)?;
    postcard::from_bytes(raw).map_err(|_| FrameError::Malformed)
}

/// Generic postcard helpers for nested payloads.
pub fn to_bytes<T: Serialize>(v: &T) -> Vec<u8> {
    postcard::to_stdvec(v).expect("serializable")
}

pub fn from_bytes<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Result<T, FrameError> {
    postcard::from_bytes(b).map_err(|_| FrameError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frame_is_block_sized() {
        let small = ClientFrame { corr_id: 1, entity: [0; 24], sig: None, cmd: Command::Ping };
        let big = ClientFrame {
            corr_id: 2,
            entity: [9; 24],
            sig: Some(vec![1; 64]),
            cmd: Command::Send { body: vec![7; MAX_BODY] },
        };
        for f in [&small, &big] {
            let b = encode_block(f).unwrap();
            assert_eq!(b.len(), BLOCK_SIZE);
            let back: ClientFrame = decode_block(&b).unwrap();
            assert_eq!(back.cmd, f.cmd);
        }
        let reply = ServerFrame::Reply {
            corr_id: 0,
            entity: [1; 24],
            resp: Response::Msg { msg_id: [2; 24], ts: 1, body: vec![3; MAX_BODY + 16] },
        };
        assert_eq!(encode_block(&reply).unwrap().len(), BLOCK_SIZE);
    }

    #[test]
    fn oversize_and_garbage_rejected() {
        let f = ClientFrame { corr_id: 1, entity: [0; 24], sig: None, cmd: Command::Send { body: vec![0; BLOCK_SIZE] } };
        assert!(encode_block(&f).is_err());
        assert!(decode_block::<ClientFrame>(&[0xff; BLOCK_SIZE]).is_err());
        assert!(decode_block::<ClientFrame>(&[0; 10]).is_err());
    }

    #[test]
    fn signature_binds_session_and_command() {
        let a = signed_bytes(&[1; 32], 5, &[2; 24], &Command::Sub);
        assert_ne!(a, signed_bytes(&[9; 32], 5, &[2; 24], &Command::Sub));
        assert_ne!(a, signed_bytes(&[1; 32], 6, &[2; 24], &Command::Sub));
        assert_ne!(a, signed_bytes(&[1; 32], 5, &[2; 24], &Command::Del));
    }
}

/// Relay→recipient delivery encryption (the per-queue layer). Both sides derive the
/// key from `DH(server_dh, recipient_dh)`; `msg_id` is a fresh random nonce.
pub mod delivery {
    use niche_crypto::primitives::{hkdf, open, seal};

    pub fn key(shared_dh: &[u8; 32]) -> [u8; 32] {
        hkdf(b"niche-delivery-v1", shared_dh, b"queue delivery key")
    }

    pub fn seal_body(key: &[u8; 32], msg_id: &super::MsgId, ts: u64, body: &[u8]) -> Vec<u8> {
        seal(key, msg_id, body, &ts.to_be_bytes())
    }

    pub fn open_body(key: &[u8; 32], msg_id: &super::MsgId, ts: u64, body: &[u8]) -> niche_crypto::Result<Vec<u8>> {
        open(key, msg_id, body, &ts.to_be_bytes())
    }
}
