//! Persistent client state and the messages carried inside queues.

use std::collections::{BTreeMap, VecDeque};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use lethe_crypto::ratchet::{Ratchet, RatchetMessage};
use lethe_crypto::x3dh::InviterKeys;
use lethe_crypto::{DhKeyPair, SigningKeyPair};
use lethe_proto::{QueueId, RelayAddr};
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

pub const INVITE_PREFIX: &str = "lethe://inv#";
const INVITE_VERSION: u16 = 1;

/// Where to send messages: a relay and a queue's sender ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueAddr {
    pub relay: RelayAddr,
    pub sender_id: QueueId,
}

/// One-time invitation. The link's data sits in the URL fragment, so even if it's
/// opened in a browser it is never sent to a web server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invitation {
    pub version: u16,
    pub queue: QueueAddr,
    pub ik: [u8; 32],
    pub ek: [u8; 32],
}

impl Invitation {
    pub fn to_link(&self) -> String {
        format!("{INVITE_PREFIX}{}", B64.encode(lethe_proto::to_bytes(self)))
    }

    pub fn from_link(link: &str) -> Result<Self> {
        let data = link.trim().strip_prefix(INVITE_PREFIX).ok_or(ClientError::InvalidLink)?;
        let bytes = B64.decode(data).map_err(|_| ClientError::InvalidLink)?;
        let inv: Self = lethe_proto::from_bytes(&bytes).map_err(|_| ClientError::InvalidLink)?;
        if inv.version != INVITE_VERSION {
            return Err(ClientError::InvalidLink);
        }
        Ok(inv)
    }

    pub(crate) fn new(queue: QueueAddr, ik: [u8; 32], ek: [u8; 32]) -> Self {
        Self { version: INVITE_VERSION, queue, ik, ek }
    }
}

/// Body of a `SEND`, as the recipient sees it after removing the relay layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Envelope {
    /// First message on an invitation queue: the joiner's X3DH keys plus a ratchet message.
    Confirmation { ik: [u8; 32], ek: [u8; 32], msg: RatchetMessage },
    Message(RatchetMessage),
}

/// Plaintext inside the ratchet, padded to `E2E_BLOCK` before encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum AppMsg {
    /// Connection setup: the key the peer should `KEY` onto its queue, and (from the
    /// joiner) the queue to reply on. `profile_name` is optional and per-contact.
    ConnInfo { sender_key: [u8; 32], reply_queue: Option<QueueAddr>, profile_name: Option<String> },
    Text { text: String, sent_at: u64 },
    /// The peer deleted this contact.
    Leave,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RcvQueue {
    pub relay: RelayAddr,
    pub recipient_id: QueueId,
    pub sender_id: QueueId,
    pub auth: SigningKeyPair,
    pub dh: DhKeyPair,
    pub server_dh: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SndQueue {
    pub addr: QueueAddr,
    pub auth: SigningKeyPair,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OutboxEntry {
    pub seq: u64,
    pub body: Vec<u8>,
    pub item_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactStatus {
    /// We created an invitation and are waiting for someone to use it.
    Invited,
    /// We used an invitation and are waiting for the inviter to confirm.
    Joining,
    Ready,
    /// The contact deleted the conversation.
    Left,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemStatus {
    /// Encrypted and waiting in the outbox.
    Pending,
    /// Accepted by the contact's relay.
    Sent,
    Failed,
    Received,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatItem {
    pub id: u64,
    pub direction: Direction,
    pub text: String,
    /// Unix seconds. For received items, the sender's claimed time.
    pub ts: u64,
    pub status: ItemStatus,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Contact {
    pub id: u64,
    pub alias: Option<String>,
    pub peer_name: Option<String>,
    pub my_profile_name: Option<String>,
    pub status: ContactStatus,
    pub rcv: RcvQueue,
    pub snd: Option<SndQueue>,
    pub invite_keys: Option<InviterKeys>,
    pub ratchet: Option<Ratchet>,
    pub outbox: VecDeque<OutboxEntry>,
    pub items: Vec<ChatItem>,
    pub created_at: u64,
}

impl Contact {
    pub fn display_name(&self) -> String {
        self.alias
            .clone()
            .or_else(|| self.peer_name.clone())
            .unwrap_or_else(|| format!("contact #{}", self.id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactInfo {
    pub id: u64,
    pub name: String,
    pub status: ContactStatus,
    pub last_item: Option<ChatItem>,
    pub relay: RelayAddr,
}

impl From<&Contact> for ContactInfo {
    fn from(c: &Contact) -> Self {
        Self { id: c.id, name: c.display_name(), status: c.status, last_item: c.items.last().cloned(), relay: c.rcv.relay.clone() }
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub contacts: BTreeMap<u64, Contact>,
    pub next_id: u64,
}

impl State {
    pub fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_link_roundtrip() {
        let relay = RelayAddr { host: "relay.example".into(), port: 5223, fingerprint: [3; 32] };
        let inv = Invitation::new(QueueAddr { relay, sender_id: [4; 24] }, [5; 32], [6; 32]);
        let link = inv.to_link();
        assert!(link.starts_with(INVITE_PREFIX));
        assert_eq!(Invitation::from_link(&link).unwrap(), inv);
        assert!(Invitation::from_link("lethe://inv#garbage!").is_err());
        assert!(Invitation::from_link("https://example.com").is_err());
    }
}
