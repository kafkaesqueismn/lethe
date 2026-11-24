//! Persistent client state and the messages carried inside queues.
//!
//! Stored state is CBOR (self-describing), and every field added after v0.1 carries
//! `#[serde(default)]`, so new versions can open profiles written by older ones.

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
/// Bytes of file data per chunk message (fits in one padded E2E block with framing).
pub const CHUNK_SIZE: usize = 15_000;
/// Largest file that can be sent.
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
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
    /// `id` is the sender's item id; receipts and deletes refer to it.
    Text { id: u64, text: String, sent_at: u64, ttl: Option<u32> },
    /// The peer deleted this contact.
    Leave,
    /// The peer's device got (`read == false`) or showed (`read == true`) our items `ids`.
    Receipt { ids: Vec<u64>, read: bool },
    /// Delete-for-everyone of the sender's own items `ids`.
    Delete { ids: Vec<u64> },
    /// Disappearing-messages timer for this conversation, in seconds (`None` = off).
    SetTimer { ttl: Option<u32> },
    /// File announcement; `chunks` `Chunk` messages with the data follow in order.
    File { id: u64, name: String, mime: String, size: u64, chunks: u32, sha256: [u8; 32], caption: String, sent_at: u64, ttl: Option<u32> },
    Chunk { file_id: u64, index: u32, data: Vec<u8> },
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
pub(crate) enum Payload {
    /// Already ratchet-encrypted and persisted; safe to (re)send as is.
    Sealed(Vec<u8>),
    /// A file chunk that is encrypted only when it reaches the front of the outbox,
    /// so a 10 MB file doesn't sit in the store as hundreds of sealed blocks.
    Chunk { index: u32, total: u32 },
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OutboxEntry {
    pub seq: u64,
    pub payload: Payload,
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
    /// The contact's device received it.
    Delivered,
    /// The contact opened the conversation and saw it (if they share read receipts).
    Read,
}

impl ItemStatus {
    /// Ordering for sent items, so a late "delivered" never downgrades "read".
    pub(crate) fn rank(self) -> u8 {
        match self {
            ItemStatus::Failed => 0,
            ItemStatus::Pending => 1,
            ItemStatus::Sent => 2,
            ItemStatus::Delivered => 3,
            ItemStatus::Read => 4,
            ItemStatus::Received => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileState {
    Transferring,
    Ready,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub chunks: u32,
    /// Chunks sent or received so far.
    pub done: u32,
    pub state: FileState,
    #[serde(default)]
    pub sha256: [u8; 32],
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
    /// For received items: the sender's id for it (receipts/deletes refer to this).
    #[serde(default)]
    pub remote_id: Option<u64>,
    /// Disappearing messages: Unix time when it erases itself.
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub attachment: Option<Attachment>,
    /// A notice in the conversation ("disappearing messages turned on") rather than a message.
    #[serde(default)]
    pub system: bool,
    /// For received items: whether you've seen it.
    #[serde(default)]
    pub read: bool,
}

impl ChatItem {
    pub(crate) fn new(id: u64, direction: Direction, text: String, ts: u64, status: ItemStatus) -> Self {
        Self { id, direction, text, ts, status, remote_id: None, expires_at: None, attachment: None, system: false, read: direction == Direction::Sent }
    }

    pub(crate) fn notice(id: u64, text: String) -> Self {
        Self { system: true, read: true, ..Self::new(id, Direction::Received, text, now(), ItemStatus::Received) }
    }
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Human wording for a timer, used in conversation notices.
pub(crate) fn describe_ttl(ttl: Option<u32>) -> String {
    match ttl {
        None => "off".into(),
        Some(s) if s % 86_400 == 0 => plural(s / 86_400, "day"),
        Some(s) if s % 3_600 == 0 => plural(s / 3_600, "hour"),
        Some(s) if s % 60 == 0 => plural(s / 60, "minute"),
        Some(s) => plural(s, "second"),
    }
}

fn plural(n: u32, unit: &str) -> String {
    if n == 1 { format!("1 {unit}") } else { format!("{n} {unit}s") }
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
    /// Disappearing-messages timer (seconds) agreed for this conversation.
    #[serde(default)]
    pub timer: Option<u32>,
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
    pub unread: u32,
    pub timer: Option<u32>,
    pub created_at: u64,
}

impl From<&Contact> for ContactInfo {
    fn from(c: &Contact) -> Self {
        Self {
            id: c.id,
            name: c.display_name(),
            status: c.status,
            last_item: c.items.iter().rev().find(|i| !i.system).or(c.items.last()).cloned(),
            relay: c.rcv.relay.clone(),
            unread: c.items.iter().filter(|i| !i.read && !i.system).count() as u32,
            timer: c.timer,
            created_at: c.created_at,
        }
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
