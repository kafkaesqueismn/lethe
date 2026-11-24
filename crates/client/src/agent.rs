//! The agent: owns state, relay connections and the connection/message state machine.
//!
//! Invariants that matter for security:
//! * Ratchet output is persisted (as an outbox entry) **before** it's sent, so a crash or
//!   retry never encrypts two different plaintexts under the same message key. File
//!   chunks are encrypted only when they reach the front of the outbox, and persisted
//!   the same way before sending.
//! * Incoming messages are processed on a copy of the contact and committed only on
//!   success. Transient failures leave the message unacknowledged, so the relay
//!   redelivers it; permanent failures (forgery, garbage) are acknowledged and dropped.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use lethe_crypto::pad::{pad, unpad};
use lethe_crypto::ratchet::{Ratchet, RatchetMessage};
use lethe_crypto::x3dh::{self, InviterKeys};
use lethe_crypto::{DhKeyPair, SigningKeyPair};
use lethe_proto::{delivery, Command, MsgId, QueueId, RelayAddr, Response, E2E_BLOCK};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, Mutex};

use crate::error::{ClientError, Result};
use crate::model::*;
use crate::store::Store;
use crate::transport::{Push, RelayConn};

pub enum StoreLocation {
    /// Nothing touches disk (tests, or a deliberately ephemeral profile).
    Memory,
    File { path: PathBuf, passphrase: String },
}

pub struct AgentConfig {
    pub store: StoreLocation,
    /// SOCKS5 proxy for all relay connections, e.g. Tor at `127.0.0.1:9050`.
    pub socks_proxy: Option<SocketAddr>,
    /// Cheap Argon2 parameters for new stores. Only for tests.
    pub fast_kdf_for_tests: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Event {
    ContactConnected { contact_id: u64 },
    /// A new item in a conversation (a message, a file, or a notice).
    Message { contact_id: u64, item: ChatItem },
    ItemStatus { contact_id: u64, item_id: u64, status: ItemStatus },
    /// An existing item changed (file transfer progress or completion).
    ItemUpdated { contact_id: u64, item: ChatItem },
    /// Items disappeared (timer, or deleted by you or the sender).
    ItemsRemoved { contact_id: u64, ids: Vec<u64> },
    /// Contact details changed (timer, unread count, name).
    ContactUpdated { contact_id: u64 },
    ContactLeft { contact_id: u64 },
    RelayConnected { relay: RelayAddr },
    RelayDisconnected { relay: RelayAddr },
    Error { contact_id: Option<u64>, message: String },
}

struct Runtime {
    state: State,
    store: Store,
    /// Contacts whose outbox is currently being flushed.
    flushing: HashSet<u64>,
    /// Plaintext of files being sent, so each chunk doesn't re-read the whole file.
    sending: HashMap<u64, Arc<Vec<u8>>>,
}

struct Inner {
    rt: Mutex<Runtime>,
    conns: Mutex<HashMap<RelayAddr, Arc<RelayConn>>>,
    reconnecting: std::sync::Mutex<HashSet<RelayAddr>>,
    push_tx: mpsc::UnboundedSender<Push>,
    events: broadcast::Sender<Event>,
    proxy: Option<SocketAddr>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// Handle to a running agent. Cheap to clone.
#[derive(Clone)]
pub struct Agent {
    inner: Arc<Inner>,
}

/// An outbox entry ready to go on the wire.
struct Job {
    addr: QueueAddr,
    auth: SigningKeyPair,
    seq: u64,
    body: Vec<u8>,
    item_id: Option<u64>,
    chunk: Option<(u32, u32)>,
}

impl Agent {
    pub async fn start(config: AgentConfig) -> Result<Self> {
        let (store, state) = match config.store {
            StoreLocation::Memory => (Store::memory(), State::default()),
            StoreLocation::File { path, passphrase } => {
                let fast = config.fast_kdf_for_tests;
                tokio::task::spawn_blocking(move || Store::open(&path, &passphrase, fast))
                    .await
                    .map_err(|e| ClientError::Store(e.to_string()))??
            }
        };
        let (push_tx, push_rx) = mpsc::unbounded_channel();
        let (events, _) = broadcast::channel(1024);
        let inner = Arc::new(Inner {
            rt: Mutex::new(Runtime { state, store, flushing: HashSet::new(), sending: HashMap::new() }),
            conns: Mutex::new(HashMap::new()),
            reconnecting: Default::default(),
            push_tx,
            events,
            proxy: config.socks_proxy,
            tasks: Default::default(),
        });
        let push = tokio::spawn(push_loop(Arc::downgrade(&inner), push_rx));
        let sweep = tokio::spawn(sweep_loop(Arc::downgrade(&inner)));
        inner.tasks.lock().unwrap().extend([push, sweep]);

        inner.sweep_expired().await;
        for relay in inner.needed_relays().await {
            inner.spawn_bring_up(relay, Duration::ZERO);
        }
        Ok(Self { inner })
    }

    /// Stop background work and drop relay connections.
    pub async fn shutdown(&self) {
        for t in self.inner.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        self.inner.conns.lock().await.clear();
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// Create a one-time invitation on `relay`. Returns the new contact's id and the link.
    /// `profile_name` is what the contact will see; `None` reveals nothing.
    pub async fn create_invite(&self, relay: &RelayAddr, alias: Option<String>, profile_name: Option<String>) -> Result<(u64, String)> {
        let inner = &self.inner;
        let rcv = inner.create_queue(relay).await?;
        let keys = InviterKeys::generate();
        let (ik, ek) = keys.public();
        let link = Invitation::new(QueueAddr { relay: relay.clone(), sender_id: rcv.sender_id }, ik, ek).to_link();
        let (id, rid, auth) = {
            let mut rt = inner.rt.lock().await;
            let id = rt.state.next_id();
            let c = new_contact(id, alias, profile_name, ContactStatus::Invited, rcv.clone(), None, Some(keys), None);
            rt.state.contacts.insert(id, c);
            rt.store.save(&rt.state)?;
            (id, rcv.recipient_id, rcv.auth.clone())
        };
        inner.request(relay, rid, Command::Sub, Some(&auth)).await?;
        Ok((id, link))
    }

    /// Accept someone's invitation. Our reply queue is created on `my_relay`.
    pub async fn accept_invite(&self, link: &str, my_relay: &RelayAddr, alias: Option<String>, profile_name: Option<String>) -> Result<u64> {
        let inner = &self.inner;
        let inv = Invitation::from_link(link)?;
        let rcv = inner.create_queue(my_relay).await?;
        let ((ik_b, ek_b), mut ratchet) = x3dh::join(&inv.ik, &inv.ek)?;
        let snd = SndQueue { addr: inv.queue, auth: SigningKeyPair::generate() };
        let info = AppMsg::ConnInfo {
            sender_key: snd.auth.public(),
            reply_queue: Some(QueueAddr { relay: my_relay.clone(), sender_id: rcv.sender_id }),
            profile_name: profile_name.clone(),
        };
        let msg = seal_app(&mut ratchet, &info)?;

        let (id, rid, auth) = {
            let mut rt = inner.rt.lock().await;
            let id = rt.state.next_id();
            let mut c = new_contact(id, alias, profile_name, ContactStatus::Joining, rcv.clone(), Some(snd), None, Some(ratchet));
            enqueue_sealed(&mut c, &Envelope::Confirmation { ik: ik_b, ek: ek_b, msg }, None);
            rt.state.contacts.insert(id, c);
            rt.store.save(&rt.state)?;
            (id, rcv.recipient_id, rcv.auth.clone())
        };
        inner.request(my_relay, rid, Command::Sub, Some(&auth)).await?;
        inner.spawn_flush(id);
        Ok(id)
    }

    /// Encrypt and queue a text message. Delivery progress arrives as `Event::ItemStatus`.
    pub async fn send_text(&self, contact_id: u64, text: &str) -> Result<ChatItem> {
        let item = {
            let mut rt = self.inner.rt.lock().await;
            let id = rt.state.next_id();
            let c = rt.state.contacts.get_mut(&contact_id).ok_or(ClientError::NotFound)?;
            let ttl = c.timer;
            let ts = now();
            let msg = seal_app(sendable(c)?, &AppMsg::Text { id, text: text.to_string(), sent_at: ts, ttl })?;
            let mut item = ChatItem::new(id, Direction::Sent, text.to_string(), ts, ItemStatus::Pending);
            item.expires_at = ttl.map(|t| ts + t as u64);
            c.items.push(item.clone());
            enqueue_sealed(c, &Envelope::Message(msg), Some(id));
            rt.store.save(&rt.state)?;
            item
        };
        self.inner.spawn_flush(contact_id);
        Ok(item)
    }

    /// Send a file (up to 10 MB). It's stored encrypted locally and sent in chunks;
    /// progress arrives as `Event::ItemUpdated`.
    pub async fn send_file(&self, contact_id: u64, name: &str, mime: &str, data: Vec<u8>, caption: &str) -> Result<ChatItem> {
        let size = data.len() as u64;
        if size > MAX_FILE_SIZE {
            return Err(ClientError::FileTooLarge);
        }
        if size == 0 {
            return Err(ClientError::Protocol("empty file"));
        }
        let name = clean_file_name(name);
        let mime: String = mime.chars().filter(|c| c.is_ascii_graphic()).take(100).collect();
        let sha256: [u8; 32] = Sha256::digest(&data).into();
        let chunks = data.len().div_ceil(CHUNK_SIZE) as u32;

        let item = {
            let mut guard = self.inner.rt.lock().await;
            let rt = &mut *guard;
            let id = rt.state.next_id();
            let c = rt.state.contacts.get_mut(&contact_id).ok_or(ClientError::NotFound)?;
            let ttl = c.timer;
            let ts = now();
            let meta = AppMsg::File {
                id,
                name: name.clone(),
                mime: mime.clone(),
                size,
                chunks,
                sha256,
                caption: caption.to_string(),
                sent_at: ts,
                ttl,
            };
            let sealed = seal_app(sendable(c)?, &meta)?;
            rt.store.put_blob(&id.to_string(), &data)?;
            let mut item = ChatItem::new(id, Direction::Sent, caption.to_string(), ts, ItemStatus::Pending);
            item.expires_at = ttl.map(|t| ts + t as u64);
            item.attachment = Some(Attachment { name, mime, size, chunks, done: 0, state: FileState::Transferring, sha256 });
            c.items.push(item.clone());
            enqueue_sealed(c, &Envelope::Message(sealed), None);
            for index in 0..chunks {
                enqueue(c, Payload::Chunk { index, total: chunks }, Some(id));
            }
            rt.sending.insert(id, Arc::new(data));
            rt.store.save(&rt.state)?;
            item
        };
        self.inner.spawn_flush(contact_id);
        Ok(item)
    }

    /// Delete items from this device. With `for_everyone`, your own messages among them
    /// are also deleted on the contact's device.
    pub async fn delete_items(&self, contact_id: u64, ids: &[u64], for_everyone: bool) -> Result<()> {
        let mut flush = false;
        {
            let mut guard = self.inner.rt.lock().await;
            let rt = &mut *guard;
            let c = rt.state.contacts.get_mut(&contact_id).ok_or(ClientError::NotFound)?;
            let removed = remove_items(c, &mut rt.store, &mut rt.sending, |i| ids.contains(&i.id));
            if removed.is_empty() {
                return Ok(());
            }
            let mine: Vec<u64> = removed.iter().filter(|i| i.direction == Direction::Sent && !i.system).map(|i| i.id).collect();
            if for_everyone && !mine.is_empty()
                && let Ok(r) = sendable(c) {
                    let msg = seal_app(r, &AppMsg::Delete { ids: mine })?;
                    enqueue_sealed(c, &Envelope::Message(msg), None);
                    flush = true;
                }
            rt.store.save(&rt.state)?;
            self.inner.emit(Event::ItemsRemoved { contact_id, ids: removed.iter().map(|i| i.id).collect() });
            self.inner.emit(Event::ContactUpdated { contact_id });
        }
        if flush {
            self.inner.spawn_flush(contact_id);
        }
        Ok(())
    }

    /// Set the disappearing-messages timer for a conversation (both sides follow it).
    pub async fn set_timer(&self, contact_id: u64, ttl: Option<u32>) -> Result<()> {
        let notice = {
            let mut rt = self.inner.rt.lock().await;
            let id = rt.state.next_id();
            let c = rt.state.contacts.get_mut(&contact_id).ok_or(ClientError::NotFound)?;
            let msg = seal_app(sendable(c)?, &AppMsg::SetTimer { ttl })?;
            c.timer = ttl;
            enqueue_sealed(c, &Envelope::Message(msg), None);
            let text = match ttl {
                Some(_) => format!("You turned on disappearing messages: {}", describe_ttl(ttl)),
                None => "You turned off disappearing messages".to_string(),
            };
            let notice = ChatItem::notice(id, text);
            c.items.push(notice.clone());
            rt.store.save(&rt.state)?;
            notice
        };
        self.inner.emit(Event::Message { contact_id, item: notice });
        self.inner.emit(Event::ContactUpdated { contact_id });
        self.inner.spawn_flush(contact_id);
        Ok(())
    }

    /// Mark everything in a conversation as seen. With `send_receipt`, the contact is
    /// told (their messages get a "read" tick).
    pub async fn mark_read(&self, contact_id: u64, send_receipt: bool) -> Result<()> {
        let mut flush = false;
        {
            let mut rt = self.inner.rt.lock().await;
            let c = rt.state.contacts.get_mut(&contact_id).ok_or(ClientError::NotFound)?;
            let mut remote = vec![];
            for it in c.items.iter_mut().filter(|i| !i.read) {
                it.read = true;
                if let Some(r) = it.remote_id.filter(|_| !it.system) {
                    remote.push(r);
                }
            }
            if send_receipt && !remote.is_empty()
                && let Ok(r) = sendable(c) {
                    let msg = seal_app(r, &AppMsg::Receipt { ids: remote, read: true })?;
                    enqueue_sealed(c, &Envelope::Message(msg), None);
                    flush = true;
                }
            rt.store.save(&rt.state)?;
        }
        self.inner.emit(Event::ContactUpdated { contact_id });
        if flush {
            self.inner.spawn_flush(contact_id);
        }
        Ok(())
    }

    /// Decrypted contents of a completed attachment: `(name, mime, bytes)`.
    pub async fn file_data(&self, contact_id: u64, item_id: u64) -> Result<(String, String, Vec<u8>)> {
        let rt = self.inner.rt.lock().await;
        let c = rt.state.contacts.get(&contact_id).ok_or(ClientError::NotFound)?;
        let item = c.items.iter().find(|i| i.id == item_id).ok_or(ClientError::NotFound)?;
        let a = item.attachment.as_ref().filter(|a| a.state == FileState::Ready || item.direction == Direction::Sent).ok_or(ClientError::NotFound)?;
        let data = rt.store.get_blob(&item_id.to_string())?;
        Ok((a.name.clone(), a.mime.clone(), data))
    }

    /// A code both people see identically if nobody intercepted the invitation.
    /// Compare it in person or on a call. `None` until the connection is set up.
    pub async fn security_code(&self, contact_id: u64) -> Result<Option<String>> {
        let rt = self.inner.rt.lock().await;
        let c = rt.state.contacts.get(&contact_id).ok_or(ClientError::NotFound)?;
        Ok(c.ratchet.as_ref().map(|r| security_code(r.associated_data())))
    }

    /// Delete a contact: tell them (best effort), delete our queue at the relay, forget everything.
    pub async fn delete_contact(&self, contact_id: u64) -> Result<()> {
        let (c, leave) = {
            let mut guard = self.inner.rt.lock().await;
            let rt = &mut *guard;
            let mut c = rt.state.contacts.remove(&contact_id).ok_or(ClientError::NotFound)?;
            rt.flushing.remove(&contact_id);
            let all: Vec<ChatItem> = std::mem::take(&mut c.items);
            for it in &all {
                forget_files(&mut rt.store, &mut rt.sending, it);
            }
            rt.store.save(&rt.state)?;
            let leave = match (&c.snd, c.ratchet.as_mut()) {
                (Some(_), Some(r)) if r.can_send() && c.status == ContactStatus::Ready => {
                    seal_app(r, &AppMsg::Leave).ok().map(|m| lethe_proto::to_bytes(&Envelope::Message(m)))
                }
                _ => None,
            };
            (c, leave)
        };
        if let (Some(snd), Some(body)) = (&c.snd, leave) {
            let _ = self.inner.request(&snd.addr.relay, snd.addr.sender_id, Command::Send { body }, Some(&snd.auth)).await;
        }
        let _ = self.inner.request(&c.rcv.relay, c.rcv.recipient_id, Command::Del, Some(&c.rcv.auth)).await;
        Ok(())
    }

    pub async fn contacts(&self) -> Vec<ContactInfo> {
        self.inner.rt.lock().await.state.contacts.values().map(ContactInfo::from).collect()
    }

    pub async fn messages(&self, contact_id: u64) -> Result<Vec<ChatItem>> {
        let rt = self.inner.rt.lock().await;
        Ok(rt.state.contacts.get(&contact_id).ok_or(ClientError::NotFound)?.items.clone())
    }

    /// The invitation link of a contact still in `Invited` state (to show the QR again).
    pub async fn invite_link(&self, contact_id: u64) -> Result<String> {
        let rt = self.inner.rt.lock().await;
        let c = rt.state.contacts.get(&contact_id).ok_or(ClientError::NotFound)?;
        let keys = c.invite_keys.as_ref().ok_or(ClientError::NotFound)?;
        let (ik, ek) = keys.public();
        Ok(Invitation::new(QueueAddr { relay: c.rcv.relay.clone(), sender_id: c.rcv.sender_id }, ik, ek).to_link())
    }

    pub async fn rename_contact(&self, contact_id: u64, alias: Option<String>) -> Result<()> {
        {
            let mut rt = self.inner.rt.lock().await;
            rt.state.contacts.get_mut(&contact_id).ok_or(ClientError::NotFound)?.alias = alias;
            rt.store.save(&rt.state)?;
        }
        self.inner.emit(Event::ContactUpdated { contact_id });
        Ok(())
    }
}

impl Inner {
    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    async fn conn(&self, relay: &RelayAddr) -> Result<Arc<RelayConn>> {
        let mut conns = self.conns.lock().await;
        if let Some(c) = conns.get(relay).filter(|c| !c.is_closed()) {
            return Ok(c.clone());
        }
        let c = RelayConn::connect(relay.clone(), self.proxy, self.push_tx.clone()).await?;
        conns.insert(relay.clone(), c.clone());
        Ok(c)
    }

    async fn request(&self, relay: &RelayAddr, entity: QueueId, cmd: Command, key: Option<&SigningKeyPair>) -> Result<Response> {
        self.conn(relay).await?.request(entity, cmd, key).await
    }

    async fn create_queue(&self, relay: &RelayAddr) -> Result<RcvQueue> {
        let auth = SigningKeyPair::generate();
        let dh = DhKeyPair::generate();
        let cmd = Command::New { recipient_key: auth.public(), recipient_dh: dh.public() };
        match self.request(relay, [0; 24], cmd, Some(&auth)).await? {
            Response::Ids { recipient_id, sender_id, server_dh } => {
                Ok(RcvQueue { relay: relay.clone(), recipient_id, sender_id, auth, dh, server_dh })
            }
            _ => Err(ClientError::Protocol("unexpected reply to NEW")),
        }
    }

    /// Relays we must stay connected to: where our receive queues live, or where an outbox is waiting.
    async fn needed_relays(&self) -> HashSet<RelayAddr> {
        let rt = self.rt.lock().await;
        let mut out = HashSet::new();
        for c in rt.state.contacts.values() {
            if c.status != ContactStatus::Left {
                out.insert(c.rcv.relay.clone());
            }
            if let (Some(s), false) = (&c.snd, c.outbox.is_empty()) {
                out.insert(s.addr.relay.clone());
            }
        }
        out
    }

    /// (Re)connect to a relay with exponential backoff, resubscribe, and flush outboxes.
    fn spawn_bring_up(self: &Arc<Self>, relay: RelayAddr, initial_delay: Duration) {
        if !self.reconnecting.lock().unwrap().insert(relay.clone()) {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut delay = initial_delay;
            loop {
                tokio::time::sleep(delay).await;
                let Some(inner) = weak.upgrade() else { return };
                if !inner.needed_relays().await.contains(&relay) {
                    break;
                }
                match inner.resync(&relay).await {
                    Ok(()) => break,
                    Err(_) => delay = (delay * 2).clamp(Duration::from_secs(1), Duration::from_secs(60)),
                }
            }
            if let Some(inner) = weak.upgrade() {
                inner.reconnecting.lock().unwrap().remove(&relay);
            }
        });
    }

    async fn resync(self: &Arc<Self>, relay: &RelayAddr) -> Result<()> {
        let conn = self.conn(relay).await?;
        let (subs, flush): (Vec<(u64, QueueId, SigningKeyPair)>, Vec<u64>) = {
            let rt = self.rt.lock().await;
            let cs = rt.state.contacts.values();
            (
                cs.clone()
                    .filter(|c| &c.rcv.relay == relay && c.status != ContactStatus::Left)
                    .map(|c| (c.id, c.rcv.recipient_id, c.rcv.auth.clone()))
                    .collect(),
                cs.filter(|c| c.snd.as_ref().is_some_and(|s| &s.addr.relay == relay) && !c.outbox.is_empty())
                    .map(|c| c.id)
                    .collect(),
            )
        };
        for (cid, rid, auth) in subs {
            match conn.request(rid, Command::Sub, Some(&auth)).await {
                Ok(_) => {}
                Err(e) if e.is_transient() => return Err(e),
                Err(e) => self.emit(Event::Error { contact_id: Some(cid), message: format!("subscription failed: {e}") }),
            }
        }
        self.emit(Event::RelayConnected { relay: relay.clone() });
        for cid in flush {
            self.spawn_flush(cid);
        }
        Ok(())
    }

    fn spawn_flush(self: &Arc<Self>, contact_id: u64) {
        tokio::spawn(self.clone().flush(contact_id));
    }

    /// Take the front of a contact's outbox, sealing a pending file chunk first (and
    /// persisting that before it can be sent).
    fn prepare_next(rt: &mut Runtime, cid: u64) -> Result<Option<Job>> {
        let Some(c) = rt.state.contacts.get_mut(&cid) else { return Ok(None) };
        let Some(snd) = c.snd.clone() else { return Ok(None) };
        let Some(front) = c.outbox.front().cloned() else { return Ok(None) };
        let mut chunk = None;
        let body = match front.payload {
            Payload::Sealed(b) => b,
            Payload::Chunk { index, total } => {
                let item_id = front.item_id.ok_or(ClientError::Protocol("chunk without file"))?;
                let data = match rt.sending.get(&item_id) {
                    Some(d) => d.clone(),
                    None => {
                        let d = Arc::new(rt.store.get_blob(&item_id.to_string())?);
                        rt.sending.insert(item_id, d.clone());
                        d
                    }
                };
                let start = index as usize * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(data.len());
                let slice = data.get(start..end).ok_or(ClientError::Protocol("chunk out of range"))?;
                let ratchet = c.ratchet.as_mut().ok_or(ClientError::NotReady)?;
                let sealed = seal_app(ratchet, &AppMsg::Chunk { file_id: item_id, index, data: slice.to_vec() })?;
                let body = lethe_proto::to_bytes(&Envelope::Message(sealed));
                c.outbox.front_mut().expect("front exists").payload = Payload::Sealed(body.clone());
                chunk = Some((index, total));
                body
            }
        };
        if chunk.is_some() {
            rt.store.save(&rt.state)?;
        }
        Ok(Some(Job { addr: snd.addr, auth: snd.auth, seq: front.seq, body, item_id: front.item_id, chunk }))
    }

    /// Send a contact's outbox in order. Only one flusher per contact runs at a time.
    async fn flush(self: Arc<Self>, cid: u64) {
        if !self.rt.lock().await.flushing.insert(cid) {
            return;
        }
        loop {
            let next = {
                let mut guard = self.rt.lock().await;
                let rt = &mut *guard;
                match Self::prepare_next(rt, cid) {
                    Ok(Some(job)) => Some(job),
                    Ok(None) => {
                        rt.flushing.remove(&cid);
                        None
                    }
                    Err(e) => {
                        rt.flushing.remove(&cid);
                        self.emit(Event::Error { contact_id: Some(cid), message: format!("couldn't prepare message: {e}") });
                        None
                    }
                }
            };
            let Some(job) = next else { return };

            let res = self.request(&job.addr.relay, job.addr.sender_id, Command::Send { body: job.body }, Some(&job.auth)).await;
            if matches!(&res, Err(e) if e.is_transient()) {
                self.rt.lock().await.flushing.remove(&cid);
                // Retry after a pause; bring-up resyncs and flushes again once reachable.
                self.spawn_bring_up(job.addr.relay, Duration::from_secs(2));
                return;
            }
            let mut guard = self.rt.lock().await;
            let rt = &mut *guard;
            let Some(c) = rt.state.contacts.get_mut(&cid) else {
                rt.flushing.remove(&cid);
                return;
            };
            if c.outbox.front().is_some_and(|e| e.seq == job.seq) {
                c.outbox.pop_front();
            }
            let mut events = vec![];
            if let Some(item_id) = job.item_id {
                let ok = res.is_ok();
                if !ok {
                    // Drop the rest of a failed file.
                    c.outbox.retain(|e| !(e.item_id == Some(item_id) && matches!(e.payload, Payload::Chunk { .. })));
                    rt.sending.remove(&item_id);
                }
                if let Some(it) = c.items.iter_mut().find(|i| i.id == item_id) {
                    match (job.chunk, it.attachment.as_mut()) {
                        (Some((index, total)), Some(a)) => {
                            a.done = index + 1;
                            let finished = a.done == total;
                            if !ok {
                                a.state = FileState::Failed;
                                it.status = ItemStatus::Failed;
                            } else if finished {
                                a.state = FileState::Ready;
                                if ItemStatus::Sent.rank() > it.status.rank() {
                                    it.status = ItemStatus::Sent;
                                }
                                rt.sending.remove(&item_id);
                            }
                            if !ok || finished || a.done % 8 == 0 {
                                events.push(Event::ItemUpdated { contact_id: cid, item: it.clone() });
                            }
                        }
                        _ => {
                            let status = if ok { ItemStatus::Sent } else { ItemStatus::Failed };
                            if !ok || status.rank() > it.status.rank() {
                                it.status = status;
                                events.push(Event::ItemStatus { contact_id: cid, item_id, status });
                            }
                        }
                    }
                }
            }
            if let Err(e) = res {
                events.push(Event::Error { contact_id: Some(cid), message: format!("message not delivered: {e}") });
            }
            if let Err(e) = rt.store.save(&rt.state) {
                events.push(Event::Error { contact_id: None, message: e.to_string() });
            }
            drop(guard);
            for e in events {
                self.emit(e);
            }
        }
    }

    async fn handle_msg(self: &Arc<Self>, relay: RelayAddr, rid: QueueId, msg_id: MsgId, ts: u64, body: Vec<u8>) {
        let (cid, auth) = {
            let rt = self.rt.lock().await;
            match rt.state.contacts.values().find(|c| c.rcv.relay == relay && c.rcv.recipient_id == rid) {
                Some(c) => (c.id, c.rcv.auth.clone()),
                None => return, // deleted contact; the relay forgets the queue on DEL
            }
        };
        let ack = match self.process_incoming(cid, msg_id, ts, &body).await {
            Ok(()) => true,
            Err(e) if e.is_transient() => false,
            Err(e) => {
                self.emit(Event::Error { contact_id: Some(cid), message: format!("dropped undecryptable message: {e}") });
                true
            }
        };
        if ack {
            let _ = self.request(&relay, rid, Command::Ack { msg_id }, Some(&auth)).await;
        }
    }

    async fn process_incoming(self: &Arc<Self>, cid: u64, msg_id: MsgId, ts: u64, body: &[u8]) -> Result<()> {
        let mut guard = self.rt.lock().await;
        let rt = &mut *guard;
        let Some(mut c) = rt.state.contacts.get(&cid).cloned() else { return Ok(()) };
        let key = delivery::key(&c.rcv.dh.dh(&c.rcv.server_dh)?);
        let env_bytes = delivery::open_body(&key, &msg_id, ts, body)?;
        let env: Envelope = lethe_proto::from_bytes(&env_bytes).map_err(|_| ClientError::Protocol("bad envelope"))?;

        let mut events = vec![];
        let mut flush = false;
        // Sender ids to acknowledge with a "delivered" receipt.
        let mut delivered: Vec<u64> = vec![];
        match env {
            Envelope::Confirmation { ik, ek, msg } => {
                // One-time link: anything after the first confirmation is ignored.
                let Some(keys) = c.invite_keys.take().filter(|_| c.status == ContactStatus::Invited) else { return Ok(()) };
                let mut ratchet = keys.accept(&ik, &ek)?;
                let AppMsg::ConnInfo { sender_key, reply_queue: Some(reply), profile_name } = open_app(&mut ratchet, &msg)? else {
                    return Err(ClientError::Protocol("expected connection info"));
                };
                self.request(&c.rcv.relay, c.rcv.recipient_id, Command::Key { sender_key }, Some(&c.rcv.auth)).await?;
                let snd = SndQueue { addr: reply, auth: SigningKeyPair::generate() };
                let info = AppMsg::ConnInfo { sender_key: snd.auth.public(), reply_queue: None, profile_name: c.my_profile_name.clone() };
                let reply_msg = seal_app(&mut ratchet, &info)?;
                c.peer_name = profile_name;
                c.status = ContactStatus::Ready;
                c.snd = Some(snd);
                c.ratchet = Some(ratchet);
                enqueue_sealed(&mut c, &Envelope::Message(reply_msg), None);
                flush = true;
                events.push(Event::ContactConnected { contact_id: cid });
            }
            Envelope::Message(msg) => {
                let ratchet = c.ratchet.as_mut().ok_or(ClientError::Protocol("no session"))?;
                match open_app(ratchet, &msg)? {
                    AppMsg::ConnInfo { sender_key, profile_name, .. } if c.status == ContactStatus::Joining => {
                        self.request(&c.rcv.relay, c.rcv.recipient_id, Command::Key { sender_key }, Some(&c.rcv.auth)).await?;
                        c.peer_name = profile_name;
                        c.status = ContactStatus::Ready;
                        events.push(Event::ContactConnected { contact_id: cid });
                    }
                    AppMsg::ConnInfo { .. } => {}
                    AppMsg::Text { id, text, sent_at, ttl } => {
                        if !c.items.iter().any(|i| i.remote_id == Some(id)) {
                            let mut item = ChatItem::new(rt.state.next_id(), Direction::Received, text, sent_at, ItemStatus::Received);
                            item.remote_id = Some(id);
                            item.expires_at = ttl.map(|t| now() + t as u64);
                            c.items.push(item.clone());
                            events.push(Event::Message { contact_id: cid, item });
                        }
                        delivered.push(id);
                    }
                    AppMsg::Receipt { ids, read } => {
                        let status = if read { ItemStatus::Read } else { ItemStatus::Delivered };
                        for it in c.items.iter_mut().filter(|i| i.direction == Direction::Sent && ids.contains(&i.id)) {
                            if status.rank() > it.status.rank() {
                                it.status = status;
                                events.push(Event::ItemStatus { contact_id: cid, item_id: it.id, status });
                            }
                        }
                    }
                    AppMsg::Delete { ids } => {
                        let removed = remove_items(&mut c, &mut rt.store, &mut rt.sending, |i| {
                            i.direction == Direction::Received && i.remote_id.is_some_and(|r| ids.contains(&r))
                        });
                        if !removed.is_empty() {
                            events.push(Event::ItemsRemoved { contact_id: cid, ids: removed.iter().map(|i| i.id).collect() });
                        }
                    }
                    AppMsg::SetTimer { ttl } => {
                        c.timer = ttl;
                        let who = c.display_name();
                        let text = match ttl {
                            Some(_) => format!("{who} turned on disappearing messages: {}", describe_ttl(ttl)),
                            None => format!("{who} turned off disappearing messages"),
                        };
                        let notice = ChatItem::notice(rt.state.next_id(), text);
                        c.items.push(notice.clone());
                        events.push(Event::Message { contact_id: cid, item: notice });
                        events.push(Event::ContactUpdated { contact_id: cid });
                    }
                    AppMsg::File { id, name, mime, size, chunks, sha256, caption, sent_at, ttl } => {
                        let expected = (size as usize).div_ceil(CHUNK_SIZE) as u32;
                        if size == 0 || size > MAX_FILE_SIZE || chunks != expected {
                            return Err(ClientError::Protocol("invalid file announcement"));
                        }
                        if !c.items.iter().any(|i| i.remote_id == Some(id)) {
                            let mut item = ChatItem::new(rt.state.next_id(), Direction::Received, caption, sent_at, ItemStatus::Received);
                            item.remote_id = Some(id);
                            item.expires_at = ttl.map(|t| now() + t as u64);
                            item.attachment = Some(Attachment {
                                name: clean_file_name(&name),
                                mime: mime.chars().filter(|c| c.is_ascii_graphic()).take(100).collect(),
                                size,
                                chunks,
                                done: 0,
                                state: FileState::Transferring,
                                sha256,
                            });
                            c.items.push(item.clone());
                            events.push(Event::Message { contact_id: cid, item });
                        }
                    }
                    AppMsg::Chunk { file_id, index, data } => {
                        let Some(it) = c.items.iter_mut().find(|i| {
                            i.direction == Direction::Received
                                && i.remote_id == Some(file_id)
                                && i.attachment.as_ref().is_some_and(|a| a.state == FileState::Transferring)
                        }) else {
                            return Ok(()); // deleted, expired, or a duplicate after completion
                        };
                        let a = it.attachment.as_mut().expect("checked");
                        if index == a.done && data.len() <= CHUNK_SIZE {
                            rt.store.put_blob(&format!("{}.{}", it.id, index), &data)?;
                            a.done += 1;
                            if a.done == a.chunks {
                                a.state = match assemble_file(&mut rt.store, it.id, a) {
                                    Ok(()) => FileState::Ready,
                                    Err(_) => FileState::Failed,
                                };
                                delivered.push(file_id);
                            }
                            if a.done == a.chunks || a.done % 8 == 0 {
                                events.push(Event::ItemUpdated { contact_id: cid, item: it.clone() });
                            }
                        }
                    }
                    AppMsg::Leave => {
                        c.status = ContactStatus::Left;
                        c.outbox.clear();
                        events.push(Event::ContactLeft { contact_id: cid });
                    }
                }
            }
        }
        if !delivered.is_empty() && c.snd.is_some()
            && let Some(r) = c.ratchet.as_mut().filter(|r| r.can_send()) {
                let msg = seal_app(r, &AppMsg::Receipt { ids: delivered, read: false })?;
                enqueue_sealed(&mut c, &Envelope::Message(msg), None);
                flush = true;
            }
        rt.state.contacts.insert(cid, c);
        rt.store.save(&rt.state)?;
        drop(guard);
        for e in events {
            self.emit(e);
        }
        if flush {
            self.spawn_flush(cid);
        }
        Ok(())
    }

    /// Erase items whose disappearing-messages timer ran out.
    async fn sweep_expired(&self) {
        let now = now();
        let mut removed_by_contact = vec![];
        {
            let mut guard = self.rt.lock().await;
            let rt = &mut *guard;
            for c in rt.state.contacts.values_mut() {
                let removed = remove_items(c, &mut rt.store, &mut rt.sending, |i| i.expires_at.is_some_and(|e| e <= now));
                if !removed.is_empty() {
                    removed_by_contact.push((c.id, removed.iter().map(|i| i.id).collect::<Vec<_>>()));
                }
            }
            if !removed_by_contact.is_empty()
                && let Err(e) = rt.store.save(&rt.state) {
                    self.emit(Event::Error { contact_id: None, message: e.to_string() });
                }
        }
        for (contact_id, ids) in removed_by_contact {
            self.emit(Event::ItemsRemoved { contact_id, ids });
            self.emit(Event::ContactUpdated { contact_id });
        }
    }
}

async fn push_loop(weak: Weak<Inner>, mut rx: mpsc::UnboundedReceiver<Push>) {
    while let Some(p) = rx.recv().await {
        let Some(inner) = weak.upgrade() else { return };
        match p {
            Push::Msg { relay, rid, msg_id, ts, body } => inner.handle_msg(relay, rid, msg_id, ts, body).await,
            Push::End { relay, rid } => {
                let contact_id = inner.rt.lock().await.state.contacts.values()
                    .find(|c| c.rcv.relay == relay && c.rcv.recipient_id == rid)
                    .map(|c| c.id);
                inner.emit(Event::Error {
                    contact_id,
                    message: "this conversation was opened on another device; it no longer receives here".into(),
                });
            }
            Push::Disconnected { relay } => {
                inner.conns.lock().await.retain(|k, c| k != &relay || !c.is_closed());
                inner.emit(Event::RelayDisconnected { relay: relay.clone() });
                inner.spawn_bring_up(relay, Duration::from_secs(1));
            }
        }
    }
}

async fn sweep_loop(weak: Weak<Inner>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Some(inner) = weak.upgrade() else { return };
        inner.sweep_expired().await;
    }
}

#[allow(clippy::too_many_arguments)]
fn new_contact(
    id: u64,
    alias: Option<String>,
    my_profile_name: Option<String>,
    status: ContactStatus,
    rcv: RcvQueue,
    snd: Option<SndQueue>,
    invite_keys: Option<InviterKeys>,
    ratchet: Option<Ratchet>,
) -> Contact {
    Contact {
        id,
        alias,
        peer_name: None,
        my_profile_name,
        status,
        rcv,
        snd,
        invite_keys,
        ratchet,
        outbox: Default::default(),
        items: vec![],
        created_at: now(),
        timer: None,
    }
}

/// The ratchet, if this contact can be sent to right now.
fn sendable(c: &mut Contact) -> Result<&mut Ratchet> {
    if !matches!(c.status, ContactStatus::Ready | ContactStatus::Joining) || c.snd.is_none() {
        return Err(ClientError::NotReady);
    }
    c.ratchet.as_mut().filter(|r| r.can_send()).ok_or(ClientError::NotReady)
}

fn enqueue(c: &mut Contact, payload: Payload, item_id: Option<u64>) {
    let seq = c.outbox.back().map_or(1, |e| e.seq + 1);
    c.outbox.push_back(OutboxEntry { seq, payload, item_id });
}

fn enqueue_sealed(c: &mut Contact, env: &Envelope, item_id: Option<u64>) {
    enqueue(c, Payload::Sealed(lethe_proto::to_bytes(env)), item_id);
}

/// Remove matching items, their files, and any unsent chunks of them.
fn remove_items(
    c: &mut Contact,
    store: &mut Store,
    sending: &mut HashMap<u64, Arc<Vec<u8>>>,
    pred: impl Fn(&ChatItem) -> bool,
) -> Vec<ChatItem> {
    let (removed, kept): (Vec<ChatItem>, Vec<ChatItem>) = c.items.drain(..).partition(|i| pred(i));
    c.items = kept;
    for it in &removed {
        forget_files(store, sending, it);
        if it.attachment.is_some() {
            c.outbox.retain(|e| !(e.item_id == Some(it.id) && matches!(e.payload, Payload::Chunk { .. })));
        }
    }
    removed
}

fn forget_files(store: &mut Store, sending: &mut HashMap<u64, Arc<Vec<u8>>>, it: &ChatItem) {
    if let Some(a) = &it.attachment {
        store.delete_blob(&it.id.to_string());
        for i in 0..a.done {
            store.delete_blob(&format!("{}.{}", it.id, i));
        }
        sending.remove(&it.id);
    }
}

/// Join received chunks into the final file and check it against the announced hash.
fn assemble_file(store: &mut Store, item_id: u64, a: &Attachment) -> Result<()> {
    let mut data = Vec::with_capacity(a.size as usize);
    for i in 0..a.chunks {
        data.extend(store.get_blob(&format!("{item_id}.{i}"))?);
    }
    for i in 0..a.chunks {
        store.delete_blob(&format!("{item_id}.{i}"));
    }
    let hash: [u8; 32] = Sha256::digest(&data).into();
    if data.len() as u64 != a.size || hash != a.sha256 {
        return Err(ClientError::Protocol("file doesn't match its announced hash"));
    }
    store.put_blob(&item_id.to_string(), &data)
}

/// Keep only a plain file name: no directories, no control characters, sane length.
fn clean_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base.chars().filter(|c| !c.is_control()).take(120).collect();
    let cleaned = cleaned.trim().trim_start_matches('.').to_string();
    if cleaned.is_empty() { "file".into() } else { cleaned }
}

/// 30 digits in six groups, derived from both sides' handshake identity keys.
fn security_code(ad: &[u8]) -> String {
    let h = Sha256::digest([b"lethe security code v1".as_slice(), ad].concat());
    h.chunks(4)
        .take(6)
        .map(|b| format!("{:05}", u32::from_be_bytes(b.try_into().expect("4 bytes")) % 100_000))
        .collect::<Vec<_>>()
        .join(" ")
}

fn seal_app(ratchet: &mut Ratchet, msg: &AppMsg) -> Result<RatchetMessage> {
    let padded = pad(&lethe_proto::to_bytes(msg), E2E_BLOCK).map_err(|_| ClientError::TooLong)?;
    Ok(ratchet.encrypt(&padded))
}

fn open_app(ratchet: &mut Ratchet, msg: &RatchetMessage) -> Result<AppMsg> {
    let padded = ratchet.decrypt(msg)?;
    lethe_proto::from_bytes(unpad(&padded)?).map_err(|_| ClientError::Protocol("bad message"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(clean_file_name("../../etc/passwd"), "passwd");
        assert_eq!(clean_file_name("C:\\Users\\me\\photo.jpg"), "photo.jpg");
        assert_eq!(clean_file_name(".hidden"), "hidden");
        assert_eq!(clean_file_name("a\u{0}b\nc.txt"), "abc.txt");
        assert_eq!(clean_file_name(""), "file");
    }

    #[test]
    fn security_code_shape() {
        let code = security_code(b"some associated data");
        assert_eq!(code.len(), 6 * 5 + 5);
        assert!(code.split(' ').all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
        assert_ne!(code, security_code(b"other data"));
    }
}
