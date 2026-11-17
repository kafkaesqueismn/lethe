//! The agent: owns state, relay connections and the connection/message state machine.
//!
//! Invariants that matter for security:
//! * Ratchet output is persisted (as an outbox entry) **before** it's sent, so a crash or
//!   retry never encrypts two different plaintexts under the same message key.
//! * Incoming messages are processed on a copy of the contact and committed only on
//!   success. Transient failures leave the message unacknowledged, so the relay
//!   redelivers it; permanent failures (forgery, garbage) are acknowledged and dropped.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lethe_crypto::pad::{pad, unpad};
use lethe_crypto::ratchet::{Ratchet, RatchetMessage};
use lethe_crypto::x3dh::{self, InviterKeys};
use lethe_crypto::{DhKeyPair, SigningKeyPair};
use lethe_proto::{delivery, Command, MsgId, QueueId, RelayAddr, Response, E2E_BLOCK};
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
    Message { contact_id: u64, item: ChatItem },
    ItemStatus { contact_id: u64, item_id: u64, status: ItemStatus },
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
}

struct Inner {
    rt: Mutex<Runtime>,
    conns: Mutex<HashMap<RelayAddr, Arc<RelayConn>>>,
    reconnecting: std::sync::Mutex<HashSet<RelayAddr>>,
    push_tx: mpsc::UnboundedSender<Push>,
    events: broadcast::Sender<Event>,
    proxy: Option<SocketAddr>,
    push_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Handle to a running agent. Cheap to clone.
#[derive(Clone)]
pub struct Agent {
    inner: Arc<Inner>,
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
            rt: Mutex::new(Runtime { state, store, flushing: HashSet::new() }),
            conns: Mutex::new(HashMap::new()),
            reconnecting: Default::default(),
            push_tx,
            events,
            proxy: config.socks_proxy,
            push_task: Default::default(),
        });
        let task = tokio::spawn(push_loop(Arc::downgrade(&inner), push_rx));
        *inner.push_task.lock().unwrap() = Some(task);

        for relay in inner.needed_relays().await {
            inner.spawn_bring_up(relay, Duration::ZERO);
        }
        Ok(Self { inner })
    }

    /// Stop background work and drop relay connections.
    pub async fn shutdown(&self) {
        if let Some(t) = self.inner.push_task.lock().unwrap().take() {
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
            let c = Contact {
                id,
                alias,
                peer_name: None,
                my_profile_name: profile_name,
                status: ContactStatus::Invited,
                rcv: rcv.clone(),
                snd: None,
                invite_keys: Some(keys),
                ratchet: None,
                outbox: Default::default(),
                items: vec![],
                created_at: now(),
            };
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
            let mut c = Contact {
                id,
                alias,
                peer_name: None,
                my_profile_name: profile_name,
                status: ContactStatus::Joining,
                rcv: rcv.clone(),
                snd: Some(snd),
                invite_keys: None,
                ratchet: Some(ratchet),
                outbox: Default::default(),
                items: vec![],
                created_at: now(),
            };
            enqueue(&mut c, &Envelope::Confirmation { ik: ik_b, ek: ek_b, msg }, None);
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
            let item_id = rt.state.next_id();
            let c = rt.state.contacts.get_mut(&contact_id).ok_or(ClientError::NotFound)?;
            if !matches!(c.status, ContactStatus::Ready | ContactStatus::Joining) || c.snd.is_none() {
                return Err(ClientError::NotReady);
            }
            let ratchet = c.ratchet.as_mut().filter(|r| r.can_send()).ok_or(ClientError::NotReady)?;
            let ts = now();
            let msg = seal_app(ratchet, &AppMsg::Text { text: text.to_string(), sent_at: ts })?;
            let item = ChatItem { id: item_id, direction: Direction::Sent, text: text.to_string(), ts, status: ItemStatus::Pending };
            c.items.push(item.clone());
            enqueue(c, &Envelope::Message(msg), Some(item_id));
            rt.store.save(&rt.state)?;
            item
        };
        self.inner.spawn_flush(contact_id);
        Ok(item)
    }

    /// Delete a contact: tell them (best effort), delete our queue at the relay, forget everything.
    pub async fn delete_contact(&self, contact_id: u64) -> Result<()> {
        let (c, leave) = {
            let mut rt = self.inner.rt.lock().await;
            let mut c = rt.state.contacts.remove(&contact_id).ok_or(ClientError::NotFound)?;
            rt.flushing.remove(&contact_id);
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
        let mut rt = self.inner.rt.lock().await;
        rt.state.contacts.get_mut(&contact_id).ok_or(ClientError::NotFound)?.alias = alias;
        rt.store.save(&rt.state)
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

    /// Send a contact's outbox in order. Only one flusher per contact runs at a time.
    async fn flush(self: Arc<Self>, cid: u64) {
        if !self.rt.lock().await.flushing.insert(cid) {
            return;
        }
        loop {
            let next = {
                let mut rt = self.rt.lock().await;
                let job = rt.state.contacts.get(&cid).and_then(|c| {
                    let s = c.snd.as_ref()?;
                    let e = c.outbox.front()?;
                    Some((s.addr.clone(), s.auth.clone(), e.clone()))
                });
                if job.is_none() {
                    rt.flushing.remove(&cid);
                }
                job
            };
            let Some((addr, auth, entry)) = next else { return };

            let res = self.request(&addr.relay, addr.sender_id, Command::Send { body: entry.body.clone() }, Some(&auth)).await;
            let mut rt = self.rt.lock().await;
            let transient = matches!(&res, Err(e) if e.is_transient());
            if transient {
                rt.flushing.remove(&cid);
                drop(rt);
                // Retry after a pause; bring-up resyncs and flushes again once reachable.
                self.spawn_bring_up(addr.relay, Duration::from_secs(2));
                return;
            }
            let status = if res.is_ok() { ItemStatus::Sent } else { ItemStatus::Failed };
            let Some(c) = rt.state.contacts.get_mut(&cid) else {
                rt.flushing.remove(&cid);
                return;
            };
            if c.outbox.front().is_some_and(|e| e.seq == entry.seq) {
                c.outbox.pop_front();
            }
            if let Some(item_id) = entry.item_id {
                if let Some(it) = c.items.iter_mut().find(|i| i.id == item_id) {
                    it.status = status;
                }
                self.emit(Event::ItemStatus { contact_id: cid, item_id, status });
            }
            if let Err(e) = res {
                self.emit(Event::Error { contact_id: Some(cid), message: format!("message not delivered: {e}") });
            }
            if let Err(e) = rt.store.save(&rt.state) {
                self.emit(Event::Error { contact_id: None, message: e.to_string() });
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
        let mut rt = self.rt.lock().await;
        let Some(mut c) = rt.state.contacts.get(&cid).cloned() else { return Ok(()) };
        let key = delivery::key(&c.rcv.dh.dh(&c.rcv.server_dh)?);
        let env_bytes = delivery::open_body(&key, &msg_id, ts, body)?;
        let env: Envelope = lethe_proto::from_bytes(&env_bytes).map_err(|_| ClientError::Protocol("bad envelope"))?;

        let mut events = vec![];
        let mut flush = false;
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
                enqueue(&mut c, &Envelope::Message(reply_msg), None);
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
                    AppMsg::Text { text, sent_at } => {
                        let item = ChatItem { id: rt.state.next_id(), direction: Direction::Received, text, ts: sent_at, status: ItemStatus::Received };
                        c.items.push(item.clone());
                        events.push(Event::Message { contact_id: cid, item });
                    }
                    AppMsg::Leave => {
                        c.status = ContactStatus::Left;
                        c.outbox.clear();
                        events.push(Event::ContactLeft { contact_id: cid });
                    }
                }
            }
        }
        rt.state.contacts.insert(cid, c);
        rt.store.save(&rt.state)?;
        drop(rt);
        for e in events {
            self.emit(e);
        }
        if flush {
            self.spawn_flush(cid);
        }
        Ok(())
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

fn enqueue(c: &mut Contact, env: &Envelope, item_id: Option<u64>) {
    let seq = c.outbox.back().map_or(1, |e| e.seq + 1);
    c.outbox.push_back(OutboxEntry { seq, body: lethe_proto::to_bytes(env), item_id });
}

fn seal_app(ratchet: &mut Ratchet, msg: &AppMsg) -> Result<RatchetMessage> {
    let padded = pad(&lethe_proto::to_bytes(msg), E2E_BLOCK).map_err(|_| ClientError::TooLong)?;
    Ok(ratchet.encrypt(&padded))
}

fn open_app(ratchet: &mut Ratchet, msg: &RatchetMessage) -> Result<AppMsg> {
    let padded = ratchet.decrypt(msg)?;
    lethe_proto::from_bytes(unpad(&padded)?).map_err(|_| ClientError::Protocol("bad message"))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
