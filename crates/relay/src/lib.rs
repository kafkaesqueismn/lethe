//! niche relay: an SMP-style server hosting anonymous one-way queues.
//!
//! What the relay knows: queue IDs, the public keys authorizing them, and opaque,
//! fixed-size, end-to-end-encrypted message bodies until they're acknowledged.
//! What it doesn't know or keep: user identities, contact lists, which queues belong
//! to the same person, message content, and client IP addresses. Nothing is logged
//! per connection.
//!
//! Messages are held in memory. A restart drops undelivered messages; clients keep
//! their own outbox, so the cost is redelivery rather than silent loss of a conversation.

mod tls;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use niche_crypto::primitives::{random_bytes, verify};
use niche_crypto::DhKeyPair;
use niche_proto::{
    delivery, decode_block, encode_block, signed_bytes, ClientFrame, Command, ErrorCode, MsgId, QueueId, RelayAddr,
    Response, ServerFrame, SessionId, BLOCK_SIZE, MAX_BODY, PROTOCOL_VERSION,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

pub struct Config {
    pub listen: SocketAddr,
    /// Hostname clients use to reach this relay (goes into the printed address).
    pub public_host: String,
    /// Where the TLS key/cert are kept. `None` generates an ephemeral one (tests).
    pub data_dir: Option<PathBuf>,
    pub message_ttl: Duration,
    pub max_queue_messages: usize,
    /// Connections silent for this long are closed (clients ping every 30s).
    pub idle_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:5223".parse().unwrap(),
            public_host: "localhost".into(),
            data_dir: None,
            message_ttl: Duration::from_secs(21 * 24 * 3600),
            max_queue_messages: 256,
            idle_timeout: Duration::from_secs(120),
        }
    }
}

pub struct RelayHandle {
    /// The address clients use, including the pinned certificate fingerprint.
    pub addr: RelayAddr,
    pub local_addr: SocketAddr,
    state: Arc<Mutex<State>>,
    tasks: Vec<JoinHandle<()>>,
}

impl RelayHandle {
    /// Number of queues and stored (unacknowledged) messages. For tests and ops.
    pub fn stats(&self) -> (usize, usize) {
        let s = self.state.lock().unwrap();
        (s.queues.len(), s.queues.values().map(|q| q.msgs.len()).sum())
    }

    pub fn shutdown(self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

type Outbox = UnboundedSender<ServerFrame>;

struct StoredMsg {
    id: MsgId,
    ts: u64,
    body: Vec<u8>,
}

struct Queue {
    recipient_key: [u8; 32],
    sender_id: QueueId,
    sender_key: Option<[u8; 32]>,
    delivery_key: [u8; 32],
    msgs: VecDeque<StoredMsg>,
    /// Message pushed to the subscriber and awaiting `Ack`.
    delivered: Option<MsgId>,
    subscriber: Option<(u64, Outbox)>,
}

#[derive(Default)]
struct State {
    queues: HashMap<QueueId, Queue>,
    /// sender ID -> recipient ID
    senders: HashMap<QueueId, QueueId>,
    recipient_keys: HashSet<[u8; 32]>,
    max_queue_messages: usize,
}

impl State {
    fn try_deliver(&mut self, rid: &QueueId) {
        let Some(q) = self.queues.get_mut(rid) else { return };
        if q.delivered.is_some() {
            return;
        }
        let (Some((_, tx)), Some(m)) = (&q.subscriber, q.msgs.front()) else { return };
        let frame = ServerFrame::Reply {
            corr_id: 0,
            entity: *rid,
            resp: Response::Msg { msg_id: m.id, ts: m.ts, body: m.body.clone() },
        };
        if tx.send(frame).is_ok() {
            q.delivered = Some(m.id);
        } else {
            q.subscriber = None;
        }
    }

    fn sweep(&mut self, ttl: Duration) {
        let cutoff = now().saturating_sub(ttl.as_secs());
        for q in self.queues.values_mut() {
            let before = q.msgs.len();
            q.msgs.retain(|m| m.ts >= cutoff);
            if q.msgs.len() != before && q.delivered.is_some_and(|d| !q.msgs.iter().any(|m| m.id == d)) {
                q.delivered = None;
            }
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub async fn start(config: Config) -> anyhow::Result<RelayHandle> {
    let identity = tls::load_or_generate(config.data_dir.as_deref())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(identity.server_config.clone());
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let addr = RelayAddr { host: config.public_host.clone(), port: local_addr.port(), fingerprint: identity.fingerprint };
    let state = Arc::new(Mutex::new(State { max_queue_messages: config.max_queue_messages, ..Default::default() }));

    let accept_state = state.clone();
    let idle = config.idle_timeout;
    let accept_task = tokio::spawn(async move {
        let conn_ids = Arc::new(AtomicU64::new(1));
        loop {
            let Ok((tcp, _peer)) = listener.accept().await else { continue };
            // `_peer` is intentionally never stored or logged.
            let (acceptor, state, id) = (acceptor.clone(), accept_state.clone(), conn_ids.fetch_add(1, Ordering::Relaxed));
            tokio::spawn(async move {
                let _ = handle_connection(tcp, acceptor, state, id, idle).await;
            });
        }
    });

    let sweep_state = state.clone();
    let ttl = config.message_ttl;
    let sweep_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            sweep_state.lock().unwrap().sweep(ttl);
        }
    });

    Ok(RelayHandle { addr, local_addr, state, tasks: vec![accept_task, sweep_task] })
}

async fn handle_connection(
    tcp: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    state: Arc<Mutex<State>>,
    conn_id: u64,
    idle: Duration,
) -> anyhow::Result<()> {
    tcp.set_nodelay(true)?;
    let tls = tokio::time::timeout(Duration::from_secs(15), acceptor.accept(tcp)).await??;
    let ws = tokio::time::timeout(Duration::from_secs(15), tokio_tungstenite::accept_async(tls)).await??;
    let (mut sink, mut source) = ws.split();
    let (tx, mut rx) = unbounded_channel::<ServerFrame>();
    let session_id: SessionId = random_bytes();
    tx.send(ServerFrame::Hello { version: PROTOCOL_VERSION, session_id })?;

    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let Ok(block) = encode_block(&frame) else { continue };
            if sink.send(Message::Binary(block)).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let mut subscribed: HashSet<QueueId> = HashSet::new();
    loop {
        let msg = match tokio::time::timeout(idle, source.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => break,
        };
        let data = match msg {
            Message::Binary(b) if b.len() == BLOCK_SIZE => b,
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => break,
        };
        let Ok(frame) = decode_block::<ClientFrame>(&data) else { break };
        let corr_id = frame.corr_id;
        let entity = frame.entity;
        let (resp, deliver) = {
            let mut st = state.lock().unwrap();
            process(&mut st, &session_id, conn_id, &tx, frame, &mut subscribed)
        };
        let reply_entity = match &resp {
            Response::Ids { recipient_id, .. } => *recipient_id,
            _ => entity,
        };
        if tx.send(ServerFrame::Reply { corr_id, entity: reply_entity, resp }).is_err() {
            break;
        }
        if let Some(rid) = deliver {
            state.lock().unwrap().try_deliver(&rid);
        }
    }

    {
        let mut st = state.lock().unwrap();
        for rid in &subscribed {
            if let Some(q) = st.queues.get_mut(rid)
                && q.subscriber.as_ref().is_some_and(|(c, _)| *c == conn_id) {
                    q.subscriber = None;
                    q.delivered = None;
                }
        }
    }
    drop(tx);
    let _ = writer.await;
    Ok(())
}

/// Handle one command. Returns the reply and, if a delivery may now be possible,
/// the recipient queue to attempt it on (after the reply has been queued).
fn process(
    st: &mut State,
    session_id: &SessionId,
    conn_id: u64,
    tx: &Outbox,
    frame: ClientFrame,
    subscribed: &mut HashSet<QueueId>,
) -> (Response, Option<QueueId>) {
    use Response::Err as E;
    let signed = signed_bytes(session_id, frame.corr_id, &frame.entity, &frame.cmd);
    let sig_ok = |key: &[u8; 32]| frame.sig.as_deref().is_some_and(|s| verify(key, &signed, s).is_ok());

    match frame.cmd {
        Command::Ping => (Response::Pong, None),

        Command::New { recipient_key, recipient_dh } => {
            if !sig_ok(&recipient_key) {
                return (E(ErrorCode::Auth), None);
            }
            if !st.recipient_keys.insert(recipient_key) {
                return (E(ErrorCode::Duplicate), None);
            }
            let server_dh = DhKeyPair::generate();
            let Ok(shared) = server_dh.dh(&recipient_dh) else {
                st.recipient_keys.remove(&recipient_key);
                return (E(ErrorCode::Syntax), None);
            };
            let (rid, sid): (QueueId, QueueId) = (random_bytes(), random_bytes());
            st.senders.insert(sid, rid);
            st.queues.insert(
                rid,
                Queue {
                    recipient_key,
                    sender_id: sid,
                    sender_key: None,
                    delivery_key: delivery::key(&shared),
                    msgs: VecDeque::new(),
                    delivered: None,
                    subscriber: None,
                },
            );
            (Response::Ids { recipient_id: rid, sender_id: sid, server_dh: server_dh.public() }, None)
        }

        Command::Send { body } => {
            let Some(rid) = st.senders.get(&frame.entity).copied() else { return (E(ErrorCode::Auth), None) };
            let max = st.max_queue_messages;
            let q = st.queues.get_mut(&rid).expect("sender index is consistent");
            if let Some(k) = q.sender_key
                && !sig_ok(&k) {
                    return (E(ErrorCode::Auth), None);
                }
            if body.len() > MAX_BODY {
                return (E(ErrorCode::Syntax), None);
            }
            if q.msgs.len() >= max {
                return (E(ErrorCode::Quota), None);
            }
            let id: MsgId = random_bytes();
            let ts = now();
            let sealed = delivery::seal_body(&q.delivery_key, &id, ts, &body);
            q.msgs.push_back(StoredMsg { id, ts, body: sealed });
            (Response::Ok, Some(rid))
        }

        // Everything else is a recipient command on `entity` = recipient ID.
        cmd => {
            let rid = frame.entity;
            let Some(q) = st.queues.get_mut(&rid) else { return (E(ErrorCode::Auth), None) };
            if !sig_ok(&q.recipient_key) {
                return (E(ErrorCode::Auth), None);
            }
            match cmd {
                Command::Key { sender_key } => match q.sender_key {
                    None => {
                        q.sender_key = Some(sender_key);
                        (Response::Ok, None)
                    }
                    Some(k) if k == sender_key => (Response::Ok, None),
                    Some(_) => (E(ErrorCode::Auth), None),
                },
                Command::Sub => {
                    if let Some((old, old_tx)) = q.subscriber.take()
                        && old != conn_id {
                            let _ = old_tx.send(ServerFrame::Reply { corr_id: 0, entity: rid, resp: Response::End });
                        }
                    q.subscriber = Some((conn_id, tx.clone()));
                    q.delivered = None;
                    subscribed.insert(rid);
                    (Response::Ok, Some(rid))
                }
                Command::Ack { msg_id } => {
                    if q.delivered != Some(msg_id) {
                        return (E(ErrorCode::NoMsg), None);
                    }
                    q.msgs.pop_front();
                    q.delivered = None;
                    (Response::Ok, Some(rid))
                }
                Command::Del => {
                    let q = st.queues.remove(&rid).expect("checked above");
                    st.senders.remove(&q.sender_id);
                    st.recipient_keys.remove(&q.recipient_key);
                    subscribed.remove(&rid);
                    (Response::Ok, None)
                }
                Command::New { .. } | Command::Send { .. } | Command::Ping => unreachable!("handled above"),
            }
        }
    }
}
