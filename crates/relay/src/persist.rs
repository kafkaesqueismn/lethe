//! On-disk snapshot of queues and undelivered messages.
//!
//! Written atomically (temp file + fsync + rename) with owner-only permissions. Live
//! connection state (subscribers, in-flight deliveries) isn't saved; clients resubscribe.

use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;

use lethe_proto::{MsgId, QueueId};
use serde::{Deserialize, Serialize};

use crate::{Queue, State, StoredMsg};

const VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
struct PQueue {
    rid: QueueId,
    recipient_key: [u8; 32],
    sender_id: QueueId,
    sender_key: Option<[u8; 32]>,
    delivery_key: [u8; 32],
    msgs: Vec<(MsgId, u64, Vec<u8>)>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Snapshot {
    version: u8,
    queues: Vec<PQueue>,
}

impl Snapshot {
    pub fn from_state(st: &State) -> Self {
        let queues = st
            .queues
            .iter()
            .map(|(rid, q)| PQueue {
                rid: *rid,
                recipient_key: q.recipient_key,
                sender_id: q.sender_id,
                sender_key: q.sender_key,
                delivery_key: q.delivery_key,
                msgs: q.msgs.iter().map(|m| (m.id, m.ts, m.body.clone())).collect(),
            })
            .collect();
        Self { version: VERSION, queues }
    }

    pub fn restore(self, st: &mut State) {
        for pq in self.queues {
            st.senders.insert(pq.sender_id, pq.rid);
            st.recipient_keys.insert(pq.recipient_key);
            let msgs: VecDeque<StoredMsg> = pq.msgs.into_iter().map(|(id, ts, body)| StoredMsg { id, ts, body }).collect();
            st.queues.insert(
                pq.rid,
                Queue {
                    recipient_key: pq.recipient_key,
                    sender_id: pq.sender_id,
                    sender_key: pq.sender_key,
                    delivery_key: pq.delivery_key,
                    msgs,
                    delivered: None,
                    subscriber: None,
                },
            );
        }
    }

    pub fn read(path: &Path) -> anyhow::Result<Option<Self>> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let snap: Self = postcard::from_bytes(&data).map_err(|e| anyhow::anyhow!("corrupt relay snapshot {}: {e}", path.display()))?;
        anyhow::ensure!(snap.version == VERSION, "unsupported relay snapshot version {}", snap.version);
        Ok(Some(snap))
    }

    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        let data = postcard::to_stdvec(self).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(tmp, path)
    }
}
