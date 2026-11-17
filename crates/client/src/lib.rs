//! niche client agent.
//!
//! ```text
//!   Alice                         relay A            relay B                  Bob
//!   NEW ─────────────────────────▶ q_A
//!   link(q_A sender id, ik_a, ek_a) ═══════ out of band (QR / paste) ═══════▶
//!                                                     q_B ◀──────────────── NEW
//!                                  q_A ◀── SEND Confirmation(ik_b, ek_b, ratchet[ConnInfo{key_b, q_B}])
//!   KEY(key_b) ──────────────────▶ q_A   (now only Bob can send to q_A)
//!   SEND ratchet[ConnInfo{key_a}] ───────────────────▶ q_B
//!                                                     q_B ◀─────────── KEY(key_a)
//!   ═══════════════ both queues secured; Double Ratchet messages flow ═══════════════
//! ```

mod agent;
mod error;
mod model;
mod store;
mod transport;

pub use agent::{Agent, AgentConfig, Event, StoreLocation};
pub use error::{ClientError, Result};
pub use model::{ChatItem, ContactInfo, ContactStatus, Direction, Invitation, ItemStatus};
pub use niche_proto::RelayAddr;
