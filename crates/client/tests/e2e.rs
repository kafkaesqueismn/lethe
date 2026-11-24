//! End-to-end: real relays over TLS on localhost, two agents, full handshake.

use std::time::Duration;

use lethe_client::{Agent, AgentConfig, ContactStatus, Direction, Event, ItemStatus, StoreLocation};
use lethe_relay::{Config, RelayHandle};
use tokio::sync::broadcast::Receiver;

async fn relay() -> RelayHandle {
    lethe_relay::start(Config { listen: "127.0.0.1:0".parse().unwrap(), public_host: "127.0.0.1".into(), ..Default::default() })
        .await
        .unwrap()
}

async fn agent() -> Agent {
    Agent::start(AgentConfig { store: StoreLocation::Memory, socks_proxy: None, fast_kdf_for_tests: true }).await.unwrap()
}

async fn wait_for(rx: &mut Receiver<Event>, mut pred: impl FnMut(&Event) -> bool) -> Event {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let e = rx.recv().await.unwrap();
            if pred(&e) {
                return e;
            }
        }
    })
    .await
    .expect("timed out waiting for event")
}

async fn connect(alice: &Agent, a_relay: &RelayHandle, bob: &Agent, b_relay: &RelayHandle) -> (u64, u64) {
    let (mut a_ev, mut b_ev) = (alice.subscribe(), bob.subscribe());
    let (a_cid, link) = alice.create_invite(&a_relay.addr, None, Some("Alice".into())).await.unwrap();
    let b_cid = bob.accept_invite(&link, &b_relay.addr, None, Some("Bob".into())).await.unwrap();
    wait_for(&mut a_ev, |e| matches!(e, Event::ContactConnected { contact_id } if *contact_id == a_cid)).await;
    wait_for(&mut b_ev, |e| matches!(e, Event::ContactConnected { contact_id } if *contact_id == b_cid)).await;
    (a_cid, b_cid)
}

#[tokio::test]
async fn two_relays_full_conversation() {
    let (ra, rb) = (relay().await, relay().await);
    let (alice, bob) = (agent().await, agent().await);
    let (a_cid, b_cid) = connect(&alice, &ra, &bob, &rb).await;

    let a_contacts = alice.contacts().await;
    assert_eq!(a_contacts[0].status, ContactStatus::Ready);
    assert_eq!(a_contacts[0].name, "Bob", "peer's chosen profile name is shown");
    assert_eq!(bob.contacts().await[0].name, "Alice");

    let (mut a_ev, mut b_ev) = (alice.subscribe(), bob.subscribe());
    for i in 0..5 {
        let sent = alice.send_text(a_cid, &format!("hello bob {i}")).await.unwrap();
        wait_for(&mut a_ev, |e| matches!(e, Event::ItemStatus { item_id, status: ItemStatus::Sent, .. } if *item_id == sent.id)).await;
        let Event::Message { item, .. } = wait_for(&mut b_ev, |e| matches!(e, Event::Message { .. })).await else { unreachable!() };
        assert_eq!(item.text, format!("hello bob {i}"));
        bob.send_text(b_cid, &format!("hi alice {i}")).await.unwrap();
        let Event::Message { item, .. } = wait_for(&mut a_ev, |e| matches!(e, Event::Message { .. })).await else { unreachable!() };
        assert_eq!(item.text, format!("hi alice {i}"));
    }

    let a_msgs = alice.messages(a_cid).await.unwrap();
    assert_eq!(a_msgs.len(), 10);
    assert_eq!(a_msgs.iter().filter(|m| m.direction == Direction::Received).count(), 5);

    // Give the last ACKs a moment, then the relays should hold nothing.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(ra.stats(), (1, 0));
    assert_eq!(rb.stats(), (1, 0));
}

#[tokio::test]
async fn messages_wait_on_relay_while_offline_and_survive_restart() {
    let r = relay().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bob.db");
    let file_agent = || {
        Agent::start(AgentConfig {
            store: StoreLocation::File { path: path.clone(), passphrase: "bob's passphrase".into() },
            socks_proxy: None,
            fast_kdf_for_tests: true,
        })
    };

    let alice = agent().await;
    let bob = file_agent().await.unwrap();
    let (a_cid, b_cid) = connect(&alice, &r, &bob, &r).await;
    bob.shutdown().await;
    drop(bob);

    let mut a_ev = alice.subscribe();
    let sent = alice.send_text(a_cid, "while you were away").await.unwrap();
    wait_for(&mut a_ev, |e| matches!(e, Event::ItemStatus { item_id, status: ItemStatus::Sent, .. } if *item_id == sent.id)).await;
    assert_eq!(r.stats().1, 1, "message is held by the relay");

    assert!(matches!(
        Agent::start(AgentConfig {
            store: StoreLocation::File { path: path.clone(), passphrase: "wrong".into() },
            socks_proxy: None,
            fast_kdf_for_tests: true,
        })
        .await,
        Err(lethe_client::ClientError::BadPassphrase)
    ));

    let bob = file_agent().await.unwrap();
    let mut b_ev = bob.subscribe();
    let Event::Message { contact_id, item } = wait_for(&mut b_ev, |e| matches!(e, Event::Message { .. })).await else { unreachable!() };
    assert_eq!((contact_id, item.text.as_str()), (b_cid, "while you were away"));

    // The restored ratchet still works in both directions.
    bob.send_text(b_cid, "back now").await.unwrap();
    let Event::Message { item, .. } = wait_for(&mut a_ev, |e| matches!(e, Event::Message { .. })).await else { unreachable!() };
    assert_eq!(item.text, "back now");
}

#[tokio::test]
async fn invitation_is_single_use() {
    let r = relay().await;
    let (alice, bob, mallory) = (agent().await, agent().await, agent().await);
    let mut a_ev = alice.subscribe();
    let (a_cid, link) = alice.create_invite(&r.addr, None, None).await.unwrap();
    bob.accept_invite(&link, &r.addr, None, None).await.unwrap();
    wait_for(&mut a_ev, |e| matches!(e, Event::ContactConnected { .. })).await;

    let mut m_ev = mallory.subscribe();
    let m_cid = mallory.accept_invite(&link, &r.addr, None, None).await.unwrap();
    let e = wait_for(&mut m_ev, |e| matches!(e, Event::Error { .. })).await;
    assert!(matches!(e, Event::Error { contact_id: Some(c), .. } if c == m_cid), "relay rejects the second joiner: {e:?}");
    assert_eq!(alice.contacts().await.len(), 1);
    assert_eq!(alice.contacts().await[0].id, a_cid);
}

#[tokio::test]
async fn delete_contact_notifies_peer_and_removes_queue() {
    let r = relay().await;
    let (alice, bob) = (agent().await, agent().await);
    let (a_cid, b_cid) = connect(&alice, &r, &bob, &r).await;
    let mut b_ev = bob.subscribe();
    alice.delete_contact(a_cid).await.unwrap();
    wait_for(&mut b_ev, |e| matches!(e, Event::ContactLeft { contact_id } if *contact_id == b_cid)).await;
    assert!(alice.contacts().await.is_empty());
    assert_eq!(r.stats().0, 1, "only Bob's queue remains");
    assert!(bob.send_text(b_cid, "hello?").await.is_err());
}

#[tokio::test]
async fn wrong_relay_fingerprint_is_rejected() {
    let r = relay().await;
    let mut fake = r.addr.clone();
    fake.fingerprint[0] ^= 1;
    let alice = agent().await;
    let err = alice.create_invite(&fake, None, None).await.unwrap_err();
    assert!(matches!(err, lethe_client::ClientError::Network(_)), "{err}");
}

#[tokio::test]
async fn relay_restart_keeps_undelivered_messages() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = |port: u16| Config {
        listen: format!("127.0.0.1:{port}").parse().unwrap(),
        public_host: "127.0.0.1".into(),
        data_dir: Some(dir.path().join("relay")),
        ..Default::default()
    };
    let bob_store = || AgentConfig {
        store: StoreLocation::File { path: dir.path().join("bob.db"), passphrase: "pw".into() },
        socks_proxy: None,
        fast_kdf_for_tests: true,
    };
    let r = lethe_relay::start(cfg(0)).await.unwrap();
    let port = r.local_addr.port();
    let alice = agent().await;
    let bob = Agent::start(bob_store()).await.unwrap();
    let (a_cid, b_cid) = connect(&alice, &r, &bob, &r).await;
    bob.shutdown().await;
    drop(bob);

    let mut a_ev = alice.subscribe();
    let sent = alice.send_text(a_cid, "survives a relay restart").await.unwrap();
    wait_for(&mut a_ev, |e| matches!(e, Event::ItemStatus { item_id, status: ItemStatus::Sent, .. } if *item_id == sent.id)).await;
    let addr = r.addr.clone();
    r.stop().await; // closes connections, frees the port, writes the final snapshot

    let r2 = lethe_relay::start(cfg(port)).await.unwrap();
    assert_eq!(r2.addr, addr, "same identity and address after restart");
    assert_eq!(r2.stats(), (2, 1), "both queues and the waiting message were restored");

    let bob = Agent::start(bob_store()).await.unwrap();
    let mut b_ev = bob.subscribe();
    let Event::Message { contact_id, item } = wait_for(&mut b_ev, |e| matches!(e, Event::Message { .. })).await else { unreachable!() };
    assert_eq!((contact_id, item.text.as_str()), (b_cid, "survives a relay restart"));
}
