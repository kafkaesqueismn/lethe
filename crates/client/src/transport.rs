//! Connection to one relay: TLS 1.3 with a pinned certificate, WebSocket framing,
//! fixed-size blocks, optional SOCKS5 (Tor) proxy.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use niche_crypto::SigningKeyPair;
use niche_proto::{
    decode_block, encode_block, signed_bytes, ClientFrame, Command, MsgId, QueueId, RelayAddr, Response, ServerFrame,
    SessionId,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

use crate::error::{ClientError, Result};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Unsolicited events from a relay.
#[derive(Debug)]
pub enum Push {
    Msg { relay: RelayAddr, rid: QueueId, msg_id: MsgId, ts: u64, body: Vec<u8> },
    End { relay: RelayAddr, rid: QueueId },
    Disconnected { relay: RelayAddr },
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Response>>>>;

pub struct RelayConn {
    session_id: SessionId,
    out: UnboundedSender<Vec<u8>>,
    pending: Pending,
    next_corr: AtomicU64,
    closed: Arc<AtomicBool>,
}

impl RelayConn {
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub async fn connect(addr: RelayAddr, proxy: Option<SocketAddr>, push: UnboundedSender<Push>) -> Result<Arc<Self>> {
        tokio::time::timeout(CONNECT_TIMEOUT, Self::connect_inner(addr, proxy, push))
            .await
            .map_err(|_| net("connect timed out"))?
    }

    async fn connect_inner(addr: RelayAddr, proxy: Option<SocketAddr>, push: UnboundedSender<Push>) -> Result<Arc<Self>> {
        let tcp = match proxy {
            // Hostname resolution happens at the proxy, so .onion relays work and DNS doesn't leak.
            Some(p) => tokio_socks::tcp::Socks5Stream::connect(p, (addr.host.as_str(), addr.port))
                .await
                .map_err(net)?
                .into_inner(),
            None => TcpStream::connect(addr.host_port()).await.map_err(net)?,
        };
        tcp.set_nodelay(true).map_err(net)?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(net)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCert { fingerprint: addr.fingerprint, provider }))
            .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("niche-relay").expect("valid name"), tcp)
            .await
            .map_err(net)?;
        let (ws, _) = tokio_tungstenite::client_async("wss://niche-relay/", tls).await.map_err(net)?;
        let (mut sink, mut source) = ws.split();

        let session_id = match source.next().await {
            Some(Ok(Message::Binary(b))) => match decode_block::<ServerFrame>(&b) {
                Ok(ServerFrame::Hello { session_id, .. }) => session_id,
                _ => return Err(ClientError::Protocol("expected hello")),
            },
            _ => return Err(net("connection closed during handshake")),
        };

        let (out, mut out_rx) = unbounded_channel::<Vec<u8>>();
        let pending: Pending = Default::default();
        let closed = Arc::new(AtomicBool::new(false));

        let writer_closed = closed.clone();
        tokio::spawn(async move {
            while let Some(block) = out_rx.recv().await {
                if sink.send(Message::Binary(block)).await.is_err() {
                    break;
                }
            }
            writer_closed.store(true, Ordering::Relaxed);
            let _ = sink.close().await;
        });

        let (r_pending, r_closed, r_addr) = (pending.clone(), closed.clone(), addr.clone());
        tokio::spawn(async move {
            while let Some(Ok(msg)) = source.next().await {
                let Message::Binary(b) = msg else { continue };
                let Ok(ServerFrame::Reply { corr_id, entity, resp }) = decode_block::<ServerFrame>(&b) else { break };
                if corr_id != 0 {
                    if let Some(tx) = r_pending.lock().unwrap().remove(&corr_id) {
                        let _ = tx.send(resp);
                    }
                    continue;
                }
                let p = match resp {
                    Response::Msg { msg_id, ts, body } => Push::Msg { relay: r_addr.clone(), rid: entity, msg_id, ts, body },
                    Response::End => Push::End { relay: r_addr.clone(), rid: entity },
                    _ => continue,
                };
                if push.send(p).is_err() {
                    break;
                }
            }
            r_closed.store(true, Ordering::Relaxed);
            r_pending.lock().unwrap().clear(); // wakes waiters with an error
            let _ = push.send(Push::Disconnected { relay: r_addr });
        });

        let conn = Arc::new(Self { session_id, out, pending, next_corr: AtomicU64::new(1), closed });

        let weak = Arc::downgrade(&conn);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(PING_INTERVAL).await;
                let Some(c) = weak.upgrade() else { break };
                if c.is_closed() || c.request([0; 24], Command::Ping, None).await.is_err() {
                    break;
                }
            }
        });
        Ok(conn)
    }

    /// Send a command and await its reply. Relay errors become `ClientError::Relay`.
    pub async fn request(&self, entity: QueueId, cmd: Command, key: Option<&SigningKeyPair>) -> Result<Response> {
        if self.is_closed() {
            return Err(net("connection closed"));
        }
        let corr_id = self.next_corr.fetch_add(1, Ordering::Relaxed);
        let sig = key.map(|k| k.sign(&signed_bytes(&self.session_id, corr_id, &entity, &cmd)));
        let block = encode_block(&ClientFrame { corr_id, entity, sig, cmd }).map_err(|_| ClientError::TooLong)?;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(corr_id, tx);
        if self.out.send(block).is_err() {
            self.pending.lock().unwrap().remove(&corr_id);
            return Err(net("connection closed"));
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(Response::Err(code))) => Err(ClientError::Relay(code)),
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => Err(net("connection closed")),
            Err(_) => {
                self.pending.lock().unwrap().remove(&corr_id);
                Err(net("request timed out"))
            }
        }
    }
}

fn net(e: impl std::fmt::Display) -> ClientError {
    ClientError::Network(e.to_string())
}

/// Accepts exactly one certificate: the one whose SHA-256 is in the relay address.
/// The TLS 1.3 handshake signature is still fully verified against that certificate.
#[derive(Debug)]
struct PinnedCert {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if niche_crypto::primitives::sha256(end_entity) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("relay certificate does not match pinned fingerprint".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
