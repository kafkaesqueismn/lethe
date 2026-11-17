//! Self-signed TLS identity. Clients pin the SHA-256 of the certificate, so no CA is involved.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct Identity {
    pub server_config: Arc<rustls::ServerConfig>,
    pub fingerprint: [u8; 32],
}

pub fn load_or_generate(dir: Option<&Path>) -> anyhow::Result<Identity> {
    let (cert, key) = match dir {
        Some(dir) => {
            let (cp, kp) = (dir.join("relay-cert.der"), dir.join("relay-key.der"));
            if cp.exists() && kp.exists() {
                (std::fs::read(&cp)?, std::fs::read(&kp)?)
            } else {
                std::fs::create_dir_all(dir)?;
                let (c, k) = generate()?;
                std::fs::write(&cp, &c)?;
                write_private(&kp, &k)?;
                (c, k)
            }
        }
        None => generate()?,
    };
    let fingerprint = lethe_crypto::primitives::sha256(&cert);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))?;
    Ok(Identity { server_config: Arc::new(server_config), fingerprint })
}

fn generate() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let ck = rcgen::generate_simple_self_signed(vec!["lethe-relay".to_string()])?;
    Ok((ck.cert.der().to_vec(), ck.key_pair.serialize_der()))
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)
}
