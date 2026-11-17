use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};

/// A relay address: `niche-relay://<base64url sha256(cert)>@host:port`.
///
/// The certificate fingerprint is pinned, so there's no reliance on certificate
/// authorities or DNS: a relay that can't present the matching certificate is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayAddr {
    pub host: String,
    pub port: u16,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
#[error("invalid relay address (expected niche-relay://<fingerprint>@host:port)")]
pub struct AddrError;

impl RelayAddr {
    pub fn host_port(&self) -> String {
        if self.host.contains(':') { format!("[{}]:{}", self.host, self.port) } else { format!("{}:{}", self.host, self.port) }
    }
}

impl fmt::Display for RelayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "niche-relay://{}@{}", B64.encode(self.fingerprint), self.host_port())
    }
}

impl FromStr for RelayAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, AddrError> {
        let rest = s.trim().strip_prefix("niche-relay://").ok_or(AddrError)?;
        let (fp, hostport) = rest.split_once('@').ok_or(AddrError)?;
        let fingerprint: [u8; 32] = B64.decode(fp).map_err(|_| AddrError)?.try_into().map_err(|_| AddrError)?;
        let (host, port) = hostport.rsplit_once(':').ok_or(AddrError)?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(AddrError);
        }
        Ok(Self { host: host.to_string(), port: port.parse().map_err(|_| AddrError)?, fingerprint })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for host in ["relay.example.org", "127.0.0.1", "::1", "abcdefghijklmnop.onion"] {
            let a = RelayAddr { host: host.into(), port: 5223, fingerprint: [7; 32] };
            assert_eq!(a.to_string().parse::<RelayAddr>().unwrap(), a);
        }
        assert!("http://x@y:1".parse::<RelayAddr>().is_err());
        assert!("niche-relay://AAAA@host:1".parse::<RelayAddr>().is_err());
    }
}
