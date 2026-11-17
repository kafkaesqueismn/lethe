use niche_proto::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("network error: {0}")]
    Network(String),
    #[error("relay rejected command: {0:?}")]
    Relay(ErrorCode),
    #[error("crypto error: {0}")]
    Crypto(#[from] niche_crypto::CryptoError),
    #[error("store error: {0}")]
    Store(String),
    #[error("wrong passphrase or corrupted store")]
    BadPassphrase,
    #[error("invalid invitation link")]
    InvalidLink,
    #[error("no such contact")]
    NotFound,
    #[error("contact is not connected yet")]
    NotReady,
    #[error("message too long")]
    TooLong,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
}

impl ClientError {
    /// Worth retrying later (relay unreachable, queue temporarily full).
    pub fn is_transient(&self) -> bool {
        matches!(self, ClientError::Network(_) | ClientError::Relay(ErrorCode::Quota))
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;
