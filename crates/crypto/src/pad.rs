//! Fixed-size padding: `[u32 BE length][data][zeros]`, always exactly `size` bytes.

use crate::{CryptoError, Result};

const LEN_PREFIX: usize = 4;

pub fn pad(data: &[u8], size: usize) -> Result<Vec<u8>> {
    if data.len() + LEN_PREFIX > size {
        return Err(CryptoError::TooLarge);
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(size, 0);
    Ok(out)
}

pub fn unpad(block: &[u8]) -> Result<&[u8]> {
    if block.len() < LEN_PREFIX {
        return Err(CryptoError::Malformed);
    }
    let len = u32::from_be_bytes(block[..LEN_PREFIX].try_into().unwrap()) as usize;
    block.get(LEN_PREFIX..LEN_PREFIX + len).ok_or(CryptoError::Malformed)
}

/// Largest payload that fits in a padded block of `size` bytes.
pub const fn capacity(size: usize) -> usize {
    size - LEN_PREFIX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_fixed_size() {
        for msg in [&b""[..], b"hi", &[7u8; 1000]] {
            let p = pad(msg, 1024).unwrap();
            assert_eq!(p.len(), 1024);
            assert_eq!(unpad(&p).unwrap(), msg);
        }
    }

    #[test]
    fn rejects_oversize_and_garbage() {
        assert_eq!(pad(&[0; 1021], 1024), Err(CryptoError::TooLarge));
        assert!(pad(&[0; 1020], 1024).is_ok());
        let mut bad = vec![0xff; 16];
        bad[..4].copy_from_slice(&100u32.to_be_bytes());
        assert_eq!(unpad(&bad), Err(CryptoError::Malformed));
    }
}
