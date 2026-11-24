//! Encrypted on-disk store.
//!
//! `lethe.db` layout: `MAGIC (6) | kdf (1) | salt (16) | nonce (24) | XChaCha20-Poly1305(CBOR state)`.
//! The key comes from the passphrase via Argon2id; header bytes are authenticated as AD.
//! Writes go to a temp file that is fsynced and renamed, so a crash can't leave a
//! half-written store.
//!
//! Attachments live next to it in `blobs/`, each encrypted with the same key and bound
//! to its name (AD), so files can't be swapped between messages.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use lethe_crypto::passphrase::{self, SALT_LEN};
use lethe_crypto::primitives::{open_random, random_bytes, seal_random};
use zeroize::Zeroizing;

use crate::error::{ClientError, Result};
use crate::model::State;

const MAGIC: &[u8; 6] = b"LETHE2";
/// The v0.1.0-alpha.1 format (postcard). Recognised only to give a clear error.
const OLD_MAGIC: &[u8; 6] = b"LETHE1";
const KDF_ARGON2ID: u8 = 0;
const KDF_TEST: u8 = 0xff;
const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN;

pub(crate) struct Store {
    path: Option<PathBuf>,
    header: [u8; HEADER_LEN],
    key: Zeroizing<[u8; 32]>,
    /// Attachments for in-memory profiles.
    mem_blobs: HashMap<String, Vec<u8>>,
}

impl Store {
    pub fn memory() -> Self {
        Self { path: None, header: [0; HEADER_LEN], key: Zeroizing::new(random_bytes()), mem_blobs: HashMap::new() }
    }

    /// Open an existing store or create a new one at `path`.
    pub fn open(path: &Path, passphrase: &str, fast_kdf_for_tests: bool) -> Result<(Self, State)> {
        if path.exists() {
            let data = std::fs::read(path).map_err(store_err)?;
            if data.len() >= OLD_MAGIC.len() && &data[..OLD_MAGIC.len()] == OLD_MAGIC {
                return Err(ClientError::OldStore);
            }
            if data.len() < HEADER_LEN || &data[..MAGIC.len()] != MAGIC {
                return Err(ClientError::Store("not a lethe store".into()));
            }
            let header: [u8; HEADER_LEN] = data[..HEADER_LEN].try_into().unwrap();
            let salt: [u8; SALT_LEN] = header[MAGIC.len() + 1..].try_into().unwrap();
            let key = derive(header[MAGIC.len()], passphrase, &salt)?;
            let plain = Zeroizing::new(open_random(&key, &data[HEADER_LEN..], &header).map_err(|_| ClientError::BadPassphrase)?);
            let state = ciborium::from_reader(&plain[..]).map_err(|e| ClientError::Store(format!("corrupted state: {e}")))?;
            Ok((Self { path: Some(path.into()), header, key, mem_blobs: HashMap::new() }, state))
        } else {
            let kdf = if fast_kdf_for_tests { KDF_TEST } else { KDF_ARGON2ID };
            let salt: [u8; SALT_LEN] = random_bytes();
            let mut header = [0u8; HEADER_LEN];
            header[..MAGIC.len()].copy_from_slice(MAGIC);
            header[MAGIC.len()] = kdf;
            header[MAGIC.len() + 1..].copy_from_slice(&salt);
            let store = Self { path: Some(path.into()), header, key: derive(kdf, passphrase, &salt)?, mem_blobs: HashMap::new() };
            let state = State::default();
            store.save(&state)?;
            Ok((store, state))
        }
    }

    pub fn save(&self, state: &State) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let mut plain = Zeroizing::new(Vec::new());
        ciborium::into_writer(state, &mut *plain).map_err(store_err)?;
        let mut out = self.header.to_vec();
        out.extend(seal_random(&self.key, &plain, &self.header));
        write_atomic(path, &out)
    }

    fn blob_dir(&self) -> Option<PathBuf> {
        self.path.as_ref().map(|p| p.with_file_name("blobs"))
    }

    fn blob_ad(name: &str) -> Vec<u8> {
        [b"lethe-blob:".as_slice(), name.as_bytes()].concat()
    }

    pub fn put_blob(&mut self, name: &str, data: &[u8]) -> Result<()> {
        check_name(name)?;
        let sealed = seal_random(&self.key, data, &Self::blob_ad(name));
        match self.blob_dir() {
            Some(dir) => {
                std::fs::create_dir_all(&dir).map_err(store_err)?;
                write_atomic(&dir.join(name), &sealed)
            }
            None => {
                self.mem_blobs.insert(name.to_string(), sealed);
                Ok(())
            }
        }
    }

    pub fn get_blob(&self, name: &str) -> Result<Vec<u8>> {
        check_name(name)?;
        let sealed = match self.blob_dir() {
            Some(dir) => std::fs::read(dir.join(name)).map_err(store_err)?,
            None => self.mem_blobs.get(name).cloned().ok_or_else(|| ClientError::Store("missing file".into()))?,
        };
        open_random(&self.key, &sealed, &Self::blob_ad(name)).map_err(|_| ClientError::Store("file is corrupted".into()))
    }

    pub fn delete_blob(&mut self, name: &str) {
        if check_name(name).is_err() {
            return;
        }
        match self.blob_dir() {
            Some(dir) => {
                let _ = std::fs::remove_file(dir.join(name));
            }
            None => {
                self.mem_blobs.remove(name);
            }
        }
    }
}

/// Blob names are generated internally (`123` or `123.4`); refuse anything else so a
/// name can never escape the blob directory.
fn check_name(name: &str) -> Result<()> {
    if !name.is_empty() && name.len() < 64 && name.chars().all(|c| c.is_ascii_digit() || c == '.') && !name.starts_with('.') {
        Ok(())
    } else {
        Err(ClientError::Store("invalid blob name".into()))
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = open_private(&tmp)?;
    f.write_all(data).map_err(store_err)?;
    f.sync_all().map_err(store_err)?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(store_err)
}

fn derive(kdf: u8, passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    match kdf {
        KDF_ARGON2ID => passphrase::derive_key(passphrase.as_bytes(), salt),
        KDF_TEST => passphrase::derive_key_insecure_for_tests(passphrase.as_bytes(), salt),
        _ => return Err(ClientError::Store("unknown key derivation".into())),
    }
    .map_err(ClientError::from)
}

fn open_private(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path).map_err(store_err)
}

fn store_err(e: impl std::fmt::Display) -> ClientError {
    ClientError::Store(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_reopen_and_wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lethe.db");
        let (store, mut state) = Store::open(&path, "correct horse", true).unwrap();
        state.next_id = 42;
        store.save(&state).unwrap();

        let (_, reopened) = Store::open(&path, "correct horse", true).unwrap();
        assert_eq!(reopened.next_id, 42);
        assert!(matches!(Store::open(&path, "wrong", true), Err(ClientError::BadPassphrase)));
    }

    #[test]
    fn tampered_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lethe.db");
        Store::open(&path, "pw", true).unwrap();
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        std::fs::write(&path, raw).unwrap();
        assert!(matches!(Store::open(&path, "pw", true), Err(ClientError::BadPassphrase)));
    }

    #[test]
    fn old_format_gives_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lethe.db");
        std::fs::write(&path, b"LETHE1\x00rest-of-old-file").unwrap();
        assert!(matches!(Store::open(&path, "pw", true), Err(ClientError::OldStore)));
    }

    #[test]
    fn blobs_are_encrypted_and_bound_to_their_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lethe.db");
        let (mut store, _) = Store::open(&path, "pw", true).unwrap();
        store.put_blob("7", b"secret picture").unwrap();
        store.put_blob("8", b"other").unwrap();
        assert_eq!(store.get_blob("7").unwrap(), b"secret picture");
        let raw = std::fs::read(dir.path().join("blobs/7")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"secret"), "stored encrypted");
        // Swapping files on disk is detected.
        std::fs::copy(dir.path().join("blobs/8"), dir.path().join("blobs/7")).unwrap();
        assert!(store.get_blob("7").is_err());
        assert!(store.put_blob("../escape", b"x").is_err());
        store.delete_blob("8");
        assert!(store.get_blob("8").is_err());
    }
}
