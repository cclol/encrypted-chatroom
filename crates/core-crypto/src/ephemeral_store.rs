use std::collections::{HashSet, VecDeque};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, fill_random};

/// Default hard bounds for local RAM history (Section 9).
pub const DEFAULT_MAX_HISTORY_ENTRIES: usize = 200;
pub const DEFAULT_MAX_HISTORY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleMessage {
    pub message_id: String,
    pub sender_id: String,
    pub is_admin: bool,
    pub is_self: bool,
    pub text: String,
    pub started_at_ms: u64,
    pub expires_at_ms: u64,
}

struct EncryptedEntry {
    message_id: String,
    sender_id: String,
    is_admin: bool,
    is_self: bool,
    started_at_ms: u64,
    expires_at_ms: u64,
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedEntry {
    fn wipe(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
        self.ciphertext.zeroize();
        self.ciphertext.clear();
        self.message_id.zeroize();
        self.sender_id.zeroize();
    }

    fn approx_bytes(&self) -> usize {
        self.ciphertext.len() + self.message_id.len() + self.sender_id.len() + 64
    }
}

impl Drop for EncryptedEntry {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Ephemeral encrypted RAM history store.
///
/// Each message is encrypted under its own fresh random 256-bit ChaCha20-Poly1305 key.
/// Expired or evicted entries overwrite their controlled key and ciphertext buffers before drop.
pub struct EphemeralHistoryStore {
    entries: VecDeque<EncryptedEntry>,
    seen_ids: HashSet<String>,
    total_bytes: usize,
    max_entries: usize,
    max_total_bytes: usize,
}

impl Default for EphemeralHistoryStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_HISTORY_ENTRIES, DEFAULT_MAX_HISTORY_BYTES)
    }
}

impl EphemeralHistoryStore {
    pub fn new(max_entries: usize, max_total_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            seen_ids: HashSet::new(),
            total_bytes: 0,
            max_entries,
            max_total_bytes,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Inserts a plaintext message encrypted with a fresh per-entry random key.
    ///
    /// - Duplicate `message_id` values are ignored and do NOT restart expiry timers (Section 3).
    /// - If `now_ms >= room_expires_at_ms`, the store wipes all entries and refuses the insert.
    /// - Returns `Ok(true)` if inserted, `Ok(false)` if duplicate or already expired.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        message_id: String,
        sender_id: String,
        is_admin: bool,
        is_self: bool,
        plaintext: &str,
        now_ms: u64,
        msg_ttl_secs: u64,
        room_expires_at_ms: u64,
    ) -> Result<bool, CryptoError> {
        if now_ms >= room_expires_at_ms {
            self.wipe_all();
            return Ok(false);
        }
        if self.seen_ids.contains(&message_id) {
            // Duplicate frame must NOT restart expiry timer.
            return Ok(false);
        }

        let raw_expiry = now_ms.saturating_add(msg_ttl_secs.saturating_mul(1000));
        let expires_at_ms = raw_expiry.min(room_expires_at_ms);
        if expires_at_ms <= now_ms {
            return Ok(false);
        }

        let mut key = Zeroizing::new([0u8; 32]);
        fill_random(&mut *key)?;
        let mut nonce = [0u8; 12];
        fill_random(&mut nonce)?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|e| CryptoError::AeadError(e.to_string()))?;

        let entry = EncryptedEntry {
            message_id: message_id.clone(),
            sender_id,
            is_admin,
            is_self,
            started_at_ms: now_ms,
            expires_at_ms,
            key,
            nonce,
            ciphertext,
        };

        let entry_bytes = entry.approx_bytes();
        self.seen_ids.insert(message_id);
        self.total_bytes = self.total_bytes.saturating_add(entry_bytes);
        self.entries.push_back(entry);

        self.enforce_bounds();
        Ok(true)
    }

    /// Applies updated room/message lifetimes according to Section 3:
    /// - Shorter message TTL shortens existing entries relative to their original `started_at_ms`.
    /// - Longer message TTL does NOT extend existing entries (only affects future messages).
    /// - All entries are clamped to `new_room_expires_at_ms`.
    pub fn apply_policy_change(
        &mut self,
        new_msg_ttl_secs: u64,
        new_room_expires_at_ms: u64,
        now_ms: u64,
    ) -> usize {
        if now_ms >= new_room_expires_at_ms {
            let count = self.entries.len();
            self.wipe_all();
            return count;
        }
        let ttl_ms = new_msg_ttl_secs.saturating_mul(1000);
        for entry in &mut self.entries {
            let shortened = entry.started_at_ms.saturating_add(ttl_ms);
            // Taking `.min()` guarantees shorter TTL applies retroactively while longer TTL never extends.
            entry.expires_at_ms = entry
                .expires_at_ms
                .min(shortened)
                .min(new_room_expires_at_ms);
        }
        self.prune_expired(now_ms, new_room_expires_at_ms)
    }

    /// Removes and zeroizes all expired entries. If the room itself expired, wipes everything.
    pub fn prune_expired(&mut self, now_ms: u64, room_expires_at_ms: u64) -> usize {
        if now_ms >= room_expires_at_ms {
            let count = self.entries.len();
            self.wipe_all();
            return count;
        }

        let mut removed = 0usize;
        let mut kept = VecDeque::with_capacity(self.entries.len());
        let mut new_bytes = 0usize;

        while let Some(mut entry) = self.entries.pop_front() {
            if now_ms >= entry.expires_at_ms {
                entry.wipe();
                removed += 1;
            } else {
                new_bytes = new_bytes.saturating_add(entry.approx_bytes());
                kept.push_back(entry);
            }
        }

        self.entries = kept;
        self.total_bytes = new_bytes;
        removed
    }

    /// Returns the earliest expiry timestamp among stored entries, if any.
    pub fn next_expiry_ms(&self) -> Option<u64> {
        self.entries.iter().map(|e| e.expires_at_ms).min()
    }

    /// Decrypts ONLY currently valid entries after checking room expiry and pruning expired entries.
    pub fn decrypt_visible(
        &mut self,
        now_ms: u64,
        room_expires_at_ms: u64,
    ) -> Result<Vec<VisibleMessage>, CryptoError> {
        self.prune_expired(now_ms, room_expires_at_ms);
        if now_ms >= room_expires_at_ms {
            return Ok(Vec::new());
        }

        let mut visible = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&*entry.key));
            let mut plain = cipher
                .decrypt(Nonce::from_slice(&entry.nonce), entry.ciphertext.as_slice())
                .map_err(|e| CryptoError::AeadError(e.to_string()))?;
            let text = String::from_utf8(plain.clone())
                .map_err(|e| CryptoError::CodecError(e.to_string()))?;
            plain.zeroize();
            visible.push(VisibleMessage {
                message_id: entry.message_id.clone(),
                sender_id: entry.sender_id.clone(),
                is_admin: entry.is_admin,
                is_self: entry.is_self,
                text,
                started_at_ms: entry.started_at_ms,
                expires_at_ms: entry.expires_at_ms,
            });
        }
        Ok(visible)
    }

    /// Immediately overwrites and discards all stored entries and deduplication state.
    pub fn wipe_all(&mut self) {
        while let Some(mut entry) = self.entries.pop_front() {
            entry.wipe();
        }
        self.seen_ids.clear();
        self.total_bytes = 0;
    }

    fn enforce_bounds(&mut self) {
        while self.entries.len() > self.max_entries || self.total_bytes > self.max_total_bytes {
            if let Some(mut evicted) = self.entries.pop_front() {
                self.total_bytes = self.total_bytes.saturating_sub(evicted.approx_bytes());
                evicted.wipe();
            } else {
                break;
            }
        }
    }
}

impl Drop for EphemeralHistoryStore {
    fn drop(&mut self) {
        self.wipe_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_frame_does_not_restart_timer() {
        let mut store = EphemeralHistoryStore::default();
        let room_exp = 10_000_000;
        assert!(
            store
                .insert(
                    "m1".into(),
                    "u1".into(),
                    true,
                    true,
                    "hi",
                    1000,
                    300,
                    room_exp
                )
                .unwrap()
        );
        // Same message_id arrives later: must NOT extend expiry beyond 301_000.
        assert!(
            !store
                .insert(
                    "m1".into(),
                    "u1".into(),
                    true,
                    true,
                    "hi",
                    50_000,
                    300,
                    room_exp
                )
                .unwrap()
        );
        assert_eq!(store.next_expiry_ms(), Some(301_000));
    }

    #[test]
    fn shorter_ttl_applies_retroactively_longer_ttl_only_for_new() {
        let mut store = EphemeralHistoryStore::default();
        let room_exp = 5_000_000;
        // Created at t=1000 with 30m (1800s) -> expires at 1_801_000.
        store
            .insert(
                "m1".into(),
                "u1".into(),
                true,
                true,
                "first",
                1000,
                1800,
                room_exp,
            )
            .unwrap();

        // Lengthen to 1h (3600s) -> existing entry must still expire at 1_801_000.
        store.apply_policy_change(3600, room_exp, 2000);
        assert_eq!(store.next_expiry_ms(), Some(1_801_000));

        // Shorten to 5m (300s) -> existing entry must now expire at 1000 + 300_000 = 301_000.
        store.apply_policy_change(300, room_exp, 3000);
        assert_eq!(store.next_expiry_ms(), Some(301_000));

        // At t=301_000 it must be pruned and invisible.
        let visible = store.decrypt_visible(301_000, room_exp).unwrap();
        assert!(visible.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn room_expiry_wipes_all_messages_even_if_msg_ttl_remains() {
        let mut store = EphemeralHistoryStore::default();
        store
            .insert(
                "m1".into(),
                "u1".into(),
                false,
                false,
                "secret",
                1000,
                3600,
                50_000,
            )
            .unwrap();
        let visible = store.decrypt_visible(50_000, 50_000).unwrap();
        assert!(visible.is_empty());
        assert!(store.is_empty());
    }
}
