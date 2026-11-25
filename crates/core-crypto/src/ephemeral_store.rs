use std::collections::{BTreeMap, HashSet, VecDeque};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, fill_random};

/// Default hard bounds for local RAM history (Section 9).
pub const DEFAULT_MAX_HISTORY_ENTRIES: usize = 200;
pub const DEFAULT_MAX_HISTORY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
pub const DEFAULT_MAX_SEEN_IDS: usize = 800;

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

impl Drop for VisibleMessage {
    fn drop(&mut self) {
        self.message_id.zeroize();
        self.sender_id.zeroize();
        self.text.zeroize();
        self.started_at_ms = 0;
        self.expires_at_ms = 0;
    }
}

/// Result of inserting a message into `EphemeralHistoryStore`.
/// Enables O(1) incremental rendering without re-decrypting existing entries.
#[derive(Debug)]
pub struct InsertOutcome {
    pub inserted: Option<VisibleMessage>,
    pub evicted_ids: Vec<String>,
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
/// Deduplication state is strictly bounded via a minimum-`sent_at_ms` eviction watermark so
/// old evicted messages can never reappear even after their IDs leave the bounded set.
pub struct EphemeralHistoryStore {
    entries: VecDeque<EncryptedEntry>,
    seen_ids: HashSet<String>,
    seen_by_time: BTreeMap<(u64, u64), String>,
    next_seen_seq: u64,
    evicted_sent_at_watermark_ms: Option<u64>,
    max_seen_ids: usize,
    total_bytes: usize,
    max_entries: usize,
    max_total_bytes: usize,
}

impl Default for EphemeralHistoryStore {
    fn default() -> Self {
        Self::new_with_seen_cap(
            DEFAULT_MAX_HISTORY_ENTRIES,
            DEFAULT_MAX_HISTORY_BYTES,
            DEFAULT_MAX_SEEN_IDS,
        )
    }
}

impl EphemeralHistoryStore {
    pub fn new(max_entries: usize, max_total_bytes: usize) -> Self {
        let max_seen = max_entries.saturating_mul(4).max(64);
        Self::new_with_seen_cap(max_entries, max_total_bytes, max_seen)
    }

    pub fn new_with_seen_cap(
        max_entries: usize,
        max_total_bytes: usize,
        max_seen_ids: usize,
    ) -> Self {
        Self {
            entries: VecDeque::new(),
            seen_ids: HashSet::new(),
            seen_by_time: BTreeMap::new(),
            next_seen_seq: 0,
            evicted_sent_at_watermark_ms: None,
            max_seen_ids: max_seen_ids.max(1),
            total_bytes: 0,
            max_entries,
            max_total_bytes,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn seen_len(&self) -> usize {
        self.seen_ids.len()
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
    /// - Messages whose `sent_at_ms` is at or below the evicted watermark are rejected so old
    ///   evicted messages can never reappear after leaving the bounded deduplication set.
    /// - If `now_ms >= room_expires_at_ms`, the store wipes all entries and refuses the insert.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        message_id: String,
        sender_id: String,
        is_admin: bool,
        is_self: bool,
        plaintext: &str,
        sent_at_ms: u64,
        now_ms: u64,
        msg_ttl_secs: u64,
        room_expires_at_ms: u64,
    ) -> Result<InsertOutcome, CryptoError> {
        if now_ms >= room_expires_at_ms {
            self.wipe_all();
            return Ok(InsertOutcome {
                inserted: None,
                evicted_ids: Vec::new(),
            });
        }
        if self.seen_ids.contains(&message_id) {
            // Duplicate frame must NOT restart expiry timer.
            return Ok(InsertOutcome {
                inserted: None,
                evicted_ids: Vec::new(),
            });
        }
        if let Some(wm) = self.evicted_sent_at_watermark_ms
            && sent_at_ms <= wm
        {
            return Ok(InsertOutcome {
                inserted: None,
                evicted_ids: Vec::new(),
            });
        }

        let raw_expiry = now_ms.saturating_add(msg_ttl_secs.saturating_mul(1000));
        let expires_at_ms = raw_expiry.min(room_expires_at_ms);
        if expires_at_ms <= now_ms {
            return Ok(InsertOutcome {
                inserted: None,
                evicted_ids: Vec::new(),
            });
        }

        let mut key = Zeroizing::new([0u8; 32]);
        fill_random(&mut *key)?;
        let mut nonce = [0u8; 12];
        fill_random(&mut nonce)?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|e| CryptoError::AeadError(e.to_string()))?;

        let visible = VisibleMessage {
            message_id: message_id.clone(),
            sender_id: sender_id.clone(),
            is_admin,
            is_self,
            text: plaintext.to_string(),
            started_at_ms: now_ms,
            expires_at_ms,
        };

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
        self.record_seen_id(message_id, sent_at_ms);
        self.total_bytes = self.total_bytes.saturating_add(entry_bytes);
        self.entries.push_back(entry);

        let evicted_ids = self.enforce_bounds();
        let inserted = if evicted_ids.iter().any(|id| id == &visible.message_id) {
            None
        } else {
            Some(visible)
        };
        Ok(InsertOutcome {
            inserted,
            evicted_ids,
        })
    }

    fn record_seen_id(&mut self, message_id: String, sent_at_ms: u64) {
        while self.seen_ids.len() >= self.max_seen_ids {
            let Some(((oldest_sent_at, _), oldest_id)) = self.seen_by_time.pop_first() else {
                break;
            };
            self.seen_ids.remove(&oldest_id);
            self.evicted_sent_at_watermark_ms = Some(
                self.evicted_sent_at_watermark_ms
                    .map_or(oldest_sent_at, |wm| wm.max(oldest_sent_at)),
            );
        }
        let seq = self.next_seen_seq;
        self.next_seen_seq = self.next_seen_seq.wrapping_add(1);
        self.seen_ids.insert(message_id.clone());
        self.seen_by_time.insert((sent_at_ms, seq), message_id);
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
    ) -> Vec<String> {
        if now_ms >= new_room_expires_at_ms {
            let removed: Vec<String> = self.entries.iter().map(|e| e.message_id.clone()).collect();
            self.wipe_all();
            return removed;
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

    /// Removes and zeroizes all expired entries, returning their `message_id`s.
    /// If the room itself expired, wipes everything.
    pub fn prune_expired(&mut self, now_ms: u64, room_expires_at_ms: u64) -> Vec<String> {
        if now_ms >= room_expires_at_ms {
            let removed: Vec<String> = self.entries.iter().map(|e| e.message_id.clone()).collect();
            self.wipe_all();
            return removed;
        }

        let mut removed = Vec::new();
        let mut kept = VecDeque::with_capacity(self.entries.len());
        let mut new_bytes = 0usize;

        while let Some(mut entry) = self.entries.pop_front() {
            if now_ms >= entry.expires_at_ms {
                removed.push(entry.message_id.clone());
                entry.wipe();
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
    /// Intermediate plaintext byte buffers are wrapped in `Zeroizing` so they are wiped on all paths.
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
            let plain = Zeroizing::new(
                cipher
                    .decrypt(Nonce::from_slice(&entry.nonce), entry.ciphertext.as_slice())
                    .map_err(|e| CryptoError::AeadError(e.to_string()))?,
            );
            let text = std::str::from_utf8(&plain)
                .map_err(|e| CryptoError::CodecError(e.to_string()))?
                .to_string();
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
        self.seen_by_time.clear();
        self.evicted_sent_at_watermark_ms = None;
        self.next_seen_seq = 0;
        self.total_bytes = 0;
    }

    fn enforce_bounds(&mut self) -> Vec<String> {
        let mut evicted_ids = Vec::new();
        while self.entries.len() > self.max_entries || self.total_bytes > self.max_total_bytes {
            if let Some(mut evicted) = self.entries.pop_front() {
                evicted_ids.push(evicted.message_id.clone());
                self.total_bytes = self.total_bytes.saturating_sub(evicted.approx_bytes());
                evicted.wipe();
            } else {
                break;
            }
        }
        evicted_ids
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
        let r1 = store
            .insert(
                "m1".into(),
                "u1".into(),
                true,
                true,
                "hi",
                1000,
                1000,
                300,
                room_exp,
            )
            .unwrap();
        assert!(r1.inserted.is_some());
        // Same message_id arrives later: must NOT extend expiry beyond 301_000.
        let r2 = store
            .insert(
                "m1".into(),
                "u1".into(),
                true,
                true,
                "hi",
                1000,
                50_000,
                300,
                room_exp,
            )
            .unwrap();
        assert!(r2.inserted.is_none());
        assert_eq!(store.next_expiry_ms(), Some(301_000));
    }

    #[test]
    fn bounded_seen_ids_prevents_evicted_old_messages_from_reappearing() {
        let mut store = EphemeralHistoryStore::new_with_seen_cap(3, 64 * 1024, 5);
        let room_exp = 10_000_000;
        for i in 1..=8u64 {
            let res = store
                .insert(
                    format!("m{i}"),
                    "u1".into(),
                    false,
                    false,
                    &format!("msg {i}"),
                    i * 1000,
                    i * 1000,
                    300,
                    room_exp,
                )
                .unwrap();
            assert!(res.inserted.is_some());
        }
        assert!(store.seen_len() <= 5);
        assert_eq!(store.len(), 3);

        // Replaying evicted old message m1 (sent_at_ms = 1000) MUST be rejected!
        let replay = store
            .insert(
                "m1".into(),
                "u1".into(),
                false,
                false,
                "msg 1",
                1000,
                9000,
                300,
                room_exp,
            )
            .unwrap();
        assert!(replay.inserted.is_none());

        // A genuinely new message (sent_at_ms = 9000) is still accepted.
        let fresh = store
            .insert(
                "m9".into(),
                "u1".into(),
                false,
                false,
                "msg 9",
                9000,
                9000,
                300,
                room_exp,
            )
            .unwrap();
        assert!(fresh.inserted.is_some());
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
