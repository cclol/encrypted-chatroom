use serde::{Deserialize, Serialize};

use crate::CryptoError;

/// Allowed message lifetime choices in seconds: 5m, 30m (default), 1h.
pub const ALLOWED_MESSAGE_TTL_SECS: [u64; 3] = [300, 1800, 3600];
pub const DEFAULT_MESSAGE_TTL_SECS: u64 = 1800;

/// Allowed room lifetime choices in seconds: 5m, 30m, 1h (default).
pub const ALLOWED_ROOM_TTL_SECS: [u64; 3] = [300, 1800, 3600];
pub const DEFAULT_ROOM_TTL_SECS: u64 = 3600;

/// Hard maximum room duration from creation (1 hour).
pub const MAX_ROOM_LIFETIME_SECS: u64 = 3600;

/// Reconnect grace period when a participant disconnects while at least one other socket remains open.
pub const RECONNECT_GRACE_SECS: u64 = 60;

/// Maximum room retention & admin resume grace period after the last socket disconnects
/// while at least one valid, unconsumed invite exists (capped at invite & room expiry).
pub const INVITE_HOLD_MAX_SECS: u64 = 300;

/// Hard maximum participants per room (1 admin + up to 3 guests).
pub const MAX_ROOM_MEMBERS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomPolicy {
    pub msg_ttl_secs: u64,
    pub room_ttl_secs: u64,
}

impl Default for RoomPolicy {
    fn default() -> Self {
        Self {
            msg_ttl_secs: DEFAULT_MESSAGE_TTL_SECS,
            room_ttl_secs: DEFAULT_ROOM_TTL_SECS,
        }
    }
}

impl RoomPolicy {
    pub fn new(msg_ttl_secs: u64, room_ttl_secs: u64) -> Result<Self, CryptoError> {
        let policy = Self {
            msg_ttl_secs,
            room_ttl_secs,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if !ALLOWED_MESSAGE_TTL_SECS.contains(&self.msg_ttl_secs) {
            return Err(CryptoError::InvalidPolicy(format!(
                "unsupported message TTL {}s (allowed: 300, 1800, 3600)",
                self.msg_ttl_secs
            )));
        }
        if !ALLOWED_ROOM_TTL_SECS.contains(&self.room_ttl_secs) {
            return Err(CryptoError::InvalidPolicy(format!(
                "unsupported room TTL {}s (allowed: 300, 1800, 3600)",
                self.room_ttl_secs
            )));
        }
        Ok(())
    }

    /// Computes room expiry timestamp in milliseconds relative to the original room creation time,
    /// always capped at `MAX_ROOM_LIFETIME_SECS` (1 hour) after creation.
    pub fn compute_room_expires_at_ms(&self, room_created_at_ms: u64) -> u64 {
        let capped_secs = self.room_ttl_secs.min(MAX_ROOM_LIFETIME_SECS);
        room_created_at_ms.saturating_add(capped_secs.saturating_mul(1000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_allowed_ttls() {
        assert!(RoomPolicy::new(300, 3600).is_ok());
        assert!(RoomPolicy::new(1800, 1800).is_ok());
        assert!(RoomPolicy::new(3600, 300).is_ok());
        assert!(RoomPolicy::new(60, 3600).is_err());
        assert!(RoomPolicy::new(1800, 7200).is_err());
    }

    #[test]
    fn caps_room_expiry_from_creation_time() {
        let p = RoomPolicy::new(1800, 300).unwrap();
        assert_eq!(p.compute_room_expires_at_ms(1_000_000), 1_300_000);

        let p_max = RoomPolicy {
            msg_ttl_secs: 1800,
            room_ttl_secs: 9999,
        };
        assert_eq!(p_max.compute_room_expires_at_ms(1_000_000), 4_600_000);
    }
}
