use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, sha256_hex};

/// Version prefix for v1 copyable room codes.
pub const ROOM_CODE_VERSION: &str = "geistr1";

/// Maximum display name length (in Unicode scalar values) for room orientation.
pub const ROOM_NAME_MAX_CHARS: usize = 48;

/// Sanitizes an optional room display name for UI orientation only.
/// Strips control characters, collapses surrounding whitespace, caps length, and maps empty to `None`.
pub fn sanitize_room_name(raw: Option<&str>) -> Option<String> {
    let s = raw?;
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(ROOM_NAME_MAX_CHARS)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Parsed v1 room code: `geistr1.<room_id>.<access_secret>.<admin_fingerprint>`.
/// Automatically zeroizes all fields when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct RoomCode {
    pub room_id: String,
    pub access_secret: String,
    pub admin_fingerprint: String,
}

impl std::fmt::Debug for RoomCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomCode")
            .field("room_id", &"<redacted>")
            .field("access_secret", &"<redacted>")
            .field("admin_fingerprint", &"<redacted>")
            .finish()
    }
}

impl Drop for RoomCode {
    fn drop(&mut self) {
        self.room_id.zeroize();
        self.access_secret.zeroize();
        self.admin_fingerprint.zeroize();
    }
}

impl RoomCode {
    pub fn new(
        room_id: impl Into<String>,
        access_secret: impl Into<String>,
        admin_fingerprint: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let code = Self {
            room_id: room_id.into(),
            access_secret: access_secret.into(),
            admin_fingerprint: admin_fingerprint.into(),
        };
        code.validate()?;
        Ok(code)
    }

    /// Encodes the room code into a single copy/paste-friendly string.
    pub fn encode(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{ROOM_CODE_VERSION}.{}.{}.{}",
            self.room_id, self.access_secret, self.admin_fingerprint
        ))
    }

    /// Parses a pasted room code, tolerating whitespace and invisible formatting characters
    /// that mobile messaging apps may insert when wrapping or copying text.
    pub fn parse(raw: &str) -> Result<Self, CryptoError> {
        let cleaned = Zeroizing::new(
            raw.chars()
                .filter(|c| !c.is_whitespace() && !is_invisible_separator(*c))
                .collect::<String>(),
        );
        let mut parts = cleaned.split('.');
        let version = parts
            .next()
            .ok_or_else(|| CryptoError::CodecError("missing room code version".into()))?;
        let room_id = parts
            .next()
            .ok_or_else(|| CryptoError::CodecError("missing room id".into()))?;
        let access_secret = parts
            .next()
            .ok_or_else(|| CryptoError::CodecError("missing access secret".into()))?;
        let admin_fingerprint = parts
            .next()
            .ok_or_else(|| CryptoError::CodecError("missing admin fingerprint".into()))?;
        if parts.next().is_some() {
            return Err(CryptoError::CodecError(
                "unexpected extra segments in room code".into(),
            ));
        }
        if version != ROOM_CODE_VERSION {
            return Err(CryptoError::CodecError(format!(
                "unsupported room code version: {version}"
            )));
        }
        Self::new(room_id, access_secret, admin_fingerprint)
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        let room_id_bytes = URL_SAFE_NO_PAD
            .decode(&self.room_id)
            .map_err(|_| CryptoError::CodecError("invalid room_id encoding".into()))?;
        if !(8..=32).contains(&room_id_bytes.len()) {
            return Err(CryptoError::CodecError("invalid room_id length".into()));
        }

        let mut secret_bytes = URL_SAFE_NO_PAD
            .decode(&self.access_secret)
            .map_err(|_| CryptoError::CodecError("invalid access_secret encoding".into()))?;
        let secret_len = secret_bytes.len();
        secret_bytes.zeroize();
        if !(16..=64).contains(&secret_len) {
            return Err(CryptoError::CodecError(
                "invalid access_secret length".into(),
            ));
        }

        let fp_bytes = URL_SAFE_NO_PAD
            .decode(&self.admin_fingerprint)
            .map_err(|_| CryptoError::CodecError("invalid admin_fingerprint encoding".into()))?;
        if fp_bytes.len() != 32 {
            return Err(CryptoError::CodecError(
                "invalid admin_fingerprint length".into(),
            ));
        }
        Ok(())
    }

    pub fn secret_hash_hex(&self) -> String {
        sha256_hex(self.access_secret.as_bytes())
    }
}

fn is_invisible_separator(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' // ZERO WIDTH SPACE
        | '\u{200C}' // ZERO WIDTH NON-JOINER
        | '\u{200D}' // ZERO WIDTH JOINER
        | '\u{2060}' // WORD JOINER
        | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE / BOM
    )
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Reconciles the admin worker's local confirmed and pending room codes against the
/// authoritative relay snapshot delivered in `SessionResumed`.
///
/// Guarantees that after reconnect/resume:
/// - If `RoomCodeUpdated` was lost after initial creation or rotation, the matching pending
///   code is promoted to active.
/// - If a pending rotation never reached the relay, the previously confirmed code remains active.
/// - If the relay has no active code, it expired, or its hash matches no local code,
///   no stale code is exposed to the UI.
pub fn reconcile_room_code_on_resume(
    active_room_code: &mut Option<(RoomCode, u64)>,
    pending_room_codes: &mut HashMap<String, RoomCode>,
    relay_secret_hash_hex: Option<&str>,
    relay_expires_at_ms: Option<u64>,
    room_expires_at_ms: u64,
    now_ms: u64,
) {
    let Some((relay_hash, relay_exp)) = relay_secret_hash_hex.zip(relay_expires_at_ms) else {
        *active_room_code = None;
        pending_room_codes.clear();
        return;
    };

    let effective_exp = if room_expires_at_ms > 0 {
        relay_exp.min(room_expires_at_ms)
    } else {
        relay_exp
    };
    if now_ms >= effective_exp {
        *active_room_code = None;
        pending_room_codes.clear();
        return;
    }

    if let Some(promoted) = pending_room_codes.remove(relay_hash) {
        *active_room_code = Some((promoted, effective_exp));
        pending_room_codes.clear();
        return;
    }

    let active_matches = active_room_code
        .as_ref()
        .is_some_and(|(code, _)| ct_eq_str(&code.secret_hash_hex(), relay_hash));
    if active_matches {
        if let Some((_, cur_exp)) = active_room_code.as_mut() {
            *cur_exp = (*cur_exp).min(effective_exp);
        }
    } else {
        *active_room_code = None;
    }
    pending_room_codes.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::AdminSigningKey;
    use crate::random_token_b64url;

    #[test]
    fn room_code_roundtrips_and_tolerates_mobile_paste_whitespace() {
        let room_id = random_token_b64url(16).unwrap();
        let secret = random_token_b64url(24).unwrap();
        let admin = AdminSigningKey::generate(&room_id).unwrap();
        let fp = admin.fingerprint();

        let code = RoomCode::new(&room_id, &secret, &fp).unwrap();
        let encoded = code.encode();
        assert!(encoded.starts_with("geistr1."));

        let parsed = RoomCode::parse(&encoded).unwrap();
        assert_eq!(parsed.room_id, room_id);
        assert_eq!(parsed.access_secret, secret);
        assert_eq!(parsed.admin_fingerprint, fp);
        assert_eq!(parsed.secret_hash_hex(), sha256_hex(secret.as_bytes()));

        // Simulate mobile messaging app line-wrapping, spaces, and zero-width chars.
        let messy = format!(
            "  \u{FEFF}{}\n\t  {}\r\n\u{200B}{} ",
            &encoded[..12],
            &encoded[12..35],
            &encoded[35..]
        );
        let parsed_messy = RoomCode::parse(&messy).unwrap();
        assert_eq!(parsed_messy.room_id, room_id);
        assert_eq!(parsed_messy.access_secret, secret);
        assert_eq!(parsed_messy.admin_fingerprint, fp);
    }

    #[test]
    fn room_code_rejects_invalid_version_segments_and_lengths() {
        let room_id = random_token_b64url(16).unwrap();
        let secret = random_token_b64url(24).unwrap();
        let admin = AdminSigningKey::generate(&room_id).unwrap();
        let fp = admin.fingerprint();

        assert!(RoomCode::parse(&format!("geistr2.{room_id}.{secret}.{fp}")).is_err());
        assert!(RoomCode::parse(&format!("geistr1.{room_id}.{secret}")).is_err());
        assert!(RoomCode::parse(&format!("geistr1.{room_id}.{secret}.{fp}.extra")).is_err());
        assert!(RoomCode::parse(&format!("geistr1.short.{secret}.{fp}")).is_err());
        assert!(RoomCode::parse(&format!("geistr1.{room_id}.short.{fp}")).is_err());
        assert!(RoomCode::parse(&format!("geistr1.{room_id}.{secret}.not32bytes")).is_err());
        assert!(RoomCode::parse("").is_err());
    }

    #[test]
    fn sanitize_room_name_trims_strips_controls_and_caps_length() {
        assert_eq!(sanitize_room_name(None), None);
        assert_eq!(sanitize_room_name(Some("   \t\n  ")), None);
        assert_eq!(
            sanitize_room_name(Some("  Team\x00 Sync\n ")),
            Some("Team Sync".into())
        );
        let long = "a".repeat(80);
        assert_eq!(
            sanitize_room_name(Some(&long)).unwrap().chars().count(),
            ROOM_NAME_MAX_CHARS
        );
    }

    #[test]
    fn reconcile_on_resume_promotes_pending_initial_and_rotated_codes_and_drops_stale() {
        let room_id = random_token_b64url(16).unwrap();
        let admin = AdminSigningKey::generate(&room_id).unwrap();
        let fp = admin.fingerprint();
        let code1 = RoomCode::new(&room_id, random_token_b64url(24).unwrap(), &fp).unwrap();
        let code2 = RoomCode::new(&room_id, random_token_b64url(24).unwrap(), &fp).unwrap();
        let code3 = RoomCode::new(&room_id, random_token_b64url(24).unwrap(), &fp).unwrap();

        let now = 10_000u64;
        let room_exp = 100_000u64;

        // 1. Initial creation with lost RoomCodeUpdated -> pending code1 is promoted.
        let mut active = None;
        let mut pending = HashMap::new();
        pending.insert(code1.secret_hash_hex(), code1.clone());
        reconcile_room_code_on_resume(
            &mut active,
            &mut pending,
            Some(&code1.secret_hash_hex()),
            Some(50_000),
            room_exp,
            now,
        );
        assert!(pending.is_empty());
        assert_eq!(
            active.as_ref().map(|(c, exp)| (c.clone(), *exp)),
            Some((code1.clone(), 50_000))
        );

        // 2. Rotation with lost RoomCodeUpdated -> pending code2 replaces active code1.
        pending.insert(code2.secret_hash_hex(), code2.clone());
        reconcile_room_code_on_resume(
            &mut active,
            &mut pending,
            Some(&code2.secret_hash_hex()),
            Some(60_000),
            room_exp,
            now,
        );
        assert!(pending.is_empty());
        assert_eq!(
            active.as_ref().map(|(c, exp)| (c.clone(), *exp)),
            Some((code2.clone(), 60_000))
        );

        // 3. Rotation never reached relay -> relay still reports code2, so code2 stays active and pending code3 is discarded.
        pending.insert(code3.secret_hash_hex(), code3.clone());
        reconcile_room_code_on_resume(
            &mut active,
            &mut pending,
            Some(&code2.secret_hash_hex()),
            Some(55_000),
            room_exp,
            now,
        );
        assert!(pending.is_empty());
        assert_eq!(
            active.as_ref().map(|(c, exp)| (c.clone(), *exp)),
            Some((code2.clone(), 55_000))
        );

        // 4. Unknown relay hash -> local active code is cleared so UI never shows an invalid code.
        reconcile_room_code_on_resume(
            &mut active,
            &mut pending,
            Some(&code3.secret_hash_hex()),
            Some(70_000),
            room_exp,
            now,
        );
        assert!(active.is_none());

        // 5. Revoked on relay (None) -> local active & pending codes are cleared.
        active = Some((code2.clone(), 55_000));
        pending.insert(code3.secret_hash_hex(), code3);
        reconcile_room_code_on_resume(&mut active, &mut pending, None, None, room_exp, now);
        assert!(active.is_none());
        assert!(pending.is_empty());
    }
}
