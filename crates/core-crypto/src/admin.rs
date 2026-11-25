use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::policy::RoomPolicy;
use crate::{CryptoError, fill_random};

const ADMIN_FP_DOMAIN: &[u8] = b"geistr-admin-fp-v1";
const ADMIN_CMD_DOMAIN: &[u8] = b"geistr-admin-cmd-v1";
const ADMIN_MLS_BINDING_DOMAIN: &[u8] = b"geistr-admin-mls-binding-v1";

/// Dedicated Ed25519 signing keypair for room admin control commands.
/// Kept strictly separate from MLS identity keys, local RAM history keys, and resume tokens.
pub struct AdminSigningKey {
    signing_key: SigningKey,
    room_id: String,
    next_seq: u64,
}

impl Drop for AdminSigningKey {
    fn drop(&mut self) {
        // ed25519-dalek SigningKey zeroizes on drop when the `zeroize` feature is enabled,
        // and we also clear room metadata.
        self.room_id.zeroize();
        self.next_seq = 0;
    }
}

impl AdminSigningKey {
    /// Generates a fresh Ed25519 signing keypair bound to `room_id`.
    pub fn generate(room_id: impl Into<String>) -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_random(&mut *seed)?;
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self {
            signing_key,
            room_id: room_id.into(),
            next_seq: 1,
        })
    }

    pub fn rebind_room(&mut self, room_id: impl Into<String>) {
        self.room_id = room_id.into();
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn verifying_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.verifying_key_bytes())
    }

    /// Computes the admin fingerprint bound to this room instance, safe to include in invite URL fragments.
    pub fn fingerprint(&self) -> String {
        compute_admin_fingerprint(&self.verifying_key_bytes(), &self.room_id)
    }

    /// Signs a domain-separated binding that cryptographically links this invite-anchored
    /// AdminSigningKey to the actual MLS Ed25519 signature public key for this room instance.
    pub fn sign_mls_binding(&self, participant_id: &str, mls_signature_pubkey: &[u8]) -> String {
        let msg = canonical_mls_binding_bytes(&self.room_id, participant_id, mls_signature_pubkey);
        let sig = self.signing_key.sign(&msg);
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }

    /// Signs a new admin control command with a strictly monotonically increasing sequence number.
    pub fn sign_command(
        &mut self,
        epoch: u64,
        payload: AdminCommandPayload,
    ) -> Result<SignedAdminCommand, CryptoError> {
        let body = AdminCommandBody {
            room_id: self.room_id.clone(),
            epoch,
            seq: self.next_seq,
            payload,
        };
        let canonical = canonical_command_bytes(&body)?;
        let sig = self.signing_key.sign(&canonical);
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| CryptoError::InvalidSignature("sequence overflow".into()))?;
        Ok(SignedAdminCommand {
            body,
            signature_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        })
    }
}

fn canonical_mls_binding_bytes(
    room_id: &str,
    participant_id: &str,
    mls_signature_pubkey: &[u8],
) -> Vec<u8> {
    let role = b"admin";
    let mut out = Vec::with_capacity(
        ADMIN_MLS_BINDING_DOMAIN.len()
            + 4
            + room_id.len()
            + 4
            + participant_id.len()
            + 4
            + role.len()
            + 4
            + mls_signature_pubkey.len(),
    );
    out.extend_from_slice(ADMIN_MLS_BINDING_DOMAIN);
    out.extend_from_slice(&(room_id.len() as u32).to_be_bytes());
    out.extend_from_slice(room_id.as_bytes());
    out.extend_from_slice(&(participant_id.len() as u32).to_be_bytes());
    out.extend_from_slice(participant_id.as_bytes());
    out.extend_from_slice(&(role.len() as u32).to_be_bytes());
    out.extend_from_slice(role);
    out.extend_from_slice(&(mls_signature_pubkey.len() as u32).to_be_bytes());
    out.extend_from_slice(mls_signature_pubkey);
    out
}

/// Verifies that `mls_signature_pubkey` is cryptographically bound to `admin_pubkey_bytes`
/// for the given `room_id`, `participant_id`, and `admin` role.
pub fn verify_mls_admin_binding(
    admin_pubkey_bytes: &[u8; 32],
    room_id: &str,
    participant_id: &str,
    mls_signature_pubkey: &[u8],
    binding_sig_b64: &str,
) -> Result<(), CryptoError> {
    if mls_signature_pubkey.is_empty() {
        return Err(CryptoError::AdminVerificationFailed(
            "empty MLS signature public key".into(),
        ));
    }
    let vk = VerifyingKey::from_bytes(admin_pubkey_bytes)
        .map_err(|e| CryptoError::AdminVerificationFailed(format!("invalid admin pubkey: {e}")))?;
    let sig_raw = URL_SAFE_NO_PAD.decode(binding_sig_b64).map_err(|e| {
        CryptoError::AdminVerificationFailed(format!("invalid MLS binding signature b64: {e}"))
    })?;
    let sig_arr: [u8; 64] = sig_raw.try_into().map_err(|_| {
        CryptoError::AdminVerificationFailed("MLS binding signature must be 64 bytes".into())
    })?;
    let signature = Signature::from_bytes(&sig_arr);
    let msg = canonical_mls_binding_bytes(room_id, participant_id, mls_signature_pubkey);
    vk.verify(&msg, &signature).map_err(|e| {
        CryptoError::AdminVerificationFailed(format!(
            "MLS admin key binding signature verification failed: {e}"
        ))
    })
}

/// Computes the deterministic SHA-256 fingerprint binding an admin public key to a specific room instance.
pub fn compute_admin_fingerprint(pubkey_bytes: &[u8; 32], room_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ADMIN_FP_DOMAIN);
    hasher.update((room_id.len() as u32).to_be_bytes());
    hasher.update(room_id.as_bytes());
    hasher.update(pubkey_bytes);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub fn decode_pubkey_b64(pubkey_b64: &str) -> Result<[u8; 32], CryptoError> {
    let raw = URL_SAFE_NO_PAD
        .decode(pubkey_b64)
        .map_err(|e| CryptoError::CodecError(format!("invalid admin pubkey b64: {e}")))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| CryptoError::CodecError("admin pubkey must be 32 bytes".into()))?;
    // Ensure it is a valid Ed25519 point.
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| CryptoError::InvalidSignature(format!("invalid Ed25519 public key: {e}")))?;
    Ok(arr)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminCommandPayload {
    SetPolicy {
        msg_ttl_secs: u64,
        room_ttl_secs: u64,
    },
    RegisterInvite {
        token_hash_hex: String,
        invite_ttl_secs: u64,
    },
    KickGuest {
        participant_id: String,
    },
    PanicWipe,
    CloseRoom,
}

impl AdminCommandPayload {
    pub fn policy(&self) -> Option<Result<RoomPolicy, CryptoError>> {
        match self {
            AdminCommandPayload::SetPolicy {
                msg_ttl_secs,
                room_ttl_secs,
            } => Some(RoomPolicy::new(*msg_ttl_secs, *room_ttl_secs)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminCommandBody {
    pub room_id: String,
    pub epoch: u64,
    pub seq: u64,
    pub payload: AdminCommandPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAdminCommand {
    pub body: AdminCommandBody,
    pub signature_b64: String,
}

fn canonical_command_bytes(body: &AdminCommandBody) -> Result<Vec<u8>, CryptoError> {
    let json = serde_json::to_vec(body)
        .map_err(|e| CryptoError::CodecError(format!("serialize admin command: {e}")))?;
    let mut out = Vec::with_capacity(ADMIN_CMD_DOMAIN.len() + 4 + json.len());
    out.extend_from_slice(ADMIN_CMD_DOMAIN);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Stateless signature + room binding verification (useful for initial policy snapshots).
pub fn verify_admin_command_signature(
    cmd: &SignedAdminCommand,
    expected_room_id: &str,
    admin_pubkey_bytes: &[u8; 32],
) -> Result<(), CryptoError> {
    if cmd.body.room_id != expected_room_id {
        return Err(CryptoError::RoomMismatch);
    }
    if cmd.body.seq == 0 {
        return Err(CryptoError::ReplayDetected);
    }
    let vk = VerifyingKey::from_bytes(admin_pubkey_bytes)
        .map_err(|e| CryptoError::InvalidSignature(format!("invalid admin pubkey: {e}")))?;
    let sig_raw = URL_SAFE_NO_PAD
        .decode(&cmd.signature_b64)
        .map_err(|e| CryptoError::InvalidSignature(format!("invalid signature b64: {e}")))?;
    let sig_arr: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);
    let canonical = canonical_command_bytes(&cmd.body)?;
    vk.verify(&canonical, &signature).map_err(|e| {
        CryptoError::InvalidSignature(format!("signature verification failed: {e}"))
    })?;

    if let Some(policy_res) = cmd.body.payload.policy() {
        policy_res?;
    }
    Ok(())
}

/// Stateful verifier that enforces signature validity, room binding, epoch binding,
/// and strictly increasing sequence numbers.
#[derive(Debug, Clone)]
pub struct AdminCommandVerifier {
    room_id: String,
    admin_pubkey_bytes: [u8; 32],
    last_seq: u64,
}

impl AdminCommandVerifier {
    pub fn new(
        room_id: impl Into<String>,
        admin_pubkey_bytes: [u8; 32],
    ) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(&admin_pubkey_bytes)
            .map_err(|e| CryptoError::InvalidSignature(format!("invalid admin pubkey: {e}")))?;
        Ok(Self {
            room_id: room_id.into(),
            admin_pubkey_bytes,
            last_seq: 0,
        })
    }

    pub fn admin_pubkey_bytes(&self) -> [u8; 32] {
        self.admin_pubkey_bytes
    }

    pub fn fingerprint(&self) -> String {
        compute_admin_fingerprint(&self.admin_pubkey_bytes, &self.room_id)
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// Validates a live admin command against the current MLS epoch WITHOUT advancing `last_seq`.
    /// Call `commit_seq(cmd.body.seq)` only after all domain/deadline/payload preconditions succeed.
    pub fn check_live(
        &self,
        cmd: &SignedAdminCommand,
        expected_epoch: u64,
    ) -> Result<(), CryptoError> {
        verify_admin_command_signature(cmd, &self.room_id, &self.admin_pubkey_bytes)?;
        if cmd.body.seq <= self.last_seq {
            return Err(CryptoError::ReplayDetected);
        }
        if cmd.body.epoch != expected_epoch {
            return Err(CryptoError::EpochMismatch {
                expected: expected_epoch,
                got: cmd.body.epoch,
            });
        }
        Ok(())
    }

    /// Commits the verified sequence number after all preconditions have passed.
    pub fn commit_seq(&mut self, seq: u64) -> Result<(), CryptoError> {
        if seq <= self.last_seq {
            return Err(CryptoError::ReplayDetected);
        }
        self.last_seq = seq;
        Ok(())
    }

    /// Convenience helper for live commands when no external preconditions remain.
    pub fn verify_and_advance_live(
        &mut self,
        cmd: &SignedAdminCommand,
        expected_epoch: u64,
    ) -> Result<(), CryptoError> {
        self.check_live(cmd, expected_epoch)?;
        self.commit_seq(cmd.body.seq)
    }

    /// Validates a historical `SetPolicy` snapshot delivered during JoinAccepted or SessionResumed.
    ///
    /// Rules:
    /// - Must be a validly signed `SetPolicy` for this room.
    /// - Its signed epoch must not exceed `current_room_epoch` (`cmd.body.epoch <= current_room_epoch`).
    /// - Its sequence number must not regress below `last_seq` (`cmd.body.seq >= last_seq`).
    ///   (Equal `seq` is allowed on SessionResumed when no new policy was issued during disconnect.)
    pub fn verify_historical_policy_snapshot(
        &mut self,
        cmd: &SignedAdminCommand,
        current_room_epoch: u64,
    ) -> Result<RoomPolicy, CryptoError> {
        verify_admin_command_signature(cmd, &self.room_id, &self.admin_pubkey_bytes)?;
        let policy = match cmd.body.payload.policy() {
            Some(Ok(p)) => p,
            Some(Err(e)) => return Err(e),
            None => {
                return Err(CryptoError::InvalidPolicy(
                    "historical policy snapshot must be a SetPolicy command".into(),
                ));
            }
        };
        if cmd.body.epoch > current_room_epoch {
            return Err(CryptoError::EpochMismatch {
                expected: current_room_epoch,
                got: cmd.body.epoch,
            });
        }
        if cmd.body.seq < self.last_seq {
            return Err(CryptoError::ReplayDetected);
        }
        if cmd.body.seq > self.last_seq {
            self.last_seq = cmd.body.seq;
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_verifies_and_rejects_replays_tampering_and_epoch_mismatch() {
        let mut signer = AdminSigningKey::generate("room-abc").unwrap();
        let mut verifier =
            AdminCommandVerifier::new("room-abc", signer.verifying_key_bytes()).unwrap();
        assert_eq!(signer.fingerprint(), verifier.fingerprint());

        let cmd1 = signer
            .sign_command(
                0,
                AdminCommandPayload::SetPolicy {
                    msg_ttl_secs: 300,
                    room_ttl_secs: 3600,
                },
            )
            .unwrap();
        // Wrong expected epoch must fail WITHOUT advancing last_seq.
        assert!(matches!(
            verifier.verify_and_advance_live(&cmd1, 1),
            Err(CryptoError::EpochMismatch {
                expected: 1,
                got: 0
            })
        ));
        assert_eq!(verifier.last_seq(), 0);

        // Matching epoch succeeds.
        assert!(verifier.verify_and_advance_live(&cmd1, 0).is_ok());
        assert_eq!(verifier.last_seq(), 1);

        // Replay must fail.
        assert!(matches!(
            verifier.verify_and_advance_live(&cmd1, 0),
            Err(CryptoError::ReplayDetected)
        ));

        // Tampered payload must fail.
        let mut cmd2 = signer
            .sign_command(1, AdminCommandPayload::PanicWipe)
            .unwrap();
        cmd2.body.epoch = 99;
        assert!(matches!(
            verifier.verify_and_advance_live(&cmd2, 99),
            Err(CryptoError::InvalidSignature(_))
        ));

        // Wrong room must fail.
        let mut other_verifier =
            AdminCommandVerifier::new("room-other", signer.verifying_key_bytes()).unwrap();
        assert!(matches!(
            other_verifier.verify_and_advance_live(&cmd1, 0),
            Err(CryptoError::RoomMismatch)
        ));
    }

    #[test]
    fn historical_policy_snapshot_rules_enforce_epoch_bound_and_no_seq_rollback() {
        let mut signer = AdminSigningKey::generate("room-hist").unwrap();
        let mut verifier =
            AdminCommandVerifier::new("room-hist", signer.verifying_key_bytes()).unwrap();

        let cmd_e0 = signer
            .sign_command(
                0,
                AdminCommandPayload::SetPolicy {
                    msg_ttl_secs: 1800,
                    room_ttl_secs: 3600,
                },
            )
            .unwrap();
        let cmd_e2 = signer
            .sign_command(
                2,
                AdminCommandPayload::SetPolicy {
                    msg_ttl_secs: 300,
                    room_ttl_secs: 1800,
                },
            )
            .unwrap();

        // Snapshot from future epoch (> current_room_epoch) must fail.
        assert!(matches!(
            verifier.verify_historical_policy_snapshot(&cmd_e2, 1),
            Err(CryptoError::EpochMismatch {
                expected: 1,
                got: 2
            })
        ));
        assert_eq!(verifier.last_seq(), 0);

        // Snapshot from epoch 0 accepted when current epoch is 3.
        let p0 = verifier
            .verify_historical_policy_snapshot(&cmd_e0, 3)
            .unwrap();
        assert_eq!(p0.msg_ttl_secs, 1800);
        assert_eq!(verifier.last_seq(), 1);

        // Newer snapshot accepted.
        let p2 = verifier
            .verify_historical_policy_snapshot(&cmd_e2, 3)
            .unwrap();
        assert_eq!(p2.msg_ttl_secs, 300);
        assert_eq!(verifier.last_seq(), 2);

        // Same seq on resume is idempotent.
        assert!(
            verifier
                .verify_historical_policy_snapshot(&cmd_e2, 3)
                .is_ok()
        );

        // Rollback to older seq is rejected.
        assert!(matches!(
            verifier.verify_historical_policy_snapshot(&cmd_e0, 3),
            Err(CryptoError::ReplayDetected)
        ));
    }

    #[test]
    fn mls_admin_binding_signature_binds_room_participant_and_mls_key() {
        let signer = AdminSigningKey::generate("room-bind").unwrap();
        let other_signer = AdminSigningKey::generate("room-bind").unwrap();
        let mls_pk = [42u8; 32];
        let other_mls_pk = [7u8; 32];

        let sig = signer.sign_mls_binding("admin-1", &mls_pk);
        assert!(
            verify_mls_admin_binding(
                &signer.verifying_key_bytes(),
                "room-bind",
                "admin-1",
                &mls_pk,
                &sig,
            )
            .is_ok()
        );
        // Different MLS key fails.
        assert!(
            verify_mls_admin_binding(
                &signer.verifying_key_bytes(),
                "room-bind",
                "admin-1",
                &other_mls_pk,
                &sig,
            )
            .is_err()
        );
        // Different room fails.
        assert!(
            verify_mls_admin_binding(
                &signer.verifying_key_bytes(),
                "room-other",
                "admin-1",
                &mls_pk,
                &sig,
            )
            .is_err()
        );
        // Different participant_id fails.
        assert!(
            verify_mls_admin_binding(
                &signer.verifying_key_bytes(),
                "room-bind",
                "admin-2",
                &mls_pk,
                &sig,
            )
            .is_err()
        );
        // Different admin key fails.
        assert!(
            verify_mls_admin_binding(
                &other_signer.verifying_key_bytes(),
                "room-bind",
                "admin-1",
                &mls_pk,
                &sig,
            )
            .is_err()
        );
    }
}
