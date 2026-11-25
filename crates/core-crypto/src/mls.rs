use std::collections::HashSet;

use mls_rs::client_builder::WithCryptoProvider;
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::mls_rules::DefaultMlsRules;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::admin::{AdminSigningKey, compute_admin_fingerprint, verify_mls_admin_binding};
use crate::padding::{pad_payload, unpad_payload};
use crate::protocol::ChatAppPayload;

/// Classical RFC 9420 cipher suite for Version 1 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).
pub const V1_CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

type MlsConfig = mls_rs::client_builder::WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<RustCryptoProvider, mls_rs::client_builder::BaseConfig>,
>;

/// Structured credential placed inside each member's MLS `BasicCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsMemberIdentity {
    pub room_id: String,
    pub participant_id: String,
    pub is_admin: bool,
    pub admin_fingerprint: Option<String>,
    /// Domain-separated Ed25519 signature by the invite-anchored `AdminSigningKey`
    /// over `(room_id, participant_id, "admin", mls_signature_pubkey)`.
    #[serde(default)]
    pub admin_mls_binding_sig_b64: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AddMemberOutput {
    pub commit_bytes: Vec<u8>,
    pub welcome_bytes: Vec<u8>,
    pub expected_epoch: u64,
    pub new_epoch: u64,
    pub added_mls_participant_id: String,
}

#[derive(Debug, Clone)]
pub struct StagedAddMember {
    pub commit_bytes: Vec<u8>,
    pub welcome_bytes: Vec<u8>,
    pub expected_epoch: u64,
    pub new_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct StagedRemoveMember {
    pub commit_bytes: Vec<u8>,
    pub expected_epoch: u64,
    pub new_epoch: u64,
}

#[derive(Debug, Clone)]
pub enum MlsIncomingEvent {
    ChatMessage {
        sender_id: String,
        is_admin: bool,
        payload: ChatAppPayload,
    },
    EpochAdvanced {
        new_epoch: u64,
    },
    Ignored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsSelftestReport {
    pub cipher_suite: String,
    pub epoch_after_add: u64,
    pub epoch_after_remove: u64,
    pub removed_guest_blocked: bool,
    pub roundtrip_ok: bool,
}

/// Manages a participant's ephemeral RFC 9420 MLS client and group state in RAM.
pub struct MlsSession {
    room_id: String,
    participant_id: String,
    expected_admin_pubkey: Option<[u8; 32]>,
    client: Client<MlsConfig>,
    group: Option<Group<MlsConfig>>,
}

impl MlsSession {
    /// Creates the room admin's MLS session, cryptographically binding the freshly generated
    /// MLS Ed25519 signature public key to the invite-anchored `AdminSigningKey`.
    pub fn new_admin(
        room_id: impl Into<String>,
        participant_id: impl Into<String>,
        admin_signing_key: &AdminSigningKey,
    ) -> Result<Self, CryptoError> {
        let room_id = room_id.into();
        let participant_id = participant_id.into();
        if admin_signing_key.room_id() != room_id {
            return Err(CryptoError::RoomMismatch);
        }

        let crypto_provider = RustCryptoProvider::with_enabled_cipher_suites(vec![V1_CIPHER_SUITE]);
        let cs_provider = crypto_provider
            .cipher_suite_provider(V1_CIPHER_SUITE)
            .ok_or_else(|| CryptoError::MlsError("CURVE25519_AES128 unavailable".into()))?;

        let (secret_key, public_key) = cs_provider
            .signature_key_generate()
            .map_err(|e| CryptoError::MlsError(format!("MLS keygen failed: {e}")))?;

        let binding_sig = admin_signing_key.sign_mls_binding(&participant_id, public_key.as_ref());
        let identity = MlsMemberIdentity {
            room_id: room_id.clone(),
            participant_id: participant_id.clone(),
            is_admin: true,
            admin_fingerprint: Some(admin_signing_key.fingerprint()),
            admin_mls_binding_sig_b64: Some(binding_sig),
        };
        let identity_bytes =
            serde_json::to_vec(&identity).map_err(|e| CryptoError::CodecError(e.to_string()))?;

        let signing_identity = SigningIdentity::new(
            BasicCredential::new(identity_bytes).into_credential(),
            public_key,
        );

        let client = Client::builder()
            .crypto_provider(crypto_provider)
            .identity_provider(BasicIdentityProvider::new())
            .mls_rules(DefaultMlsRules::new())
            .signing_identity(signing_identity, secret_key, V1_CIPHER_SUITE)
            .build();

        Ok(Self {
            room_id,
            participant_id,
            expected_admin_pubkey: Some(admin_signing_key.verifying_key_bytes()),
            client,
            group: None,
        })
    }

    /// Creates a guest's MLS session with a freshly generated MLS Ed25519 signature keypair.
    pub fn new_guest(
        room_id: impl Into<String>,
        participant_id: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let room_id = room_id.into();
        let participant_id = participant_id.into();

        let crypto_provider = RustCryptoProvider::with_enabled_cipher_suites(vec![V1_CIPHER_SUITE]);
        let cs_provider = crypto_provider
            .cipher_suite_provider(V1_CIPHER_SUITE)
            .ok_or_else(|| CryptoError::MlsError("CURVE25519_AES128 unavailable".into()))?;

        let (secret_key, public_key) = cs_provider
            .signature_key_generate()
            .map_err(|e| CryptoError::MlsError(format!("MLS keygen failed: {e}")))?;

        let identity = MlsMemberIdentity {
            room_id: room_id.clone(),
            participant_id: participant_id.clone(),
            is_admin: false,
            admin_fingerprint: None,
            admin_mls_binding_sig_b64: None,
        };
        let identity_bytes =
            serde_json::to_vec(&identity).map_err(|e| CryptoError::CodecError(e.to_string()))?;

        let signing_identity = SigningIdentity::new(
            BasicCredential::new(identity_bytes).into_credential(),
            public_key,
        );

        let client = Client::builder()
            .crypto_provider(crypto_provider)
            .identity_provider(BasicIdentityProvider::new())
            .mls_rules(DefaultMlsRules::new())
            .signing_identity(signing_identity, secret_key, V1_CIPHER_SUITE)
            .build();

        Ok(Self {
            room_id,
            participant_id,
            expected_admin_pubkey: None,
            client,
            group: None,
        })
    }

    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    pub fn current_epoch(&self) -> u64 {
        self.group.as_ref().map(|g| g.current_epoch()).unwrap_or(0)
    }

    pub fn has_pending_commit(&self) -> bool {
        self.group
            .as_ref()
            .map(|g| g.has_pending_commit())
            .unwrap_or(false)
    }

    pub fn clear_pending_commit(&mut self) {
        if let Some(group) = self.group.as_mut() {
            group.clear_pending_commit();
        }
    }

    /// Admin creates a fresh MLS group bound to `room_id`.
    pub fn create_group(&mut self) -> Result<u64, CryptoError> {
        let group = self
            .client
            .create_group_with_id(
                self.room_id.as_bytes().to_vec(),
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .map_err(|e| CryptoError::MlsError(format!("create_group failed: {e}")))?;
        let epoch = group.current_epoch();
        self.group = Some(group);
        Ok(epoch)
    }

    /// Guest generates a fresh MLS KeyPackage to send over WSS during Join.
    pub fn generate_key_package(&self) -> Result<Vec<u8>, CryptoError> {
        let kp = self
            .client
            .generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
            .map_err(|e| CryptoError::MlsError(format!("generate_key_package failed: {e}")))?;
        kp.to_bytes()
            .map_err(|e| CryptoError::CodecError(format!("serialize key package: {e}")))
    }

    /// Admin stages an Add Commit WITHOUT applying it locally yet.
    /// Call `apply_pending_commit()` only after the relay acknowledges the epoch transition,
    /// or `clear_pending_commit()` if sending/relay acceptance fails.
    pub fn stage_add_member(
        &mut self,
        key_package_bytes: &[u8],
    ) -> Result<StagedAddMember, CryptoError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| CryptoError::MlsError("MLS group not initialized".into()))?;
        if group.has_pending_commit() {
            return Err(CryptoError::MlsError(
                "an MLS commit is already pending confirmation".into(),
            ));
        }

        let expected_epoch = group.current_epoch();
        let kp_msg = MlsMessage::from_bytes(key_package_bytes)
            .map_err(|e| CryptoError::CodecError(format!("decode key package: {e}")))?;

        let commit_out = group
            .commit_builder()
            .add_member(kp_msg)
            .map_err(|e| CryptoError::MlsError(format!("add_member proposal failed: {e}")))?
            .build()
            .map_err(|e| CryptoError::MlsError(format!("commit build failed: {e}")))?;

        let commit_bytes = commit_out
            .commit_message
            .to_bytes()
            .map_err(|e| CryptoError::CodecError(format!("serialize commit: {e}")))?;
        let welcome_msg = commit_out
            .welcome_messages
            .into_iter()
            .next()
            .ok_or_else(|| CryptoError::MlsError("missing welcome message".into()))?;
        let welcome_bytes = welcome_msg
            .to_bytes()
            .map_err(|e| CryptoError::CodecError(format!("serialize welcome: {e}")))?;

        Ok(StagedAddMember {
            commit_bytes,
            welcome_bytes,
            expected_epoch,
            new_epoch: expected_epoch + 1,
        })
    }

    /// Admin stages a Remove Commit WITHOUT applying it locally yet.
    pub fn stage_remove_member_by_participant_id(
        &mut self,
        target_participant_id: &str,
    ) -> Result<StagedRemoveMember, CryptoError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| CryptoError::MlsError("MLS group not initialized".into()))?;
        if group.has_pending_commit() {
            return Err(CryptoError::MlsError(
                "an MLS commit is already pending confirmation".into(),
            ));
        }

        let expected_epoch = group.current_epoch();
        let target_index = group
            .roster()
            .members()
            .into_iter()
            .find_map(|member| {
                let id = parse_member_identity(&member.signing_identity)?;
                if id.participant_id == target_participant_id {
                    Some(member.index)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                CryptoError::MlsError(format!(
                    "participant {target_participant_id} not in MLS roster"
                ))
            })?;

        let commit_out = group
            .commit_builder()
            .remove_member(target_index)
            .map_err(|e| CryptoError::MlsError(format!("remove_member proposal failed: {e}")))?
            .build()
            .map_err(|e| CryptoError::MlsError(format!("remove commit build failed: {e}")))?;

        let commit_bytes = commit_out
            .commit_message
            .to_bytes()
            .map_err(|e| CryptoError::CodecError(format!("serialize remove commit: {e}")))?;

        Ok(StagedRemoveMember {
            commit_bytes,
            expected_epoch,
            new_epoch: expected_epoch + 1,
        })
    }

    /// Applies the previously staged pending commit once the relay confirms it.
    /// Returns `(new_epoch, newly_added_mls_participant_id)`.
    pub fn apply_pending_commit(&mut self) -> Result<(u64, Option<String>), CryptoError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| CryptoError::MlsError("MLS group not initialized".into()))?;
        if !group.has_pending_commit() {
            return Err(CryptoError::MlsError(
                "no pending MLS commit to apply".into(),
            ));
        }

        let before_indices: HashSet<u32> = group
            .roster()
            .members()
            .into_iter()
            .map(|m| m.index)
            .collect();

        group
            .apply_pending_commit()
            .map_err(|e| CryptoError::MlsError(format!("apply_pending_commit failed: {e}")))?;

        if let Some(admin_pk) = self.expected_admin_pubkey {
            let expected_fp = compute_admin_fingerprint(&admin_pk, &self.room_id);
            if let Err(e) =
                verify_admin_roster_binding(group, &self.room_id, &admin_pk, &expected_fp)
            {
                self.group = None;
                return Err(e);
            }
        }

        let added_mls_participant_id = group
            .roster()
            .members()
            .into_iter()
            .find(|m| !before_indices.contains(&m.index))
            .and_then(|m| parse_member_identity(&m.signing_identity))
            .map(|id| id.participant_id);

        Ok((group.current_epoch(), added_mls_participant_id))
    }

    /// Convenience helper for synchronous callers/tests: stage and immediately apply an Add commit.
    pub fn add_member(&mut self, key_package_bytes: &[u8]) -> Result<AddMemberOutput, CryptoError> {
        let staged = self.stage_add_member(key_package_bytes)?;
        let (new_epoch, added_id) = self.apply_pending_commit()?;
        let added_mls_participant_id = added_id.ok_or_else(|| {
            CryptoError::MlsError("could not identify newly added MLS member".into())
        })?;
        Ok(AddMemberOutput {
            commit_bytes: staged.commit_bytes,
            welcome_bytes: staged.welcome_bytes,
            expected_epoch: staged.expected_epoch,
            new_epoch,
            added_mls_participant_id,
        })
    }

    /// Guest joins the MLS group from a Welcome message and cryptographically verifies:
    /// 1. `expected_admin_pubkey` matches `expected_admin_fingerprint` for `room_id`.
    /// 2. MLS `group_id` matches `room_id`.
    /// 3. Exactly one admin leaf exists in the MLS roster whose actual MLS signature public key
    ///    carries a valid domain-separated signature from `expected_admin_pubkey`.
    pub fn join_from_welcome(
        &mut self,
        welcome_bytes: &[u8],
        expected_admin_pubkey: &[u8; 32],
        expected_admin_fingerprint: &str,
    ) -> Result<u64, CryptoError> {
        let computed_fp = compute_admin_fingerprint(expected_admin_pubkey, &self.room_id);
        if computed_fp != expected_admin_fingerprint {
            return Err(CryptoError::AdminVerificationFailed(
                "admin public key does not match invite fingerprint".into(),
            ));
        }

        let welcome_msg = MlsMessage::from_bytes(welcome_bytes)
            .map_err(|e| CryptoError::CodecError(format!("decode welcome: {e}")))?;

        let (group, _info) = self
            .client
            .join_group(None, &welcome_msg, None)
            .map_err(|e| CryptoError::MlsError(format!("join_group failed: {e}")))?;

        if group.group_id() != self.room_id.as_bytes() {
            return Err(CryptoError::AdminVerificationFailed(
                "MLS group_id does not match room_id".into(),
            ));
        }

        verify_admin_roster_binding(
            &group,
            &self.room_id,
            expected_admin_pubkey,
            expected_admin_fingerprint,
        )?;

        let epoch = group.current_epoch();
        self.expected_admin_pubkey = Some(*expected_admin_pubkey);
        self.group = Some(group);
        Ok(epoch)
    }

    /// Convenience helper for synchronous callers/tests: stage and immediately apply a Remove commit.
    pub fn remove_member_by_participant_id(
        &mut self,
        target_participant_id: &str,
    ) -> Result<(Vec<u8>, u64), CryptoError> {
        let staged = self.stage_remove_member_by_participant_id(target_participant_id)?;
        let (new_epoch, _) = self.apply_pending_commit()?;
        Ok((staged.commit_bytes, new_epoch))
    }

    /// Serializes, pads to fixed size class, and MLS-encrypts an application chat message.
    /// All intermediate plaintext buffers are zeroized on drop, including on error paths.
    pub fn encrypt_chat_message(
        &mut self,
        payload: &ChatAppPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| CryptoError::MlsError("MLS group not initialized".into()))?;
        let raw_json = Zeroizing::new(
            serde_json::to_vec(payload).map_err(|e| CryptoError::CodecError(e.to_string()))?,
        );
        let padded = Zeroizing::new(pad_payload(&raw_json)?);
        let mls_msg = group
            .encrypt_application_message(&padded, Vec::new())
            .map_err(|e| {
                CryptoError::MlsError(format!("encrypt_application_message failed: {e}"))
            })?;
        mls_msg
            .to_bytes()
            .map_err(|e| CryptoError::CodecError(format!("serialize ciphertext: {e}")))
    }

    /// Processes an incoming MLS message (either an application ciphertext or a group Commit).
    /// On Commits, re-verifies the cryptographic binding of the admin MLS leaf key so key
    /// rotations or malicious commits can never detach the MLS admin identity from the invite anchor.
    pub fn process_incoming(&mut self, mls_bytes: &[u8]) -> Result<MlsIncomingEvent, CryptoError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| CryptoError::MlsError("MLS group not initialized".into()))?;
        let mls_msg = MlsMessage::from_bytes(mls_bytes)
            .map_err(|e| CryptoError::CodecError(format!("decode MLS message: {e}")))?;

        let received = group
            .process_incoming_message(mls_msg)
            .map_err(|e| CryptoError::MlsError(format!("process_incoming_message failed: {e}")))?;

        match received {
            ReceivedMessage::ApplicationMessage(app) => {
                let sender = group
                    .member_at_index(app.sender_index)
                    .and_then(|m| parse_member_identity(&m.signing_identity))
                    .ok_or_else(|| CryptoError::MlsError("unknown MLS sender identity".into()))?;
                let unpadded = Zeroizing::new(unpad_payload(app.data())?);
                let payload: ChatAppPayload = serde_json::from_slice(&unpadded)
                    .map_err(|e| CryptoError::CodecError(format!("decode chat payload: {e}")))?;
                Ok(MlsIncomingEvent::ChatMessage {
                    sender_id: sender.participant_id,
                    is_admin: sender.is_admin,
                    payload,
                })
            }
            ReceivedMessage::Commit(_) => {
                let new_epoch = group.current_epoch();
                if let Some(admin_pk) = self.expected_admin_pubkey {
                    let expected_fp = compute_admin_fingerprint(&admin_pk, &self.room_id);
                    if let Err(e) =
                        verify_admin_roster_binding(group, &self.room_id, &admin_pk, &expected_fp)
                    {
                        self.group = None;
                        return Err(e);
                    }
                }
                Ok(MlsIncomingEvent::EpochAdvanced { new_epoch })
            }
            _ => Ok(MlsIncomingEvent::Ignored),
        }
    }

    /// Drops the MLS group state from RAM.
    pub fn wipe(&mut self) {
        self.group = None;
        self.expected_admin_pubkey = None;
    }
}

fn verify_admin_roster_binding(
    group: &Group<MlsConfig>,
    room_id: &str,
    expected_admin_pubkey: &[u8; 32],
    expected_admin_fingerprint: &str,
) -> Result<(), CryptoError> {
    let mut verified_admins = 0usize;
    for member in group.roster().members() {
        let Some(id) = parse_member_identity(&member.signing_identity) else {
            return Err(CryptoError::AdminVerificationFailed(
                "unparseable MLS member credential".into(),
            ));
        };
        if id.room_id != room_id {
            return Err(CryptoError::AdminVerificationFailed(
                "MLS roster contains member for mismatched room_id".into(),
            ));
        }
        if id.is_admin {
            if id.admin_fingerprint.as_deref() != Some(expected_admin_fingerprint) {
                return Err(CryptoError::AdminVerificationFailed(
                    "admin leaf fingerprint does not match invite link".into(),
                ));
            }
            let Some(sig_b64) = id.admin_mls_binding_sig_b64.as_deref() else {
                return Err(CryptoError::AdminVerificationFailed(
                    "admin MLS leaf is missing cryptographic key binding signature".into(),
                ));
            };
            verify_mls_admin_binding(
                expected_admin_pubkey,
                room_id,
                &id.participant_id,
                member.signing_identity.signature_key.as_ref(),
                sig_b64,
            )?;
            verified_admins += 1;
        } else if id.admin_fingerprint.is_some() || id.admin_mls_binding_sig_b64.is_some() {
            return Err(CryptoError::AdminVerificationFailed(
                "non-admin leaf unexpectedly carries admin binding fields".into(),
            ));
        }
    }

    if verified_admins != 1 {
        return Err(CryptoError::AdminVerificationFailed(format!(
            "expected exactly 1 cryptographically bound admin in MLS roster, found {verified_admins}"
        )));
    }
    Ok(())
}

fn parse_member_identity(si: &SigningIdentity) -> Option<MlsMemberIdentity> {
    let basic = si.credential.as_basic()?;
    serde_json::from_slice(&basic.identifier).ok()
}

/// Runs a complete RFC 9420 MLS proof (Section 5 & Section 10):
/// Create -> KeyPackage -> Add & Welcome (with cryptographic Admin->MLS key binding) ->
/// Bidirectional Encrypted Messaging -> Remove Guest -> Verify removed guest CANNOT decrypt post-removal epoch message.
pub fn run_mls_selftest() -> Result<MlsSelftestReport, CryptoError> {
    let room_id = "selftest-room";
    let admin_key = AdminSigningKey::generate(room_id)?;
    let admin_pk = admin_key.verifying_key_bytes();
    let admin_fp = admin_key.fingerprint();

    let mut admin = MlsSession::new_admin(room_id, "admin", &admin_key)?;
    admin.create_group()?;

    let mut guest1 = MlsSession::new_guest(room_id, "guest-1")?;
    let kp1 = guest1.generate_key_package()?;
    let add1 = admin.add_member(&kp1)?;
    guest1.join_from_welcome(&add1.welcome_bytes, &admin_pk, &admin_fp)?;

    let mut guest2 = MlsSession::new_guest(room_id, "guest-2")?;
    let kp2 = guest2.generate_key_package()?;
    let add2 = admin.add_member(&kp2)?;
    guest1.process_incoming(&add2.commit_bytes)?;
    guest2.join_from_welcome(&add2.welcome_bytes, &admin_pk, &admin_fp)?;

    let epoch_after_add = admin.current_epoch();

    // Bidirectional encrypted message exchange.
    let msg_a = ChatAppPayload {
        message_id: "selftest-1".into(),
        text: "Hello from MLS epoch 2".into(),
        sent_at_ms: 1_700_000_000_000,
    };
    let ct_a = admin.encrypt_chat_message(&msg_a)?;
    let recv_g1 = guest1.process_incoming(&ct_a)?;
    let recv_g2 = guest2.process_incoming(&ct_a)?;

    let roundtrip_ok = matches!(
        (&recv_g1, &recv_g2),
        (
            MlsIncomingEvent::ChatMessage { payload: p1, .. },
            MlsIncomingEvent::ChatMessage { payload: p2, .. }
        ) if p1.text == msg_a.text && p2.text == msg_a.text
    );
    if !roundtrip_ok {
        return Err(CryptoError::MlsError("roundtrip mismatch".into()));
    }

    // Remove guest1 and rotate epoch.
    let (remove_commit, epoch_after_remove) = admin.remove_member_by_participant_id("guest-1")?;
    guest2.process_incoming(&remove_commit)?;

    // Admin sends a post-removal message. Guest2 can decrypt it; Guest1 MUST NOT.
    let post_remove_msg = ChatAppPayload {
        message_id: "selftest-2".into(),
        text: "Remaining members only".into(),
        sent_at_ms: 1_700_000_001_000,
    };
    let ct_post = admin.encrypt_chat_message(&post_remove_msg)?;

    // Guest2 succeeds.
    match guest2.process_incoming(&ct_post)? {
        MlsIncomingEvent::ChatMessage { payload, .. } if payload.text == post_remove_msg.text => {}
        _ => {
            return Err(CryptoError::MlsError(
                "remaining member failed to decrypt".into(),
            ));
        }
    }

    // Removed Guest1 MUST fail to decrypt the new epoch ciphertext.
    let removed_guest_blocked = guest1.process_incoming(&ct_post).is_err();
    if !removed_guest_blocked {
        return Err(CryptoError::MlsError(
            "SECURITY VIOLATION: removed guest decrypted post-removal message".into(),
        ));
    }

    Ok(MlsSelftestReport {
        cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
        epoch_after_add,
        epoch_after_remove,
        removed_guest_blocked,
        roundtrip_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper simulating a compromised relay forging an MLS admin session with its own MLS
    /// signing keypair while copying the real admin's fingerprint (and optionally a forged/stolen sig).
    fn forged_admin_session(
        room_id: &str,
        participant_id: &str,
        copied_fingerprint: String,
        forged_binding_sig: Option<String>,
    ) -> MlsSession {
        let crypto_provider = RustCryptoProvider::with_enabled_cipher_suites(vec![V1_CIPHER_SUITE]);
        let cs_provider = crypto_provider
            .cipher_suite_provider(V1_CIPHER_SUITE)
            .unwrap();
        let (secret_key, public_key) = cs_provider.signature_key_generate().unwrap();
        let identity = MlsMemberIdentity {
            room_id: room_id.into(),
            participant_id: participant_id.into(),
            is_admin: true,
            admin_fingerprint: Some(copied_fingerprint),
            admin_mls_binding_sig_b64: forged_binding_sig,
        };
        let signing_identity = SigningIdentity::new(
            BasicCredential::new(serde_json::to_vec(&identity).unwrap()).into_credential(),
            public_key,
        );
        let client = Client::builder()
            .crypto_provider(crypto_provider)
            .identity_provider(BasicIdentityProvider::new())
            .mls_rules(DefaultMlsRules::new())
            .signing_identity(signing_identity, secret_key, V1_CIPHER_SUITE)
            .build();
        MlsSession {
            room_id: room_id.into(),
            participant_id: participant_id.into(),
            expected_admin_pubkey: None,
            client,
            group: None,
        }
    }

    #[test]
    fn mls_selftest_full_lifecycle_and_removal_isolation() {
        let report = run_mls_selftest().expect("MLS selftest should succeed");
        assert!(report.roundtrip_ok);
        assert!(report.removed_guest_blocked);
        assert_eq!(report.epoch_after_add, 2);
        assert_eq!(report.epoch_after_remove, 3);
    }

    #[test]
    fn guest_rejects_wrong_admin_fingerprint() {
        let admin_key = AdminSigningKey::generate("room-1").unwrap();
        let mut admin = MlsSession::new_admin("room-1", "admin", &admin_key).unwrap();
        admin.create_group().unwrap();
        let mut guest = MlsSession::new_guest("room-1", "guest-1").unwrap();
        let kp = guest.generate_key_package().unwrap();
        let add = admin.add_member(&kp).unwrap();
        let err = guest.join_from_welcome(
            &add.welcome_bytes,
            &admin_key.verifying_key_bytes(),
            "wrong",
        );
        assert!(matches!(err, Err(CryptoError::AdminVerificationFailed(_))));
    }

    #[test]
    fn guest_rejects_unbound_mls_admin_key_even_with_matching_fingerprint() {
        // Real admin holds the invite-anchored key and signs real room policies.
        let real_admin_key = AdminSigningKey::generate("room-mitm").unwrap();
        let real_pk = real_admin_key.verifying_key_bytes();
        let real_fp = real_admin_key.fingerprint();

        // Compromised relay creates its own MLS group with its own MLS signing key,
        // copying the real admin's fingerprint into BasicCredential (without a valid binding sig).
        let mut relay_mitm = forged_admin_session("room-mitm", "admin", real_fp.clone(), None);
        relay_mitm.create_group().unwrap();

        let mut guest = MlsSession::new_guest("room-mitm", "guest-1").unwrap();
        let kp = guest.generate_key_package().unwrap();
        let add = relay_mitm.add_member(&kp).unwrap();

        let err = guest.join_from_welcome(&add.welcome_bytes, &real_pk, &real_fp);
        assert!(
            matches!(err, Err(CryptoError::AdminVerificationFailed(_))),
            "Welcome with matching fingerprint but unbound MLS key MUST be rejected, got {err:?}"
        );
    }

    #[test]
    fn guest_rejects_stolen_binding_signature_attached_to_different_mls_key() {
        let real_admin_key = AdminSigningKey::generate("room-mitm2").unwrap();
        let real_pk = real_admin_key.verifying_key_bytes();
        let real_fp = real_admin_key.fingerprint();

        // Real admin signs a binding for the real admin's MLS public key.
        let real_binding_sig = real_admin_key.sign_mls_binding("admin", &[99u8; 32]);

        // Attacker copies that valid binding signature into a BasicCredential with attacker's OWN MLS key!
        let mut relay_mitm = forged_admin_session(
            "room-mitm2",
            "admin",
            real_fp.clone(),
            Some(real_binding_sig),
        );
        relay_mitm.create_group().unwrap();

        let mut guest = MlsSession::new_guest("room-mitm2", "guest-1").unwrap();
        let kp = guest.generate_key_package().unwrap();
        let add = relay_mitm.add_member(&kp).unwrap();

        let err = guest.join_from_welcome(&add.welcome_bytes, &real_pk, &real_fp);
        assert!(
            matches!(err, Err(CryptoError::AdminVerificationFailed(_))),
            "Stolen binding sig on a different MLS key MUST be rejected, got {err:?}"
        );
    }

    #[test]
    fn staged_commit_does_not_advance_epoch_until_applied_and_can_be_cleared() {
        let admin_key = AdminSigningKey::generate("room-stage").unwrap();
        let mut admin = MlsSession::new_admin("room-stage", "admin", &admin_key).unwrap();
        admin.create_group().unwrap();
        assert_eq!(admin.current_epoch(), 0);

        let guest = MlsSession::new_guest("room-stage", "guest-1").unwrap();
        let kp = guest.generate_key_package().unwrap();

        let staged = admin.stage_add_member(&kp).unwrap();
        assert_eq!(staged.expected_epoch, 0);
        assert_eq!(staged.new_epoch, 1);
        assert!(admin.has_pending_commit());
        // Epoch MUST still be 0 until relay confirms and apply_pending_commit is called!
        assert_eq!(admin.current_epoch(), 0);

        // Clearing pending commit discards it cleanly and allows re-staging.
        admin.clear_pending_commit();
        assert!(!admin.has_pending_commit());
        assert_eq!(admin.current_epoch(), 0);

        let _staged2 = admin.stage_add_member(&kp).unwrap();
        let (new_epoch, added_id) = admin.apply_pending_commit().unwrap();
        assert_eq!(new_epoch, 1);
        assert_eq!(added_id.as_deref(), Some("guest-1"));
        assert!(!admin.has_pending_commit());
    }
}
