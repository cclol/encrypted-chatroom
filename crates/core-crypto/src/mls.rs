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

use crate::CryptoError;
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
}

#[derive(Debug, Clone)]
pub struct AddMemberOutput {
    pub commit_bytes: Vec<u8>,
    pub welcome_bytes: Vec<u8>,
    pub new_epoch: u64,
    pub added_mls_participant_id: String,
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
    client: Client<MlsConfig>,
    group: Option<Group<MlsConfig>>,
}

impl MlsSession {
    /// Creates a new MLS participant with a freshly generated MLS Ed25519 signature keypair
    /// sourced from the platform CSPRNG (separate from AdminSigningKey).
    pub fn new(
        room_id: impl Into<String>,
        participant_id: impl Into<String>,
        is_admin: bool,
        admin_fingerprint: Option<String>,
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
            is_admin,
            admin_fingerprint,
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

    /// Admin adds a guest via their KeyPackage, commits, and advances the local group state.
    pub fn add_member(&mut self, key_package_bytes: &[u8]) -> Result<AddMemberOutput, CryptoError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| CryptoError::MlsError("MLS group not initialized".into()))?;
        let before_indices: std::collections::HashSet<u32> = group
            .roster()
            .members()
            .into_iter()
            .map(|m| m.index)
            .collect();

        let kp_msg = MlsMessage::from_bytes(key_package_bytes)
            .map_err(|e| CryptoError::CodecError(format!("decode key package: {e}")))?;

        let commit_out = group
            .commit_builder()
            .add_member(kp_msg)
            .map_err(|e| CryptoError::MlsError(format!("add_member proposal failed: {e}")))?
            .build()
            .map_err(|e| CryptoError::MlsError(format!("commit build failed: {e}")))?;

        group
            .apply_pending_commit()
            .map_err(|e| CryptoError::MlsError(format!("apply_pending_commit failed: {e}")))?;

        let added_mls_participant_id = group
            .roster()
            .members()
            .into_iter()
            .find(|m| !before_indices.contains(&m.index))
            .and_then(|m| parse_member_identity(&m.signing_identity))
            .map(|id| id.participant_id)
            .ok_or_else(|| {
                CryptoError::MlsError("could not identify newly added MLS member".into())
            })?;

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

        Ok(AddMemberOutput {
            commit_bytes,
            welcome_bytes,
            new_epoch: group.current_epoch(),
            added_mls_participant_id,
        })
    }

    /// Guest joins the MLS group from a Welcome message and cryptographically verifies
    /// that the group ID and the admin's credential fingerprint match the invite link.
    pub fn join_from_welcome(
        &mut self,
        welcome_bytes: &[u8],
        expected_admin_fingerprint: &str,
    ) -> Result<u64, CryptoError> {
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

        // Verify that the group roster contains an Admin leaf whose room_id and admin_fingerprint
        // match the invite fragment.
        let mut verified_admin = false;
        for member in group.roster().members() {
            if let Some(id) = parse_member_identity(&member.signing_identity)
                && id.is_admin
                && id.room_id == self.room_id
                && id.admin_fingerprint.as_deref() == Some(expected_admin_fingerprint)
            {
                verified_admin = true;
                break;
            }
        }
        if !verified_admin {
            return Err(CryptoError::AdminVerificationFailed(
                "admin identity fingerprint not found in MLS group roster".into(),
            ));
        }

        let epoch = group.current_epoch();
        self.group = Some(group);
        Ok(epoch)
    }

    /// Admin removes a guest by `participant_id`, committing a new MLS epoch so the removed guest
    /// cannot decrypt any subsequent messages.
    pub fn remove_member_by_participant_id(
        &mut self,
        target_participant_id: &str,
    ) -> Result<(Vec<u8>, u64), CryptoError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| CryptoError::MlsError("MLS group not initialized".into()))?;

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

        group
            .apply_pending_commit()
            .map_err(|e| CryptoError::MlsError(format!("apply remove commit failed: {e}")))?;

        let commit_bytes = commit_out
            .commit_message
            .to_bytes()
            .map_err(|e| CryptoError::CodecError(format!("serialize remove commit: {e}")))?;

        Ok((commit_bytes, group.current_epoch()))
    }

    /// Serializes, pads to fixed size class, and MLS-encrypts an application chat message.
    pub fn encrypt_chat_message(
        &mut self,
        payload: &ChatAppPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| CryptoError::MlsError("MLS group not initialized".into()))?;
        let raw_json =
            serde_json::to_vec(payload).map_err(|e| CryptoError::CodecError(e.to_string()))?;
        let padded = pad_payload(&raw_json)?;
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
                let unpadded = unpad_payload(app.data())?;
                let payload: ChatAppPayload = serde_json::from_slice(&unpadded)
                    .map_err(|e| CryptoError::CodecError(format!("decode chat payload: {e}")))?;
                Ok(MlsIncomingEvent::ChatMessage {
                    sender_id: sender.participant_id,
                    is_admin: sender.is_admin,
                    payload,
                })
            }
            ReceivedMessage::Commit(_) => Ok(MlsIncomingEvent::EpochAdvanced {
                new_epoch: group.current_epoch(),
            }),
            _ => Ok(MlsIncomingEvent::Ignored),
        }
    }

    /// Drops the MLS group state from RAM.
    pub fn wipe(&mut self) {
        self.group = None;
    }
}

fn parse_member_identity(si: &SigningIdentity) -> Option<MlsMemberIdentity> {
    let basic = si.credential.as_basic()?;
    serde_json::from_slice(&basic.identifier).ok()
}

/// Runs a complete RFC 9420 MLS proof (Section 5 & Section 10):
/// Create -> KeyPackage -> Add & Welcome -> Bidirectional Encrypted Messaging ->
/// Remove Guest -> Verify removed guest CANNOT decrypt post-removal epoch message.
pub fn run_mls_selftest() -> Result<MlsSelftestReport, CryptoError> {
    let room_id = "selftest-room";
    let admin_fp = "selftest-admin-fingerprint";

    let mut admin = MlsSession::new(room_id, "admin", true, Some(admin_fp.into()))?;
    admin.create_group()?;

    let mut guest1 = MlsSession::new(room_id, "guest-1", false, None)?;
    let kp1 = guest1.generate_key_package()?;
    let add1 = admin.add_member(&kp1)?;
    guest1.join_from_welcome(&add1.welcome_bytes, admin_fp)?;

    let mut guest2 = MlsSession::new(room_id, "guest-2", false, None)?;
    let kp2 = guest2.generate_key_package()?;
    let add2 = admin.add_member(&kp2)?;
    guest1.process_incoming(&add2.commit_bytes)?;
    guest2.join_from_welcome(&add2.welcome_bytes, admin_fp)?;

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
        let mut admin = MlsSession::new("room-1", "admin", true, Some("fp-real".into())).unwrap();
        admin.create_group().unwrap();
        let mut guest = MlsSession::new("room-1", "guest-1", false, None).unwrap();
        let kp = guest.generate_key_package().unwrap();
        let add = admin.add_member(&kp).unwrap();
        let err = guest.join_from_welcome(&add.welcome_bytes, "fp-wrong");
        assert!(matches!(err, Err(CryptoError::AdminVerificationFailed(_))));
    }
}
