use serde::{Deserialize, Serialize};

use crate::admin::SignedAdminCommand;
use crate::policy::RoomPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    Admin,
    Guest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSummary {
    pub participant_id: String,
    pub role: ParticipantRole,
    pub connected: bool,
}

/// Application-layer chat payload encrypted + padded inside MLS application messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatAppPayload {
    pub message_id: String,
    pub text: String,
    pub sent_at_ms: u64,
}

/// Wire messages sent from a browser worker client to the relay server over WSS.
/// Create, Join, and Resume are strictly separate operations (Section 8).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientToRelay {
    /// Creates a brand new room instance (admin only).
    CreateRoom {
        admin_pubkey_b64: String,
        initial_policy: RoomPolicy,
    },
    /// Registers the initial signed policy command right after receiving `room_id` from `RoomCreated`.
    /// Also used for all subsequent signed admin commands (SetPolicy, RegisterInvite, KickGuest, PanicWipe, CloseRoom).
    AdminCommand { signed_cmd: SignedAdminCommand },
    /// Joins an existing room with a one-time invite token and MLS KeyPackage.
    /// NEVER creates a room.
    JoinRoom {
        room_id: String,
        invite_token: String,
        key_package_b64: String,
        client_join_nonce: String,
    },
    /// Sent automatically by the admin client after processing `GuestJoinRequest`.
    CompleteJoin {
        reservation_id: String,
        guest_id: String,
        commit_b64: String,
        welcome_b64: String,
        new_epoch: u64,
    },
    /// Resumes an existing participant session within the 60s reconnect grace window.
    ResumeSession {
        room_id: String,
        participant_id: String,
        resume_token: String,
    },
    /// Sends an end-to-end encrypted MLS application message ciphertext.
    SendMlsMessage {
        epoch: u64,
        message_id: String,
        ciphertext_b64: String,
    },
    /// Sends an MLS Commit (e.g., Remove commit after a guest permanently left or was kicked).
    SendMlsCommit {
        epoch: u64,
        commit_b64: String,
        removed_participant_id: Option<String>,
    },
    /// Explicit voluntary leave. If sent by Admin, the room ends immediately.
    LeaveRoom,
    /// Application-level keep-alive ping.
    Ping { ts_ms: u64 },
}

/// Wire messages sent from the relay server to a browser worker client over WSS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayToClient {
    RoomCreated {
        room_id: String,
        participant_id: String,
        resume_token: String,
        room_created_at_ms: u64,
        room_expires_at_ms: u64,
        policy: RoomPolicy,
        invite_ttl_secs: u64,
        keepalive_interval_secs: u64,
    },
    InviteRegistered {
        token_hash_hex: String,
        expires_at_ms: u64,
    },
    JoinPending {
        room_id: String,
        reason: String,
    },
    GuestJoinRequest {
        reservation_id: String,
        guest_id: String,
        key_package_b64: String,
    },
    JoinAccepted {
        room_id: String,
        participant_id: String,
        resume_token: String,
        welcome_b64: String,
        admin_pubkey_b64: String,
        latest_policy_cmd: SignedAdminCommand,
        room_created_at_ms: u64,
        room_expires_at_ms: u64,
        members: Vec<MemberSummary>,
        keepalive_interval_secs: u64,
    },
    SessionResumed {
        room_id: String,
        participant_id: String,
        resume_token: String,
        epoch: u64,
        room_created_at_ms: u64,
        room_expires_at_ms: u64,
        latest_policy_cmd: Option<SignedAdminCommand>,
        members: Vec<MemberSummary>,
        messaging_paused: bool,
        keepalive_interval_secs: u64,
    },
    MlsCommit {
        sender_id: String,
        epoch: u64,
        commit_b64: String,
        members: Vec<MemberSummary>,
        messaging_paused: bool,
    },
    MlsMessage {
        sender_id: String,
        epoch: u64,
        message_id: String,
        ciphertext_b64: String,
    },
    PolicyUpdated {
        signed_cmd: SignedAdminCommand,
        room_expires_at_ms: u64,
    },
    MemberStatus {
        participant_id: String,
        role: ParticipantRole,
        connected: bool,
        members: Vec<MemberSummary>,
        messaging_paused: bool,
    },
    /// Delivered to Admin whenever a guest permanently leaves, times out after 60s, or is kicked.
    /// Room messaging remains paused until Admin commits the MLS Remove.
    MemberRemovalRequired {
        participant_id: String,
        reason: String,
    },
    /// Sent to Admin once the relay has locked the room and invalidated invites & resume tokens.
    PanicWipeConfirmed {
        room_id: String,
    },
    RoomWiped {
        room_id: String,
        reason: String,
    },
    RoomClosed {
        room_id: String,
        reason: String,
    },
    Pong {
        ts_ms: u64,
    },
    Error {
        code: String,
        message: String,
    },
}
