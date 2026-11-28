use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use core_crypto::admin::{
    AdminCommandPayload, AdminCommandVerifier, AdminSigningKey, compute_admin_fingerprint,
    decode_pubkey_b64,
};
use core_crypto::ephemeral_store::{EphemeralHistoryStore, VisibleMessage};
use core_crypto::mls::{MlsIncomingEvent, MlsSelftestReport, MlsSession, run_mls_selftest};
use core_crypto::policy::{ADMIN_RECONNECT_GRACE_SECS, RECONNECT_GRACE_SECS, RoomPolicy};
use core_crypto::protocol::{
    ChatAppPayload, ClientToRelay, MemberSummary, MissedCommit, ParticipantRole, RelayToClient,
};
use core_crypto::room_code::{RoomCode, reconcile_room_code_on_resume, sanitize_room_name};
use core_crypto::{random_token_b64url, sha256_hex};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent, WebSocket};
use zeroize::{Zeroize, Zeroizing};

const JOIN_RETRY_DEADLINE_MS: u64 = 60_000;
const PANIC_WIPE_CONFIRM_TIMEOUT_MS: i32 = 4_000;
const VISIBILITY_VERIFY_TIMEOUT_MS: i32 = 4_000;
const RESUME_HANDSHAKE_TIMEOUT_MS: i32 = 8_000;
const KEEPALIVE_LIVENESS_TIMEOUT_MS: u64 = 15_000;

const ROOM_CODE_ERROR_CODE: &str = "invalid_room_code";
const ROOM_CODE_ERROR_MSG: &str = "Room code is invalid, revoked, or the room has ended";

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UiToWorker {
    RunMlsSelftest,
    CreateRoom {
        relay_url: String,
        msg_ttl_secs: u64,
        room_ttl_secs: u64,
        #[serde(default)]
        room_name: Option<String>,
    },
    JoinRoom {
        relay_url: String,
        room_id: String,
        invite_token: String,
        admin_fingerprint: String,
    },
    JoinWithRoomCode {
        relay_url: String,
        room_code: String,
    },
    GenerateInvite,
    GenerateRoomCode,
    RevokeRoomCode,
    SendMessage {
        text: String,
    },
    UpdatePolicy {
        msg_ttl_secs: u64,
        room_ttl_secs: u64,
    },
    KickGuest {
        participant_id: String,
    },
    PanicWipe,
    LeaveRoom,
    UiHidden,
    UiVisible {
        #[serde(default)]
        visibility_token: u64,
        #[serde(default)]
        force_reconnect: bool,
    },
    CheckConnection {
        #[serde(default)]
        visibility_token: u64,
        #[serde(default)]
        force_reconnect: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WorkerToUi {
    WorkerReady,
    MlsSelftestResult {
        ok: bool,
        report: Option<MlsSelftestReport>,
        error: Option<String>,
    },
    StateUpdate {
        phase: String,
        room_id: Option<String>,
        room_name: Option<String>,
        participant_id: Option<String>,
        role: Option<ParticipantRole>,
        epoch: u64,
        policy: RoomPolicy,
        room_created_at_ms: u64,
        room_expires_at_ms: u64,
        members: Vec<MemberSummary>,
        messaging_paused: bool,
        status_text: String,
        admin_fingerprint: Option<String>,
    },
    InviteReady {
        room_id: String,
        invite_token: String,
        admin_fingerprint: String,
        expires_at_ms: u64,
    },
    RoomCodeState {
        active: bool,
        room_code: Option<String>,
        expires_at_ms: u64,
    },
    VisibilityVerified {
        visibility_token: u64,
    },
    RenderHistory {
        visibility_token: u64,
        messages: Vec<VisibleMessage>,
    },
    AppendMessage {
        visibility_token: u64,
        message: VisibleMessage,
    },
    RemoveMessages {
        visibility_token: u64,
        message_ids: Vec<String>,
    },
    ClearDisplay {
        reason: String,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Connecting,
    PendingJoin,
    Active,
    Reconnecting,
    Ended,
    WipedLocal,
    WipedConfirmed,
    WipedUnconfirmed,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Connecting => "connecting",
            Phase::PendingJoin => "pending_join",
            Phase::Active => "active",
            Phase::Reconnecting => "reconnecting",
            Phase::Ended => "ended",
            Phase::WipedLocal => "wiped_local",
            Phase::WipedConfirmed => "wiped_confirmed",
            Phase::WipedUnconfirmed => "wiped_unconfirmed",
        }
    }
}

enum PendingConnectAction {
    Create {
        policy: RoomPolicy,
        room_name: Option<String>,
    },
    Join,
    Resume,
}

enum PendingJoinKind {
    Invite { invite_token: String },
    RoomCode { access_secret: String },
}

impl Drop for PendingJoinKind {
    fn drop(&mut self) {
        match self {
            PendingJoinKind::Invite { invite_token } => invite_token.zeroize(),
            PendingJoinKind::RoomCode { access_secret } => access_secret.zeroize(),
        }
    }
}

struct PendingJoinAttempt {
    room_id: String,
    kind: PendingJoinKind,
    client_join_nonce: String,
    key_package_b64: String,
    deadline_ms: u64,
}

impl Drop for PendingJoinAttempt {
    fn drop(&mut self) {
        self.room_id.zeroize();
        self.client_join_nonce.zeroize();
        self.key_package_b64.zeroize();
        self.deadline_ms = 0;
    }
}

struct PendingInvite {
    token: String,
}

impl Drop for PendingInvite {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

enum AdminCommitKind {
    Add { guest_id: String },
    Remove { participant_id: String },
}

struct PendingAdminCommit {
    commit_id: String,
    prev_epoch: u64,
    new_epoch: u64,
    kind: AdminCommitKind,
}

struct ManagedWebSocket {
    ws: WebSocket,
    _onopen: Closure<dyn FnMut()>,
    _onmessage: Closure<dyn FnMut(MessageEvent)>,
    _onclose: Closure<dyn FnMut()>,
}

impl ManagedWebSocket {
    fn detach_and_close(&self) {
        self.ws.set_onopen(None);
        self.ws.set_onmessage(None);
        self.ws.set_onclose(None);
        let _ = self.ws.close();
    }
}

impl Drop for ManagedWebSocket {
    fn drop(&mut self) {
        self.detach_and_close();
    }
}

/// Persistent reusable timer callbacks allocated once for the lifetime of the worker.
/// Prevents per-tick `Closure::forget()` leaks and avoids self-dropping a running closure.
struct TimerCallbacks {
    expiry_cb: Closure<dyn FnMut()>,
    keepalive_cb: Closure<dyn FnMut()>,
    reconnect_cb: Closure<dyn FnMut()>,
    wipe_cb: Closure<dyn FnMut()>,
    verify_cb: Closure<dyn FnMut()>,
    handshake_cb: Closure<dyn FnMut()>,
}

struct WorkerState {
    scope: DedicatedWorkerGlobalScope,
    phase: Phase,
    ui_visible: bool,
    visibility_token: u64,
    verified_visibility_token: Option<u64>,
    pending_visibility_check: Option<(u64, String)>,

    relay_url: Option<String>,
    ws: Option<ManagedWebSocket>,
    /// Closed WebSocket moved here during `onclose` and dropped on the next event turn
    /// so we never drop an `onclose` closure while it is executing on the stack.
    retired_ws: Option<ManagedWebSocket>,
    ws_generation: u64,
    pending_action: Option<PendingConnectAction>,
    pending_join: Option<PendingJoinAttempt>,

    room_id: Option<String>,
    room_name: Option<String>,
    participant_id: Option<String>,
    role: Option<ParticipantRole>,
    resume_token: Option<String>,
    resume_attempt_id: Option<String>,
    expected_admin_fingerprint: Option<String>,
    wipe_room_id: Option<String>,

    admin_signing_key: Option<AdminSigningKey>,
    admin_verifier: Option<AdminCommandVerifier>,
    mls: Option<MlsSession>,
    relay_epoch: u64,
    pending_admin_commit: Option<PendingAdminCommit>,
    queued_join_requests: VecDeque<(String, String, String)>,
    queued_removals: VecDeque<(String, String)>,
    relay_to_mls_id: HashMap<String, String>,

    policy: RoomPolicy,
    room_created_at_ms: u64,
    room_expires_at_ms: u64,
    invite_ttl_secs: u64,
    room_code_ttl_secs: u64,
    keepalive_interval_secs: u64,
    last_relay_activity_ms: u64,
    pending_ping_sent_at_ms: Option<u64>,
    members: Vec<MemberSummary>,
    messaging_paused: bool,
    status_text: String,

    pending_invites: HashMap<String, PendingInvite>,
    pending_room_codes: HashMap<String, RoomCode>,
    active_room_code: Option<(RoomCode, u64)>,
    history: EphemeralHistoryStore,
    reconnect_attempts: u32,
    reconnect_deadline_ms: Option<u64>,

    expiry_timer_id: Option<i32>,
    keepalive_timer_id: Option<i32>,
    reconnect_timer_id: Option<i32>,
    wipe_timer_id: Option<i32>,
    verify_timer_id: Option<i32>,
    handshake_timer_id: Option<i32>,
    timers: Option<Rc<TimerCallbacks>>,
}

impl WorkerState {
    fn local_epoch(&self) -> u64 {
        self.mls.as_ref().map(|m| m.current_epoch()).unwrap_or(0)
    }

    fn is_epoch_synced(&self) -> bool {
        self.mls.is_some()
            && self.local_epoch() == self.relay_epoch
            && self.pending_admin_commit.is_none()
    }

    fn can_render_now(&self) -> bool {
        self.phase == Phase::Active
            && self.ui_visible
            && self.verified_visibility_token == Some(self.visibility_token)
            && self.is_epoch_synced()
    }
}

fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

pub fn start() {
    let scope: DedicatedWorkerGlobalScope = js_sys::global()
        .dyn_into()
        .expect("web-client must run inside a DedicatedWorkerGlobalScope");

    let state = Rc::new(RefCell::new(WorkerState {
        scope: scope.clone(),
        phase: Phase::Idle,
        ui_visible: true,
        visibility_token: 0,
        verified_visibility_token: Some(0),
        pending_visibility_check: None,
        relay_url: None,
        ws: None,
        retired_ws: None,
        ws_generation: 0,
        pending_action: None,
        pending_join: None,
        room_id: None,
        room_name: None,
        participant_id: None,
        role: None,
        resume_token: None,
        resume_attempt_id: None,
        expected_admin_fingerprint: None,
        wipe_room_id: None,
        admin_signing_key: None,
        admin_verifier: None,
        mls: None,
        relay_epoch: 0,
        pending_admin_commit: None,
        queued_join_requests: VecDeque::new(),
        queued_removals: VecDeque::new(),
        relay_to_mls_id: HashMap::new(),
        policy: RoomPolicy::default(),
        room_created_at_ms: 0,
        room_expires_at_ms: 0,
        invite_ttl_secs: 300,
        room_code_ttl_secs: 900,
        keepalive_interval_secs: 20,
        last_relay_activity_ms: 0,
        pending_ping_sent_at_ms: None,
        members: Vec::new(),
        messaging_paused: false,
        status_text: "Ready".into(),
        pending_invites: HashMap::new(),
        pending_room_codes: HashMap::new(),
        active_room_code: None,
        history: EphemeralHistoryStore::default(),
        reconnect_attempts: 0,
        reconnect_deadline_ms: None,
        expiry_timer_id: None,
        keepalive_timer_id: None,
        reconnect_timer_id: None,
        wipe_timer_id: None,
        verify_timer_id: None,
        handshake_timer_id: None,
        timers: None,
    }));

    // Allocate reusable timer callbacks once — zero per-refresh closure leaks.
    let timers = Rc::new(TimerCallbacks {
        expiry_cb: {
            let st_rc = Rc::clone(&state);
            Closure::new(move || on_expiry_timer(&st_rc))
        },
        keepalive_cb: {
            let st_rc = Rc::clone(&state);
            Closure::new(move || on_keepalive_timer(&st_rc))
        },
        reconnect_cb: {
            let st_rc = Rc::clone(&state);
            Closure::new(move || on_reconnect_timer(&st_rc))
        },
        wipe_cb: {
            let st_rc = Rc::clone(&state);
            Closure::new(move || on_wipe_timeout(&st_rc))
        },
        verify_cb: {
            let st_rc = Rc::clone(&state);
            Closure::new(move || on_visibility_verify_timeout(&st_rc))
        },
        handshake_cb: {
            let st_rc = Rc::clone(&state);
            Closure::new(move || on_handshake_timeout(&st_rc))
        },
    });
    state.borrow_mut().timers = Some(timers);

    let state_for_msg = Rc::clone(&state);
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
        // Safely collect any previously closed WebSocket on a clean stack turn.
        state_for_msg.borrow_mut().retired_ws = None;
        if let Some(mut text) = ev.data().as_string() {
            let parsed = serde_json::from_str::<UiToWorker>(&text);
            text.zeroize();
            match parsed {
                Ok(cmd) => handle_ui_command(&state_for_msg, cmd),
                Err(e) => {
                    post_to_ui(
                        &state_for_msg.borrow().scope,
                        &WorkerToUi::Error {
                            code: "bad_ui_cmd".into(),
                            message: e.to_string(),
                        },
                    );
                }
            }
        }
    });
    scope.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    // Single top-level worker lifetime handler.
    onmessage.forget();

    post_to_ui(&scope, &WorkerToUi::WorkerReady);
}

fn post_to_ui(scope: &DedicatedWorkerGlobalScope, msg: &WorkerToUi) {
    if let Ok(mut json) = serde_json::to_string(msg) {
        let _ = scope.post_message(&JsValue::from_str(&json));
        json.zeroize();
    }
}

fn emit_state(st: &WorkerState) {
    let admin_fingerprint = st
        .admin_signing_key
        .as_ref()
        .map(|k| k.fingerprint())
        .or_else(|| st.expected_admin_fingerprint.clone());
    let epoch = st.local_epoch();
    let effective_paused = st.messaging_paused || !st.is_epoch_synced();
    post_to_ui(
        &st.scope,
        &WorkerToUi::StateUpdate {
            phase: st.phase.as_str().into(),
            room_id: st.room_id.clone(),
            room_name: st.room_name.clone(),
            participant_id: st.participant_id.clone(),
            role: st.role,
            epoch,
            policy: st.policy,
            room_created_at_ms: st.room_created_at_ms,
            room_expires_at_ms: st.room_expires_at_ms,
            members: st.members.clone(),
            messaging_paused: effective_paused,
            status_text: st.status_text.clone(),
            admin_fingerprint,
        },
    );
}

fn send_ws(st: &WorkerState, msg: &ClientToRelay) -> Result<(), String> {
    let managed = st
        .ws
        .as_ref()
        .ok_or_else(|| "No active WebSocket connection".to_string())?;
    if managed.ws.ready_state() != WebSocket::OPEN {
        return Err("WebSocket is not connected".to_string());
    }
    let mut json = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    let res = managed
        .ws
        .send_with_str(&json)
        .map_err(|_| "Failed to send over WebSocket".to_string());
    json.zeroize();
    res
}

fn clear_timer(scope: &DedicatedWorkerGlobalScope, slot: &mut Option<i32>) {
    if let Some(id) = slot.take() {
        scope.clear_timeout_with_handle(id);
    }
}

fn clear_all_timers(st: &mut WorkerState) {
    let scope = st.scope.clone();
    clear_timer(&scope, &mut st.expiry_timer_id);
    clear_timer(&scope, &mut st.keepalive_timer_id);
    clear_timer(&scope, &mut st.reconnect_timer_id);
    clear_timer(&scope, &mut st.wipe_timer_id);
    clear_timer(&scope, &mut st.verify_timer_id);
    clear_timer(&scope, &mut st.handshake_timer_id);
}

fn arm_timeout(
    scope: &DedicatedWorkerGlobalScope,
    slot: &mut Option<i32>,
    cb: &Closure<dyn FnMut()>,
    delay_ms: i32,
) {
    clear_timer(scope, slot);
    if let Ok(id) = scope.set_timeout_with_callback_and_timeout_and_arguments_0(
        cb.as_ref().unchecked_ref(),
        delay_ms.max(10),
    ) {
        *slot = Some(id);
    }
}

fn wipe_session_state(st: &mut WorkerState, new_phase: Phase, status: &str, close_ws: bool) {
    clear_all_timers(st);
    st.retired_ws = None;
    st.history.wipe_all();
    if let Some(mut mls) = st.mls.take() {
        mls.wipe();
    }
    st.relay_epoch = 0;
    st.pending_admin_commit = None;
    st.queued_join_requests.clear();
    st.queued_removals.clear();
    st.relay_to_mls_id.clear();
    if let Some(mut tok) = st.resume_token.take() {
        tok.zeroize();
    }
    if let Some(mut attempt) = st.resume_attempt_id.take() {
        attempt.zeroize();
    }
    st.pending_join = None;
    st.pending_invites.clear();
    st.pending_room_codes.clear();
    st.active_room_code = None;
    st.room_name = None;
    st.pending_action = None;
    st.pending_visibility_check = None;
    st.verified_visibility_token = None;
    st.reconnect_attempts = 0;
    st.reconnect_deadline_ms = None;
    st.pending_ping_sent_at_ms = None;
    st.admin_verifier = None;
    if close_ws {
        st.admin_signing_key = None;
        st.wipe_room_id = None;
        st.ws_generation = st.ws_generation.wrapping_add(1);
        if let Some(ws) = st.ws.take() {
            ws.detach_and_close();
            drop(ws);
        }
    }
    st.members.clear();
    st.messaging_paused = false;
    st.phase = new_phase;
    st.status_text = status.into();

    post_to_ui(
        &st.scope,
        &WorkerToUi::ClearDisplay {
            reason: status.into(),
        },
    );
    emit_state(st);
}

fn handle_ui_command(state: &Rc<RefCell<WorkerState>>, cmd: UiToWorker) {
    match cmd {
        UiToWorker::RunMlsSelftest => {
            let scope = state.borrow().scope.clone();
            match run_mls_selftest() {
                Ok(report) => post_to_ui(
                    &scope,
                    &WorkerToUi::MlsSelftestResult {
                        ok: true,
                        report: Some(report),
                        error: None,
                    },
                ),
                Err(e) => post_to_ui(
                    &scope,
                    &WorkerToUi::MlsSelftestResult {
                        ok: false,
                        report: None,
                        error: Some(e.to_string()),
                    },
                ),
            }
        }
        UiToWorker::CreateRoom {
            relay_url,
            msg_ttl_secs,
            room_ttl_secs,
            room_name,
        } => {
            let policy = match RoomPolicy::new(msg_ttl_secs, room_ttl_secs) {
                Ok(p) => p,
                Err(e) => {
                    post_to_ui(
                        &state.borrow().scope,
                        &WorkerToUi::Error {
                            code: "invalid_policy".into(),
                            message: e.to_string(),
                        },
                    );
                    return;
                }
            };
            let admin_key = match AdminSigningKey::generate("pending") {
                Ok(k) => k,
                Err(e) => {
                    post_to_ui(
                        &state.borrow().scope,
                        &WorkerToUi::Error {
                            code: "keygen_failed".into(),
                            message: e.to_string(),
                        },
                    );
                    return;
                }
            };
            let clean_name = sanitize_room_name(room_name.as_deref());
            {
                let mut st = state.borrow_mut();
                wipe_session_state(&mut st, Phase::Connecting, "Connecting to relay...", true);
                st.relay_url = Some(relay_url);
                st.role = Some(ParticipantRole::Admin);
                st.policy = policy;
                st.room_name = clean_name.clone();
                st.admin_signing_key = Some(admin_key);
                st.pending_action = Some(PendingConnectAction::Create {
                    policy,
                    room_name: clean_name,
                });
                emit_state(&st);
            }
            open_websocket(state);
        }
        UiToWorker::JoinRoom {
            relay_url,
            room_id,
            invite_token,
            admin_fingerprint,
        } => {
            start_guest_join(
                state,
                relay_url,
                room_id,
                PendingJoinKind::Invite { invite_token },
                admin_fingerprint,
            );
        }
        UiToWorker::JoinWithRoomCode {
            relay_url,
            mut room_code,
        } => {
            let parsed = RoomCode::parse(&room_code);
            room_code.zeroize();
            let parsed = match parsed {
                Ok(c) => c,
                Err(_) => {
                    post_to_ui(
                        &state.borrow().scope,
                        &WorkerToUi::Error {
                            code: ROOM_CODE_ERROR_CODE.into(),
                            message: ROOM_CODE_ERROR_MSG.into(),
                        },
                    );
                    return;
                }
            };
            start_guest_join(
                state,
                relay_url,
                parsed.room_id.clone(),
                PendingJoinKind::RoomCode {
                    access_secret: parsed.access_secret.clone(),
                },
                parsed.admin_fingerprint.clone(),
            );
            // `parsed` drops here and zeroizes its fields.
        }
        UiToWorker::GenerateInvite => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active
                || st.role != Some(ParticipantRole::Admin)
                || !st.is_epoch_synced()
            {
                return;
            }
            let Ok(token) = random_token_b64url(24) else {
                return;
            };
            let token_hash_hex = sha256_hex(token.as_bytes());
            let epoch = st.local_epoch();
            let ttl = st.invite_ttl_secs;
            let signed_cmd = match st.admin_signing_key.as_mut() {
                Some(key) => match key.sign_command(
                    epoch,
                    AdminCommandPayload::RegisterInvite {
                        token_hash_hex: token_hash_hex.clone(),
                        invite_ttl_secs: ttl,
                    },
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        post_to_ui(
                            &st.scope,
                            &WorkerToUi::Error {
                                code: "sign_failed".into(),
                                message: e.to_string(),
                            },
                        );
                        return;
                    }
                },
                None => return,
            };
            st.pending_invites
                .insert(token_hash_hex, PendingInvite { token });
            if let Err(e) = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd }) {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "send_failed".into(),
                        message: e,
                    },
                );
            }
        }
        UiToWorker::GenerateRoomCode => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active
                || st.role != Some(ParticipantRole::Admin)
                || !st.is_epoch_synced()
            {
                return;
            }
            let Some(room_id) = st.room_id.clone() else {
                return;
            };
            let Ok(secret) = random_token_b64url(24) else {
                return;
            };
            let epoch = st.local_epoch();
            let ttl = st.room_code_ttl_secs;
            let (code, secret_hash_hex, signed_cmd) = match st.admin_signing_key.as_mut() {
                Some(key) => {
                    let fp = key.fingerprint();
                    let Ok(code) = RoomCode::new(&room_id, &secret, &fp) else {
                        return;
                    };
                    let hash = code.secret_hash_hex();
                    match key.sign_command(
                        epoch,
                        AdminCommandPayload::SetRoomCode {
                            secret_hash_hex: hash.clone(),
                            code_ttl_secs: ttl,
                        },
                    ) {
                        Ok(c) => (code, hash, c),
                        Err(e) => {
                            post_to_ui(
                                &st.scope,
                                &WorkerToUi::Error {
                                    code: "sign_failed".into(),
                                    message: e.to_string(),
                                },
                            );
                            return;
                        }
                    }
                }
                None => return,
            };
            st.pending_room_codes.insert(secret_hash_hex, code);
            if let Err(e) = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd }) {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "send_failed".into(),
                        message: e,
                    },
                );
            }
        }
        UiToWorker::RevokeRoomCode => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active
                || st.role != Some(ParticipantRole::Admin)
                || !st.is_epoch_synced()
            {
                return;
            }
            let epoch = st.local_epoch();
            let Some(key) = st.admin_signing_key.as_mut() else {
                return;
            };
            let Ok(signed_cmd) = key.sign_command(epoch, AdminCommandPayload::RevokeRoomCode)
            else {
                return;
            };
            if let Err(e) = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd }) {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "send_failed".into(),
                        message: e,
                    },
                );
            }
        }
        UiToWorker::SendMessage { mut text } => {
            let mut st = state.borrow_mut();
            let now = now_ms();
            if st.phase != Phase::Active || now >= st.room_expires_at_ms {
                text.zeroize();
                if now >= st.room_expires_at_ms && st.room_expires_at_ms > 0 {
                    wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
                }
                return;
            }
            if st.messaging_paused || !st.is_epoch_synced() {
                text.zeroize();
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "messaging_paused".into(),
                        message:
                            "Messaging paused until membership change completes in the verified MLS epoch."
                                .into(),
                    },
                );
                return;
            }
            let trimmed = Zeroizing::new(text.trim().to_string());
            text.zeroize();
            if trimmed.is_empty() {
                return;
            }

            let Ok(message_id) = random_token_b64url(12) else {
                return;
            };
            let payload = ChatAppPayload {
                message_id: message_id.clone(),
                text: (*trimmed).clone(),
                sent_at_ms: now,
            };

            let (ct_bytes, epoch) = match st.mls.as_mut() {
                Some(mls) => match mls.encrypt_chat_message(&payload) {
                    Ok(ct) => (ct, mls.current_epoch()),
                    Err(e) => {
                        post_to_ui(
                            &st.scope,
                            &WorkerToUi::Error {
                                code: "encrypt_failed".into(),
                                message: e.to_string(),
                            },
                        );
                        return;
                    }
                },
                None => return,
            };

            let send_res = send_ws(
                &st,
                &ClientToRelay::SendMlsMessage {
                    epoch,
                    message_id: message_id.clone(),
                    ciphertext_b64: STANDARD.encode(&ct_bytes),
                },
            );
            if let Err(e) = send_res {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "send_failed".into(),
                        message: e,
                    },
                );
                return;
            }

            let self_id = st.participant_id.clone().unwrap_or_else(|| "self".into());
            let is_admin = st.role == Some(ParticipantRole::Admin);
            let ttl = st.policy.msg_ttl_secs;
            let room_exp = st.room_expires_at_ms;
            if let Ok(outcome) = st.history.insert(
                message_id, self_id, is_admin, true, &trimmed, now, now, ttl, room_exp,
            ) {
                emit_incremental_insert(&st, outcome);
            }
            schedule_next_expiry_timer(&mut st);
        }
        UiToWorker::UpdatePolicy {
            msg_ttl_secs,
            room_ttl_secs,
        } => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active
                || st.role != Some(ParticipantRole::Admin)
                || !st.is_epoch_synced()
            {
                return;
            }
            if let Err(e) = RoomPolicy::new(msg_ttl_secs, room_ttl_secs) {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "invalid_policy".into(),
                        message: e.to_string(),
                    },
                );
                return;
            }
            let epoch = st.local_epoch();
            let Some(key) = st.admin_signing_key.as_mut() else {
                return;
            };
            let Ok(signed_cmd) = key.sign_command(
                epoch,
                AdminCommandPayload::SetPolicy {
                    msg_ttl_secs,
                    room_ttl_secs,
                },
            ) else {
                return;
            };
            if let Err(e) = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd }) {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "send_failed".into(),
                        message: e,
                    },
                );
            }
        }
        UiToWorker::KickGuest { participant_id } => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active
                || st.role != Some(ParticipantRole::Admin)
                || !st.is_epoch_synced()
            {
                return;
            }
            let epoch = st.local_epoch();
            let Some(key) = st.admin_signing_key.as_mut() else {
                return;
            };
            let Ok(signed_cmd) =
                key.sign_command(epoch, AdminCommandPayload::KickGuest { participant_id })
            else {
                return;
            };
            if let Err(e) = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd }) {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "send_failed".into(),
                        message: e,
                    },
                );
            }
        }
        UiToWorker::PanicWipe => {
            // Section 7: Immediately hide & wipe local history, sign PanicWipe for Relay,
            // keep socket open briefly ONLY with a hard timeout to receive PanicWipeConfirmed.
            let mut st = state.borrow_mut();
            if st.role != Some(ParticipantRole::Admin) {
                wipe_session_state(&mut st, Phase::Ended, "Local history cleared.", true);
                return;
            }
            let target_room_id = st.room_id.clone();
            let epoch = st.local_epoch();
            let signed_cmd = st
                .admin_signing_key
                .as_mut()
                .and_then(|k| k.sign_command(epoch, AdminCommandPayload::PanicWipe).ok());
            // Immediately wipe local history & MLS state while keeping WS briefly for confirmation.
            wipe_session_state(
                &mut st,
                Phase::WipedLocal,
                "Cleared locally — waiting for relay room-closure confirmation...",
                false,
            );
            st.admin_signing_key = None;
            st.wipe_room_id = target_room_id;

            if let Some(cmd) = signed_cmd {
                if send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd: cmd }).is_err() {
                    wipe_session_state(
                        &mut st,
                        Phase::WipedUnconfirmed,
                        "Cleared locally — room closure unconfirmed (relay unreachable).",
                        true,
                    );
                } else if let Some(timers) = st.timers.clone() {
                    let scope = st.scope.clone();
                    arm_timeout(
                        &scope,
                        &mut st.wipe_timer_id,
                        &timers.wipe_cb,
                        PANIC_WIPE_CONFIRM_TIMEOUT_MS,
                    );
                }
            } else {
                wipe_session_state(
                    &mut st,
                    Phase::WipedUnconfirmed,
                    "Cleared locally — room closure unconfirmed.",
                    true,
                );
            }
        }
        UiToWorker::LeaveRoom => {
            let mut st = state.borrow_mut();
            let _ = send_ws(&st, &ClientToRelay::LeaveRoom);
            wipe_session_state(&mut st, Phase::Ended, "Left room.", true);
        }
        UiToWorker::UiHidden => {
            // Section 6: Invalidate current visibility verification; keep encrypted history in RAM.
            let mut st = state.borrow_mut();
            let scope = st.scope.clone();
            st.ui_visible = false;
            st.verified_visibility_token = None;
            st.pending_visibility_check = None;
            clear_timer(&scope, &mut st.verify_timer_id);
        }
        UiToWorker::UiVisible {
            visibility_token,
            force_reconnect,
        }
        | UiToWorker::CheckConnection {
            visibility_token,
            force_reconnect,
        } => {
            handle_session_check(state, visibility_token, force_reconnect);
        }
    }
}

fn start_guest_join(
    state: &Rc<RefCell<WorkerState>>,
    relay_url: String,
    room_id: String,
    kind: PendingJoinKind,
    admin_fingerprint: String,
) {
    let provisional_id = match random_token_b64url(8) {
        Ok(id) => id,
        Err(e) => {
            post_to_ui(
                &state.borrow().scope,
                &WorkerToUi::Error {
                    code: "rng_failed".into(),
                    message: e.to_string(),
                },
            );
            return;
        }
    };
    let client_join_nonce = match random_token_b64url(16) {
        Ok(n) => n,
        Err(e) => {
            post_to_ui(
                &state.borrow().scope,
                &WorkerToUi::Error {
                    code: "rng_failed".into(),
                    message: e.to_string(),
                },
            );
            return;
        }
    };
    let mls = match MlsSession::new_guest(&room_id, &provisional_id) {
        Ok(m) => m,
        Err(e) => {
            post_to_ui(
                &state.borrow().scope,
                &WorkerToUi::Error {
                    code: "mls_init_failed".into(),
                    message: e.to_string(),
                },
            );
            return;
        }
    };
    let kp_bytes = match mls.generate_key_package() {
        Ok(kp) => kp,
        Err(e) => {
            post_to_ui(
                &state.borrow().scope,
                &WorkerToUi::Error {
                    code: "kp_failed".into(),
                    message: e.to_string(),
                },
            );
            return;
        }
    };
    let key_package_b64 = STANDARD.encode(&kp_bytes);

    {
        let mut st = state.borrow_mut();
        wipe_session_state(&mut st, Phase::Connecting, "Joining room...", true);
        st.relay_url = Some(relay_url);
        st.room_id = Some(room_id.clone());
        st.role = Some(ParticipantRole::Guest);
        st.expected_admin_fingerprint = Some(admin_fingerprint);
        st.mls = Some(mls);
        st.pending_join = Some(PendingJoinAttempt {
            room_id,
            kind,
            client_join_nonce,
            key_package_b64,
            deadline_ms: now_ms().saturating_add(JOIN_RETRY_DEADLINE_MS),
        });
        st.pending_action = Some(PendingConnectAction::Join);
        emit_state(&st);
    }
    open_websocket(state);
}

fn emit_room_code_state(st: &mut WorkerState) {
    if st.role != Some(ParticipantRole::Admin) || !st.can_render_now() {
        return;
    }
    let now = now_ms();
    if let Some((code, exp)) = &st.active_room_code {
        if now >= *exp {
            st.active_room_code = None;
            post_to_ui(
                &st.scope,
                &WorkerToUi::RoomCodeState {
                    active: false,
                    room_code: None,
                    expires_at_ms: 0,
                },
            );
        } else {
            let encoded = code.encode();
            post_to_ui(
                &st.scope,
                &WorkerToUi::RoomCodeState {
                    active: true,
                    room_code: Some((*encoded).clone()),
                    expires_at_ms: *exp,
                },
            );
        }
    } else {
        post_to_ui(
            &st.scope,
            &WorkerToUi::RoomCodeState {
                active: false,
                room_code: None,
                expires_at_ms: 0,
            },
        );
    }
}

fn handle_session_check(
    state: &Rc<RefCell<WorkerState>>,
    visibility_token: u64,
    force_reconnect: bool,
) {
    // Keep UI shielded until fresh server verification of room, deadline,
    // membership, and MLS epoch completes for THIS visibility transition!
    let should_open_ws = {
        let mut st = state.borrow_mut();
        let now = now_ms();
        st.ui_visible = true;
        st.visibility_token = visibility_token;

        if st.room_expires_at_ms > 0 && now >= st.room_expires_at_ms {
            wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
            return;
        }
        if let Some(deadline) = st.reconnect_deadline_ms
            && now >= deadline
        {
            wipe_session_state(&mut st, Phase::Ended, "Reconnect window expired.", true);
            return;
        }

        match st.phase {
            Phase::Reconnecting => {
                st.verified_visibility_token = None;
                st.pending_visibility_check = None;
                let scope = st.scope.clone();
                if st.ws.is_some() {
                    if force_reconnect {
                        // Manual retry or network switch: cleanly replace stalled socket without parallel connections.
                        clear_timer(&scope, &mut st.reconnect_timer_id);
                        clear_timer(&scope, &mut st.handshake_timer_id);
                        st.ws_generation = st.ws_generation.wrapping_add(1);
                        if let Some(old_ws) = st.ws.take() {
                            old_ws.detach_and_close();
                            drop(old_ws);
                        }
                        st.pending_action = Some(PendingConnectAction::Resume);
                        emit_state(&st);
                        true
                    } else {
                        // Coalesce overlapping return events while a Resume handshake is already in flight.
                        emit_state(&st);
                        false
                    }
                } else {
                    // Waiting on backoff timer -> attempt Resume immediately without waiting for throttled timer.
                    clear_timer(&scope, &mut st.reconnect_timer_id);
                    st.pending_action = Some(PendingConnectAction::Resume);
                    emit_state(&st);
                    true
                }
            }
            Phase::Active => {
                if !st.is_epoch_synced() {
                    // Bound the wait even when a pending MLS change prevents a verification request.
                    // Never restart an already-armed verify timeout so automatic retries cannot push it out.
                    if st.verify_timer_id.is_none()
                        && let Some(timers) = st.timers.clone()
                    {
                        let scope = st.scope.clone();
                        arm_timeout(
                            &scope,
                            &mut st.verify_timer_id,
                            &timers.verify_cb,
                            VISIBILITY_VERIFY_TIMEOUT_MS,
                        );
                    }
                    return;
                }
                if let Some((ref mut req_tok, _)) = st.pending_visibility_check
                    && !force_reconnect
                {
                    // Coalesce overlapping return events into the in-flight VerifySession check.
                    *req_tok = visibility_token;
                    return;
                }
                st.verified_visibility_token = None;
                st.pending_visibility_check = None;
                let Ok(check_id) = random_token_b64url(12) else {
                    return;
                };
                let local_epoch = st.local_epoch();
                if send_ws(
                    &st,
                    &ClientToRelay::VerifySession {
                        check_id: check_id.clone(),
                        local_epoch,
                    },
                )
                .is_err()
                {
                    // Existing socket is closed/unavailable -> start Resume in the same tab.
                    enter_reconnecting_from_active(&mut st);
                    return;
                }
                st.pending_visibility_check = Some((visibility_token, check_id));
                if let Some(timers) = st.timers.clone() {
                    let scope = st.scope.clone();
                    arm_timeout(
                        &scope,
                        &mut st.verify_timer_id,
                        &timers.verify_cb,
                        VISIBILITY_VERIFY_TIMEOUT_MS,
                    );
                }
                false
            }
            Phase::PendingJoin => {
                if force_reconnect
                    && st.ws.is_none()
                    && st
                        .pending_join
                        .as_ref()
                        .is_some_and(|pj| now < pj.deadline_ms)
                {
                    let scope = st.scope.clone();
                    clear_timer(&scope, &mut st.reconnect_timer_id);
                    st.pending_action = Some(PendingConnectAction::Join);
                    emit_state(&st);
                    true
                } else {
                    emit_state(&st);
                    false
                }
            }
            _ => {
                // Remain shielded / in current non-active view; never release history.
                emit_state(&st);
                false
            }
        }
    };
    if should_open_ws {
        open_websocket(state);
    }
}

fn emit_incremental_insert(st: &WorkerState, outcome: core_crypto::ephemeral_store::InsertOutcome) {
    if !st.can_render_now() {
        return;
    }
    let tok = st.visibility_token;
    if !outcome.evicted_ids.is_empty() {
        post_to_ui(
            &st.scope,
            &WorkerToUi::RemoveMessages {
                visibility_token: tok,
                message_ids: outcome.evicted_ids,
            },
        );
    }
    if let Some(message) = outcome.inserted {
        post_to_ui(
            &st.scope,
            &WorkerToUi::AppendMessage {
                visibility_token: tok,
                message,
            },
        );
    }
}

fn render_full_if_verified(st: &mut WorkerState) {
    if !st.can_render_now() {
        return;
    }
    let now = now_ms();
    let room_exp = st.room_expires_at_ms;
    if room_exp > 0 && now >= room_exp {
        wipe_session_state(st, Phase::Ended, "Room lifetime expired.", true);
        return;
    }
    if let Ok(visible) = st.history.decrypt_visible(now, room_exp) {
        let tok = st.visibility_token;
        post_to_ui(
            &st.scope,
            &WorkerToUi::RenderHistory {
                visibility_token: tok,
                messages: visible,
            },
        );
    }
    emit_room_code_state(st);
    schedule_next_expiry_timer(st);
}

fn schedule_next_expiry_timer(st: &mut WorkerState) {
    let scope = st.scope.clone();
    clear_timer(&scope, &mut st.expiry_timer_id);
    if st.phase != Phase::Active {
        return;
    }
    let now = now_ms();
    let next_msg_exp = st.history.next_expiry_ms();
    let next_event = match (next_msg_exp, st.room_expires_at_ms) {
        (Some(m), r) if r > 0 => Some(m.min(r)),
        (Some(m), _) => Some(m),
        (None, r) if r > 0 => Some(r),
        _ => None,
    };
    if let (Some(ts), Some(timers)) = (next_event, st.timers.clone()) {
        let delay = ts.saturating_sub(now).clamp(100, 60_000) as i32;
        arm_timeout(&scope, &mut st.expiry_timer_id, &timers.expiry_cb, delay);
    }
}

fn schedule_keepalive_timer(st: &mut WorkerState, delay_ms: i32) {
    let scope = st.scope.clone();
    clear_timer(&scope, &mut st.keepalive_timer_id);
    if st.ws.is_none() || !matches!(st.phase, Phase::Active | Phase::PendingJoin) {
        return;
    }
    if let Some(timers) = st.timers.clone() {
        arm_timeout(
            &scope,
            &mut st.keepalive_timer_id,
            &timers.keepalive_cb,
            delay_ms,
        );
    }
}

fn enter_reconnecting_from_active(st: &mut WorkerState) {
    let now = now_ms();
    if st.room_expires_at_ms > 0 && now >= st.room_expires_at_ms {
        wipe_session_state(st, Phase::Ended, "Room lifetime expired.", true);
        return;
    }
    let scope = st.scope.clone();
    clear_timer(&scope, &mut st.keepalive_timer_id);
    clear_timer(&scope, &mut st.verify_timer_id);
    clear_timer(&scope, &mut st.handshake_timer_id);
    st.pending_visibility_check = None;
    st.verified_visibility_token = None;
    st.pending_ping_sent_at_ms = None;

    // If Admin had an unconfirmed staged commit in flight when socket dropped, discard it cleanly
    // so local MLS state matches the last confirmed epoch!
    if let Some(pending) = st.pending_admin_commit.take() {
        if let Some(mls) = st.mls.as_mut() {
            mls.clear_pending_commit();
        }
        if let AdminCommitKind::Remove { participant_id } = pending.kind {
            st.queued_removals
                .push_front((participant_id, "Retrying pending removal".into()));
        }
    }

    // Set absolute reconnect deadline and attempt ID ONCE when entering Reconnecting!
    // Admin always gets 5 minutes on unintentional disconnect (capped at room expiry);
    // Guests keep the 60-second reconnect grace window.
    let is_admin = st.role == Some(ParticipantRole::Admin);
    let grace_secs = if is_admin {
        ADMIN_RECONNECT_GRACE_SECS
    } else {
        RECONNECT_GRACE_SECS
    };
    if st.reconnect_deadline_ms.is_none() {
        let grace_deadline = now.saturating_add(grace_secs.saturating_mul(1000));
        let capped = if st.room_expires_at_ms > 0 {
            grace_deadline.min(st.room_expires_at_ms)
        } else {
            grace_deadline
        };
        st.reconnect_deadline_ms = Some(capped);
    }
    if st.resume_attempt_id.is_none() {
        st.resume_attempt_id = random_token_b64url(16).ok();
    }

    st.phase = Phase::Reconnecting;
    st.status_text = if is_admin {
        "Connection interrupted — attempting to resume (up to 5 min window)...".into()
    } else {
        "Connection interrupted — attempting to reconnect (60s window)...".into()
    };
    post_to_ui(
        &st.scope,
        &WorkerToUi::ClearDisplay {
            reason: "Connection interrupted".into(),
        },
    );
    emit_state(st);
    schedule_reconnect_timer(st);
}

fn schedule_reconnect_timer(st: &mut WorkerState) {
    let now = now_ms();
    let scope = st.scope.clone();
    clear_timer(&scope, &mut st.reconnect_timer_id);

    match st.phase {
        Phase::Reconnecting => {
            if st.room_expires_at_ms > 0 && now >= st.room_expires_at_ms {
                wipe_session_state(st, Phase::Ended, "Room lifetime expired.", true);
                return;
            }
            let Some(deadline) = st.reconnect_deadline_ms else {
                wipe_session_state(st, Phase::Ended, "Reconnect window expired.", true);
                return;
            };
            if now >= deadline {
                wipe_session_state(
                    st,
                    Phase::Ended,
                    "Reconnect window expired. Please start a new room or request a new invite link.",
                    true,
                );
                return;
            }
            st.reconnect_attempts = st.reconnect_attempts.saturating_add(1);
            st.pending_action = Some(PendingConnectAction::Resume);
            let backoff_ms = (1000u64 * u64::from(st.reconnect_attempts.min(5)))
                .min(deadline.saturating_sub(now))
                .max(100) as i32;
            if let Some(timers) = st.timers.clone() {
                arm_timeout(
                    &scope,
                    &mut st.reconnect_timer_id,
                    &timers.reconnect_cb,
                    backoff_ms,
                );
            }
        }
        Phase::Connecting | Phase::PendingJoin => {
            let Some(pj) = &st.pending_join else {
                wipe_session_state(st, Phase::Ended, "Disconnected from relay.", true);
                return;
            };
            if now >= pj.deadline_ms {
                wipe_session_state(
                    st,
                    Phase::Ended,
                    "Join attempt timed out before admission completed.",
                    true,
                );
                return;
            }
            st.reconnect_attempts = st.reconnect_attempts.saturating_add(1);
            st.pending_action = Some(PendingConnectAction::Join);
            let backoff_ms = (1000u64 * u64::from(st.reconnect_attempts.min(4)))
                .min(pj.deadline_ms.saturating_sub(now))
                .max(100) as i32;
            if let Some(timers) = st.timers.clone() {
                arm_timeout(
                    &scope,
                    &mut st.reconnect_timer_id,
                    &timers.reconnect_cb,
                    backoff_ms,
                );
            }
        }
        _ => {}
    }
}

fn on_expiry_timer(state: &Rc<RefCell<WorkerState>>) {
    let mut st = state.borrow_mut();
    st.retired_ws = None;
    st.expiry_timer_id = None;
    if st.phase != Phase::Active {
        return;
    }
    let now = now_ms();
    if st.room_expires_at_ms > 0 && now >= st.room_expires_at_ms {
        wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
        return;
    }
    let room_exp = st.room_expires_at_ms;
    let expired_ids = st.history.prune_expired(now, room_exp);
    if !expired_ids.is_empty() && st.can_render_now() {
        post_to_ui(
            &st.scope,
            &WorkerToUi::RemoveMessages {
                visibility_token: st.visibility_token,
                message_ids: expired_ids,
            },
        );
    }
    schedule_next_expiry_timer(&mut st);
}

fn on_keepalive_timer(state: &Rc<RefCell<WorkerState>>) {
    let mut st = state.borrow_mut();
    st.retired_ws = None;
    st.keepalive_timer_id = None;
    if st.ws.is_none() || !matches!(st.phase, Phase::Active | Phase::PendingJoin) {
        return;
    }
    let now = now_ms();
    let interval_ms = st.keepalive_interval_secs.clamp(5, 60) * 1000;

    if let Some(sent_at) = st.pending_ping_sent_at_ms {
        if now.saturating_sub(sent_at) >= KEEPALIVE_LIVENESS_TIMEOUT_MS {
            // Heartbeat liveness failed: close stalled socket and trigger reconnect/retry!
            st.ws_generation = st.ws_generation.wrapping_add(1);
            if let Some(ws) = st.ws.take() {
                ws.detach_and_close();
                drop(ws);
            }
            if st.phase == Phase::Active {
                enter_reconnecting_from_active(&mut st);
            } else {
                schedule_reconnect_timer(&mut st);
            }
            return;
        }
        let remaining = KEEPALIVE_LIVENESS_TIMEOUT_MS.saturating_sub(now.saturating_sub(sent_at));
        schedule_keepalive_timer(&mut st, remaining.max(250) as i32);
        return;
    }

    let idle_ms = now.saturating_sub(st.last_relay_activity_ms);
    if idle_ms >= interval_ms {
        if send_ws(&st, &ClientToRelay::Ping { ts_ms: now }).is_err() {
            st.ws_generation = st.ws_generation.wrapping_add(1);
            if let Some(ws) = st.ws.take() {
                ws.detach_and_close();
                drop(ws);
            }
            if st.phase == Phase::Active {
                enter_reconnecting_from_active(&mut st);
            } else {
                schedule_reconnect_timer(&mut st);
            }
            return;
        }
        st.pending_ping_sent_at_ms = Some(now);
        schedule_keepalive_timer(&mut st, KEEPALIVE_LIVENESS_TIMEOUT_MS as i32);
    } else {
        let wait_ms = interval_ms.saturating_sub(idle_ms).max(250) as i32;
        schedule_keepalive_timer(&mut st, wait_ms);
    }
}

fn on_reconnect_timer(state: &Rc<RefCell<WorkerState>>) {
    let should_open = {
        let mut st = state.borrow_mut();
        st.retired_ws = None;
        st.reconnect_timer_id = None;
        let now = now_ms();
        match st.phase {
            Phase::Reconnecting => {
                if st.room_expires_at_ms > 0 && now >= st.room_expires_at_ms {
                    wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
                    false
                } else if st.reconnect_deadline_ms.is_some_and(|d| now >= d) {
                    wipe_session_state(&mut st, Phase::Ended, "Reconnect window expired.", true);
                    false
                } else {
                    true
                }
            }
            Phase::Connecting | Phase::PendingJoin => {
                if st
                    .pending_join
                    .as_ref()
                    .is_some_and(|pj| now < pj.deadline_ms)
                {
                    true
                } else {
                    wipe_session_state(&mut st, Phase::Ended, "Join attempt timed out.", true);
                    false
                }
            }
            _ => false,
        }
    };
    if should_open {
        open_websocket(state);
    }
}

fn on_wipe_timeout(state: &Rc<RefCell<WorkerState>>) {
    let mut st = state.borrow_mut();
    st.wipe_timer_id = None;
    if st.phase == Phase::WipedLocal {
        wipe_session_state(
            &mut st,
            Phase::WipedUnconfirmed,
            "Cleared locally — room closure unconfirmed by relay (timed out).",
            true,
        );
    }
}

fn on_visibility_verify_timeout(state: &Rc<RefCell<WorkerState>>) {
    let mut st = state.borrow_mut();
    st.verify_timer_id = None;
    if st.phase == Phase::Active
        && st.ui_visible
        && st.verified_visibility_token != Some(st.visibility_token)
    {
        st.pending_visibility_check = None;
        st.ws_generation = st.ws_generation.wrapping_add(1);
        if let Some(ws) = st.ws.take() {
            ws.detach_and_close();
            drop(ws);
        }
        enter_reconnecting_from_active(&mut st);
    }
}

fn on_handshake_timeout(state: &Rc<RefCell<WorkerState>>) {
    let mut st = state.borrow_mut();
    st.handshake_timer_id = None;
    if matches!(
        st.phase,
        Phase::Reconnecting | Phase::Connecting | Phase::PendingJoin
    ) {
        // WebSocket opened but SessionResumed / JoinPending / JoinAccepted never arrived.
        st.ws_generation = st.ws_generation.wrapping_add(1);
        if let Some(ws) = st.ws.take() {
            ws.detach_and_close();
            drop(ws);
        }
        schedule_reconnect_timer(&mut st);
    }
}

fn open_websocket(state: &Rc<RefCell<WorkerState>>) {
    let (relay_url, generation, scope) = {
        let mut st = state.borrow_mut();
        st.retired_ws = None;
        st.ws_generation = st.ws_generation.wrapping_add(1);
        if let Some(old) = st.ws.take() {
            old.detach_and_close();
            drop(old);
        }
        let Some(url) = st.relay_url.clone() else {
            return;
        };
        (url, st.ws_generation, st.scope.clone())
    };

    let ws = match WebSocket::new(&relay_url) {
        Ok(ws) => ws,
        Err(_) => {
            post_to_ui(
                &scope,
                &WorkerToUi::Error {
                    code: "ws_connect_failed".into(),
                    message: "Could not open WebSocket connection to relay.".into(),
                },
            );
            let mut st = state.borrow_mut();
            schedule_reconnect_timer(&mut st);
            return;
        }
    };

    // onopen
    let state_open = Rc::clone(state);
    let onopen = Closure::<dyn FnMut()>::new(move || {
        let mut st = state_open.borrow_mut();
        st.retired_ws = None;
        if st.ws_generation != generation {
            return;
        }
        let now = now_ms();
        st.last_relay_activity_ms = now;
        st.pending_ping_sent_at_ms = None;

        // Do NOT reset reconnect_attempts or reconnect_deadline_ms on WebSocket open!
        // They are reset ONLY once SessionResumed / JoinAccepted actually succeeds.
        let action = st.pending_action.take();
        match action {
            Some(PendingConnectAction::Create { policy, room_name }) => {
                if let Some(key) = &st.admin_signing_key {
                    let msg = ClientToRelay::CreateRoom {
                        admin_pubkey_b64: key.verifying_key_b64(),
                        initial_policy: policy,
                        room_name,
                    };
                    let _ = send_ws(&st, &msg);
                }
            }
            Some(PendingConnectAction::Join) => {
                // Keep pending_join intact in RAM for idempotent retries until JoinAccepted or deadline!
                if let Some(pj) = &st.pending_join {
                    if now >= pj.deadline_ms {
                        wipe_session_state(&mut st, Phase::Ended, "Join attempt timed out.", true);
                        return;
                    }
                    let msg = match &pj.kind {
                        PendingJoinKind::Invite { invite_token } => ClientToRelay::JoinRoom {
                            room_id: pj.room_id.clone(),
                            invite_token: invite_token.clone(),
                            key_package_b64: pj.key_package_b64.clone(),
                            client_join_nonce: pj.client_join_nonce.clone(),
                        },
                        PendingJoinKind::RoomCode { access_secret } => {
                            ClientToRelay::JoinRoomWithCode {
                                room_id: pj.room_id.clone(),
                                access_secret: access_secret.clone(),
                                key_package_b64: pj.key_package_b64.clone(),
                                client_join_nonce: pj.client_join_nonce.clone(),
                            }
                        }
                    };
                    let _ = send_ws(&st, &msg);
                    let remaining = pj.deadline_ms.saturating_sub(now);
                    let timeout_ms = remaining.min(RESUME_HANDSHAKE_TIMEOUT_MS as u64) as i32;
                    if let Some(timers) = st.timers.clone() {
                        let scope = st.scope.clone();
                        arm_timeout(
                            &scope,
                            &mut st.handshake_timer_id,
                            &timers.handshake_cb,
                            timeout_ms,
                        );
                    }
                }
            }
            Some(PendingConnectAction::Resume) => {
                if let Some(deadline) = st.reconnect_deadline_ms
                    && now >= deadline
                {
                    wipe_session_state(&mut st, Phase::Ended, "Reconnect window expired.", true);
                    return;
                }
                if let (Some(room_id), Some(participant_id), Some(resume_token), Some(attempt_id)) = (
                    st.room_id.clone(),
                    st.participant_id.clone(),
                    st.resume_token.clone(),
                    st.resume_attempt_id.clone(),
                ) {
                    let last_epoch = st.local_epoch();
                    let _ = send_ws(
                        &st,
                        &ClientToRelay::ResumeSession {
                            room_id,
                            participant_id,
                            resume_token,
                            resume_attempt_id: attempt_id,
                            last_epoch,
                        },
                    );
                    let timeout_ms = st
                        .reconnect_deadline_ms
                        .map(|d| {
                            d.saturating_sub(now)
                                .min(RESUME_HANDSHAKE_TIMEOUT_MS as u64)
                        })
                        .unwrap_or(RESUME_HANDSHAKE_TIMEOUT_MS as u64)
                        as i32;
                    if let Some(timers) = st.timers.clone() {
                        let scope = st.scope.clone();
                        arm_timeout(
                            &scope,
                            &mut st.handshake_timer_id,
                            &timers.handshake_cb,
                            timeout_ms,
                        );
                    }
                }
            }
            None => {}
        }
        let ka_ms = (st.keepalive_interval_secs.clamp(5, 60) * 1000) as i32;
        schedule_keepalive_timer(&mut st, ka_ms);
    });
    ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));

    // onmessage
    let state_msg = Rc::clone(state);
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
        {
            let mut st = state_msg.borrow_mut();
            st.retired_ws = None;
            if st.ws_generation != generation {
                return;
            }
            st.last_relay_activity_ms = now_ms();
            st.pending_ping_sent_at_ms = None;
        }
        if let Some(mut text) = ev.data().as_string() {
            let parsed = serde_json::from_str::<RelayToClient>(&text);
            text.zeroize();
            if let Ok(msg) = parsed {
                handle_relay_message(&state_msg, msg);
            }
        }
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

    // onclose
    let state_close = Rc::clone(state);
    let onclose = Closure::<dyn FnMut()>::new(move || {
        let mut st = state_close.borrow_mut();
        if st.ws_generation != generation {
            return;
        }
        // Move ManagedWebSocket into retired_ws (do NOT drop this running closure synchronously!).
        if let Some(old_ws) = st.ws.take() {
            old_ws.detach_and_close();
            st.retired_ws = Some(old_ws);
        }
        let scope = st.scope.clone();
        clear_timer(&scope, &mut st.keepalive_timer_id);
        clear_timer(&scope, &mut st.handshake_timer_id);
        clear_timer(&scope, &mut st.verify_timer_id);

        match st.phase {
            Phase::Active => {
                enter_reconnecting_from_active(&mut st);
            }
            Phase::Reconnecting => {
                schedule_reconnect_timer(&mut st);
            }
            Phase::WipedLocal => {
                // Socket closed before PanicWipeConfirmed arrived -> report unconfirmed cleanly.
                clear_timer(&scope, &mut st.wipe_timer_id);
                st.phase = Phase::WipedUnconfirmed;
                st.wipe_room_id = None;
                st.status_text =
                    "Cleared locally — room closure unconfirmed (relay disconnected).".into();
                emit_state(&st);
            }
            Phase::WipedConfirmed | Phase::WipedUnconfirmed | Phase::Ended | Phase::Idle => {}
            Phase::Connecting | Phase::PendingJoin => {
                // Keep pending_join and MLS session intact if within the fixed join retry deadline!
                if let Some(pj) = &st.pending_join
                    && now_ms() < pj.deadline_ms
                {
                    st.status_text =
                        "Connection interrupted — retrying join with preserved invite attempt..."
                            .into();
                    emit_state(&st);
                    schedule_reconnect_timer(&mut st);
                } else {
                    wipe_session_state(&mut st, Phase::Ended, "Disconnected from relay.", true);
                }
            }
        }
    });
    ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));

    state.borrow_mut().ws = Some(ManagedWebSocket {
        ws,
        _onopen: onopen,
        _onmessage: onmessage,
        _onclose: onclose,
    });
}

fn process_next_admin_task(st: &mut WorkerState) {
    if st.role != Some(ParticipantRole::Admin)
        || st.phase != Phase::Active
        || st.pending_admin_commit.is_some()
    {
        return;
    }

    // Prioritize removals before new admissions.
    if let Some((participant_id, reason)) = st.queued_removals.pop_front() {
        st.messaging_paused = true;
        st.status_text = format!("Removing member ({reason}) — rotating MLS keys...");
        emit_state(st);

        let target_mls_id = st
            .relay_to_mls_id
            .get(&participant_id)
            .cloned()
            .unwrap_or_else(|| participant_id.clone());
        let Ok(commit_id) = random_token_b64url(12) else {
            return;
        };
        let staged = match st.mls.as_mut() {
            Some(mls) => mls.stage_remove_member_by_participant_id(&target_mls_id),
            None => return,
        };
        match staged {
            Ok(out) => {
                let send_res = send_ws(
                    st,
                    &ClientToRelay::SendMlsCommit {
                        commit_id: commit_id.clone(),
                        expected_epoch: out.expected_epoch,
                        epoch: out.new_epoch,
                        commit_b64: STANDARD.encode(&out.commit_bytes),
                        removed_participant_id: Some(participant_id.clone()),
                    },
                );
                if let Err(e) = send_res {
                    if let Some(mls) = st.mls.as_mut() {
                        mls.clear_pending_commit();
                    }
                    st.queued_removals.push_front((participant_id, reason));
                    post_to_ui(
                        &st.scope,
                        &WorkerToUi::Error {
                            code: "mls_remove_send_failed".into(),
                            message: e,
                        },
                    );
                } else {
                    st.pending_admin_commit = Some(PendingAdminCommit {
                        commit_id,
                        prev_epoch: out.expected_epoch,
                        new_epoch: out.new_epoch,
                        kind: AdminCommitKind::Remove { participant_id },
                    });
                }
            }
            Err(e) => {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "mls_remove_failed".into(),
                        message: e.to_string(),
                    },
                );
            }
        }
        return;
    }

    if let Some((reservation_id, guest_id, key_package_b64)) = st.queued_join_requests.pop_front() {
        let Ok(kp_bytes) = STANDARD.decode(&key_package_b64) else {
            return;
        };
        let Ok(commit_id) = random_token_b64url(12) else {
            return;
        };
        let staged = match st.mls.as_mut() {
            Some(mls) => mls.stage_add_member(&kp_bytes),
            None => return,
        };
        match staged {
            Ok(out) => {
                let send_res = send_ws(
                    st,
                    &ClientToRelay::CompleteJoin {
                        reservation_id,
                        guest_id: guest_id.clone(),
                        commit_id: commit_id.clone(),
                        expected_epoch: out.expected_epoch,
                        commit_b64: STANDARD.encode(&out.commit_bytes),
                        welcome_b64: STANDARD.encode(&out.welcome_bytes),
                        new_epoch: out.new_epoch,
                    },
                );
                if let Err(e) = send_res {
                    if let Some(mls) = st.mls.as_mut() {
                        mls.clear_pending_commit();
                    }
                    post_to_ui(
                        &st.scope,
                        &WorkerToUi::Error {
                            code: "mls_add_send_failed".into(),
                            message: e,
                        },
                    );
                } else {
                    st.pending_admin_commit = Some(PendingAdminCommit {
                        commit_id,
                        prev_epoch: out.expected_epoch,
                        new_epoch: out.new_epoch,
                        kind: AdminCommitKind::Add { guest_id },
                    });
                    emit_state(st);
                }
            }
            Err(e) => {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "mls_add_failed".into(),
                        message: e.to_string(),
                    },
                );
            }
        }
    }
}

fn apply_missed_commits(
    mls: &mut MlsSession,
    missed_commits: &[MissedCommit],
    expected_final_epoch: u64,
) -> Result<Option<String>, String> {
    let mut last_commit_id = None;
    for mc in missed_commits {
        let local = mls.current_epoch();
        if mc.prev_epoch != local || mc.epoch != local.saturating_add(1) {
            return Err(format!(
                "Out-of-order missed commit {} ({}->{}) at local epoch {local}",
                mc.commit_id, mc.prev_epoch, mc.epoch
            ));
        }
        let bytes = STANDARD
            .decode(&mc.commit_b64)
            .map_err(|_| "Invalid base64 in missed commit".to_string())?;
        match mls.process_incoming(&bytes) {
            Ok(MlsIncomingEvent::EpochAdvanced { new_epoch }) if new_epoch == mc.epoch => {
                last_commit_id = Some(mc.commit_id.clone());
            }
            Ok(_) => {
                return Err("Missed commit did not advance MLS epoch as declared".into());
            }
            Err(e) => {
                return Err(format!("Failed to verify/apply missed MLS commit: {e}"));
            }
        }
    }
    if mls.current_epoch() != expected_final_epoch {
        return Err(format!(
            "Local MLS epoch {} does not match relay epoch {expected_final_epoch}",
            mls.current_epoch()
        ));
    }
    Ok(last_commit_id)
}

fn handle_relay_message(state: &Rc<RefCell<WorkerState>>, msg: RelayToClient) {
    match msg {
        RelayToClient::RoomCreated {
            room_id,
            room_name,
            participant_id,
            resume_token,
            room_created_at_ms,
            room_expires_at_ms,
            policy,
            invite_ttl_secs,
            room_code_ttl_secs,
            keepalive_interval_secs,
        } => {
            let mut st = state.borrow_mut();
            st.room_id = Some(room_id.clone());
            st.room_name = room_name;
            st.participant_id = Some(participant_id.clone());
            st.resume_token = Some(resume_token);
            st.room_created_at_ms = room_created_at_ms;
            st.room_expires_at_ms = room_expires_at_ms;
            st.policy = policy;
            st.invite_ttl_secs = invite_ttl_secs;
            if room_code_ttl_secs > 0 {
                st.room_code_ttl_secs = room_code_ttl_secs;
            }
            st.keepalive_interval_secs = keepalive_interval_secs;
            st.relay_epoch = 0;
            st.members = vec![MemberSummary {
                participant_id: participant_id.clone(),
                role: ParticipantRole::Admin,
                connected: true,
            }];

            let Some(admin_key) = st.admin_signing_key.as_mut() else {
                return;
            };
            admin_key.rebind_room(&room_id);
            let verifier = AdminCommandVerifier::new(&room_id, admin_key.verifying_key_bytes());
            let init_policy_cmd = admin_key.sign_command(
                0,
                AdminCommandPayload::SetPolicy {
                    msg_ttl_secs: policy.msg_ttl_secs,
                    room_ttl_secs: policy.room_ttl_secs,
                },
            );
            let mls_res =
                MlsSession::new_admin(&room_id, &participant_id, admin_key).and_then(|mut m| {
                    m.create_group()?;
                    Ok(m)
                });

            match (verifier, init_policy_cmd, mls_res) {
                (Ok(v), Ok(cmd), Ok(mls)) => {
                    st.admin_verifier = Some(v);
                    st.mls = Some(mls);
                    st.phase = Phase::Active;
                    st.verified_visibility_token = Some(st.visibility_token);
                    st.status_text = "Room active (MLS Epoch 0)".into();
                    let _ = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd: cmd });
                    emit_state(&st);
                    post_to_ui(
                        &st.scope,
                        &WorkerToUi::VisibilityVerified {
                            visibility_token: st.visibility_token,
                        },
                    );
                    render_full_if_verified(&mut st);
                }
                _ => {
                    wipe_session_state(
                        &mut st,
                        Phase::Ended,
                        "MLS room initialization failed.",
                        true,
                    );
                }
            }
        }
        RelayToClient::InviteRegistered {
            token_hash_hex,
            expires_at_ms,
        } => {
            let mut st = state.borrow_mut();
            let capped_exp = if st.room_expires_at_ms > 0 {
                expires_at_ms.min(st.room_expires_at_ms)
            } else {
                expires_at_ms
            };
            if let Some(inv) = st.pending_invites.remove(&token_hash_hex)
                && let (Some(room_id), Some(key)) =
                    (st.room_id.clone(), st.admin_signing_key.as_ref())
            {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::InviteReady {
                        room_id,
                        invite_token: inv.token.clone(),
                        admin_fingerprint: key.fingerprint(),
                        expires_at_ms: capped_exp,
                    },
                );
                // `inv` drops here and zeroizes `inv.token`.
            }
        }
        RelayToClient::RoomCodeUpdated {
            secret_hash_hex,
            expires_at_ms,
        } => {
            let mut st = state.borrow_mut();
            let capped_exp = if st.room_expires_at_ms > 0 {
                expires_at_ms.min(st.room_expires_at_ms)
            } else {
                expires_at_ms
            };
            if let Some(code) = st.pending_room_codes.remove(&secret_hash_hex) {
                st.active_room_code = Some((code, capped_exp));
                st.pending_room_codes.clear();
                emit_room_code_state(&mut st);
            }
        }
        RelayToClient::RoomCodeRevoked => {
            let mut st = state.borrow_mut();
            st.active_room_code = None;
            st.pending_room_codes.clear();
            post_to_ui(
                &st.scope,
                &WorkerToUi::RoomCodeState {
                    active: false,
                    room_code: None,
                    expires_at_ms: 0,
                },
            );
        }
        RelayToClient::JoinPending { reason, .. } => {
            let mut st = state.borrow_mut();
            let scope = st.scope.clone();
            clear_timer(&scope, &mut st.handshake_timer_id);
            st.phase = Phase::PendingJoin;
            st.status_text = format!("Join pending: {reason}");
            emit_state(&st);
        }
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => {
            let mut st = state.borrow_mut();
            if st.role != Some(ParticipantRole::Admin) || st.phase != Phase::Active {
                return;
            }
            st.queued_join_requests
                .push_back((reservation_id, guest_id, key_package_b64));
            process_next_admin_task(&mut st);
        }
        RelayToClient::CommitAccepted {
            commit_id,
            prev_epoch,
            new_epoch,
            members,
            messaging_paused,
        } => {
            let mut st = state.borrow_mut();
            let Some(pending) = st.pending_admin_commit.take() else {
                wipe_session_state(
                    &mut st,
                    Phase::Ended,
                    "Unexpected CommitAccepted without pending commit.",
                    true,
                );
                return;
            };
            if pending.commit_id != commit_id
                || pending.prev_epoch != prev_epoch
                || pending.new_epoch != new_epoch
                || st.local_epoch() != prev_epoch
            {
                wipe_session_state(
                    &mut st,
                    Phase::Ended,
                    "MLS commit confirmation mismatch — session terminated.",
                    true,
                );
                return;
            }
            let apply_res = match st.mls.as_mut() {
                Some(mls) => mls.apply_pending_commit(),
                None => return,
            };
            match apply_res {
                Ok((applied_epoch, added_mls_id)) if applied_epoch == new_epoch => {
                    match pending.kind {
                        AdminCommitKind::Add { guest_id } => {
                            if let Some(mls_pid) = added_mls_id {
                                st.relay_to_mls_id.insert(guest_id, mls_pid);
                            }
                            st.status_text = format!("Guest admitted (MLS Epoch {new_epoch})");
                        }
                        AdminCommitKind::Remove { participant_id } => {
                            st.relay_to_mls_id.remove(&participant_id);
                            st.status_text = if messaging_paused {
                                format!("Waiting for member acks on MLS Epoch {new_epoch}...")
                            } else {
                                format!("Member removed (MLS Epoch {new_epoch})")
                            };
                        }
                    }
                    st.relay_epoch = new_epoch;
                    st.members = members;
                    st.messaging_paused = messaging_paused;
                    let _ = send_ws(
                        &st,
                        &ClientToRelay::AckCommit {
                            commit_id,
                            epoch: new_epoch,
                        },
                    );
                    emit_state(&st);
                    process_next_admin_task(&mut st);
                }
                _ => {
                    wipe_session_state(
                        &mut st,
                        Phase::Ended,
                        "Failed to apply confirmed MLS commit — session terminated.",
                        true,
                    );
                }
            }
        }
        RelayToClient::JoinAccepted {
            room_id,
            room_name,
            participant_id,
            resume_token,
            commit_id,
            welcome_epoch,
            epoch,
            missed_commits,
            welcome_b64,
            admin_pubkey_b64,
            latest_policy_cmd,
            room_created_at_ms,
            room_expires_at_ms,
            members,
            messaging_paused,
            keepalive_interval_secs,
        } => {
            // Section 4 & 5: Guest MUST cryptographically verify:
            // 1. Admin pubkey matches invite fingerprint.
            // 2. MLS Welcome binds actual MLS admin signature key to invite-anchored AdminSigningKey.
            // 3. Any missed commits apply in order to reach `epoch`.
            // 4. Signed room rules are valid historical snapshot for `<= epoch`.
            let mut st = state.borrow_mut();
            let scope = st.scope.clone();
            clear_timer(&scope, &mut st.handshake_timer_id);
            clear_timer(&scope, &mut st.reconnect_timer_id);

            let expected_fp = match st.expected_admin_fingerprint.clone() {
                Some(fp) => fp,
                None => return,
            };
            let admin_pk = match decode_pubkey_b64(&admin_pubkey_b64) {
                Ok(pk) => pk,
                Err(_) => {
                    wipe_session_state(
                        &mut st,
                        Phase::Ended,
                        "Security error: invalid admin public key.",
                        true,
                    );
                    return;
                }
            };
            let computed_fp = compute_admin_fingerprint(&admin_pk, &room_id);
            if computed_fp != expected_fp {
                wipe_session_state(
                    &mut st,
                    Phase::Ended,
                    "Security error: admin fingerprint does not match invite link!",
                    true,
                );
                return;
            }
            let mut verifier = match AdminCommandVerifier::new(&room_id, admin_pk) {
                Ok(v) => v,
                Err(_) => {
                    wipe_session_state(&mut st, Phase::Ended, "Admin verification failed.", true);
                    return;
                }
            };

            let Ok(welcome_bytes) = STANDARD.decode(&welcome_b64) else {
                wipe_session_state(&mut st, Phase::Ended, "Invalid MLS Welcome message.", true);
                return;
            };
            let Some(mls) = st.mls.as_mut() else {
                return;
            };
            let joined_epoch = match mls.join_from_welcome(&welcome_bytes, &admin_pk, &expected_fp)
            {
                Ok(ep) => ep,
                Err(e) => {
                    wipe_session_state(
                        &mut st,
                        Phase::Ended,
                        &format!("MLS join rejected: {e}"),
                        true,
                    );
                    return;
                }
            };
            if joined_epoch != welcome_epoch {
                wipe_session_state(&mut st, Phase::Ended, "MLS Welcome epoch mismatch.", true);
                return;
            }
            let ack_commit_id = match apply_missed_commits(mls, &missed_commits, epoch) {
                Ok(Some(cid)) => cid,
                Ok(None) => commit_id,
                Err(e) => {
                    wipe_session_state(&mut st, Phase::Ended, &e, true);
                    return;
                }
            };

            let verified_policy =
                match verifier.verify_historical_policy_snapshot(&latest_policy_cmd, epoch) {
                    Ok(p) => p,
                    Err(_) => {
                        wipe_session_state(
                            &mut st,
                            Phase::Ended,
                            "Security error: invalid room policy signature or epoch!",
                            true,
                        );
                        return;
                    }
                };
            let computed_expires = verified_policy.compute_room_expires_at_ms(room_created_at_ms);
            let effective_expires = room_expires_at_ms.min(computed_expires);
            if now_ms() >= effective_expires {
                wipe_session_state(&mut st, Phase::Ended, "Room has already expired.", true);
                return;
            }

            st.pending_join = None;
            st.reconnect_attempts = 0;
            st.admin_verifier = Some(verifier);
            st.room_name = room_name;
            st.participant_id = Some(participant_id);
            st.resume_token = Some(resume_token);
            st.policy = verified_policy;
            st.room_created_at_ms = room_created_at_ms;
            st.room_expires_at_ms = effective_expires;
            st.relay_epoch = epoch;
            st.members = members;
            st.messaging_paused = messaging_paused;
            st.keepalive_interval_secs = keepalive_interval_secs;
            st.phase = Phase::Active;
            st.status_text =
                format!("Connected — admin identity & MLS key verified (Epoch {epoch})");
            let _ = send_ws(
                &st,
                &ClientToRelay::AckCommit {
                    commit_id: ack_commit_id,
                    epoch,
                },
            );
            if st.ui_visible {
                st.verified_visibility_token = Some(st.visibility_token);
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::VisibilityVerified {
                        visibility_token: st.visibility_token,
                    },
                );
            }
            emit_state(&st);
            render_full_if_verified(&mut st);
        }
        RelayToClient::SessionResumed {
            room_name,
            resume_token,
            epoch,
            missed_commits,
            room_created_at_ms,
            room_expires_at_ms,
            latest_policy_cmd,
            members,
            messaging_paused,
            keepalive_interval_secs,
            room_code_secret_hash_hex,
            room_code_expires_at_ms,
            ..
        } => {
            let mut st = state.borrow_mut();
            let scope = st.scope.clone();
            clear_timer(&scope, &mut st.handshake_timer_id);
            clear_timer(&scope, &mut st.reconnect_timer_id);

            let now = now_ms();
            if now >= room_expires_at_ms {
                wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
                return;
            }

            // Apply all missed MLS commits in strict order and verify we reached `epoch`!
            let ack_commit_id = match st.mls.as_mut() {
                Some(mls) => match apply_missed_commits(mls, &missed_commits, epoch) {
                    Ok(cid) => cid,
                    Err(e) => {
                        wipe_session_state(&mut st, Phase::Ended, &e, true);
                        return;
                    }
                },
                None => {
                    wipe_session_state(&mut st, Phase::Ended, "MLS session unavailable.", true);
                    return;
                }
            };

            // Validate historical policy snapshot if provided.
            if let Some(cmd) = latest_policy_cmd {
                let Some(verifier) = st.admin_verifier.as_mut() else {
                    wipe_session_state(&mut st, Phase::Ended, "Missing admin verifier.", true);
                    return;
                };
                match verifier.verify_historical_policy_snapshot(&cmd, epoch) {
                    Ok(new_pol) => {
                        let exp = new_pol
                            .compute_room_expires_at_ms(room_created_at_ms)
                            .min(room_expires_at_ms);
                        if now >= exp {
                            wipe_session_state(
                                &mut st,
                                Phase::Ended,
                                "Room lifetime expired.",
                                true,
                            );
                            return;
                        }
                        st.policy = new_pol;
                        st.room_expires_at_ms = exp;
                        st.history
                            .apply_policy_change(new_pol.msg_ttl_secs, exp, now);
                    }
                    Err(e) => {
                        wipe_session_state(
                            &mut st,
                            Phase::Ended,
                            &format!("Invalid room policy on resume: {e}"),
                            true,
                        );
                        return;
                    }
                }
            } else {
                st.room_expires_at_ms = room_expires_at_ms;
            }

            st.room_name = room_name;
            if st.role == Some(ParticipantRole::Admin) {
                let room_exp = st.room_expires_at_ms;
                let WorkerState {
                    active_room_code,
                    pending_room_codes,
                    ..
                } = &mut *st;
                reconcile_room_code_on_resume(
                    active_room_code,
                    pending_room_codes,
                    room_code_secret_hash_hex.as_deref(),
                    room_code_expires_at_ms,
                    room_exp,
                    now,
                );
            }
            st.resume_token = Some(resume_token);
            st.reconnect_attempts = 0;
            st.reconnect_deadline_ms = None;
            st.resume_attempt_id = None;
            st.relay_epoch = epoch;
            st.members = members;
            st.messaging_paused = messaging_paused;
            st.keepalive_interval_secs = keepalive_interval_secs;
            st.phase = Phase::Active;
            st.status_text = format!("Session resumed (MLS Epoch {epoch})");

            // Confirm receipt of rotated resume token and any applied commits!
            let _ = send_ws(&st, &ClientToRelay::AckResume);
            if let Some(cid) = ack_commit_id {
                let _ = send_ws(
                    &st,
                    &ClientToRelay::AckCommit {
                        commit_id: cid,
                        epoch,
                    },
                );
            }

            if st.ui_visible {
                st.verified_visibility_token = Some(st.visibility_token);
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::VisibilityVerified {
                        visibility_token: st.visibility_token,
                    },
                );
            }
            emit_state(&st);
            render_full_if_verified(&mut st);
            process_next_admin_task(&mut st);
        }
        RelayToClient::SessionVerified {
            check_id,
            epoch,
            room_expires_at_ms,
            members,
            messaging_paused,
        } => {
            let mut st = state.borrow_mut();
            // An earlier foreground check may complete after another visibility transition.
            // Only the matching response may cancel the current check's timeout.
            if !st.ui_visible
                || !st
                    .pending_visibility_check
                    .as_ref()
                    .is_some_and(|(token, id)| *token == st.visibility_token && *id == check_id)
            {
                return;
            }
            let scope = st.scope.clone();
            clear_timer(&scope, &mut st.verify_timer_id);
            let now = now_ms();
            if now >= room_expires_at_ms {
                wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
                return;
            }
            if st.phase != Phase::Active || st.local_epoch() != epoch {
                wipe_session_state(
                    &mut st,
                    Phase::Ended,
                    "Session verification failed: MLS epoch mismatch.",
                    true,
                );
                return;
            }
            if let Some((req_tok, req_id)) = st.pending_visibility_check.take()
                && req_tok == st.visibility_token
                && req_id == check_id
                && st.ui_visible
            {
                st.room_expires_at_ms = st.room_expires_at_ms.min(room_expires_at_ms);
                st.relay_epoch = epoch;
                st.members = members;
                st.messaging_paused = messaging_paused;
                st.verified_visibility_token = Some(req_tok);
                emit_state(&st);
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::VisibilityVerified {
                        visibility_token: req_tok,
                    },
                );
                render_full_if_verified(&mut st);
            }
        }
        RelayToClient::MlsCommit {
            commit_id,
            prev_epoch,
            epoch,
            commit_b64,
            members,
            messaging_paused,
            ..
        } => {
            // Verify and apply the MLS commit FIRST before adopting members or pause state!
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active {
                return;
            }
            if prev_epoch != st.local_epoch() || epoch != prev_epoch.saturating_add(1) {
                wipe_session_state(
                    &mut st,
                    Phase::Ended,
                    "MLS epoch desynchronized — session terminated.",
                    true,
                );
                return;
            }
            let Ok(bytes) = STANDARD.decode(&commit_b64) else {
                wipe_session_state(
                    &mut st,
                    Phase::Ended,
                    "Corrupted MLS commit — session terminated.",
                    true,
                );
                return;
            };
            let Some(mls) = st.mls.as_mut() else {
                return;
            };
            match mls.process_incoming(&bytes) {
                Ok(MlsIncomingEvent::EpochAdvanced { new_epoch }) if new_epoch == epoch => {
                    st.relay_epoch = new_epoch;
                    st.members = members;
                    st.messaging_paused = messaging_paused;
                    st.status_text = format!("MLS epoch updated (Epoch {new_epoch})");
                    let _ = send_ws(
                        &st,
                        &ClientToRelay::AckCommit {
                            commit_id,
                            epoch: new_epoch,
                        },
                    );
                    emit_state(&st);
                }
                Ok(_) => {
                    wipe_session_state(
                        &mut st,
                        Phase::Ended,
                        "Invalid MLS commit epoch — session terminated.",
                        true,
                    );
                }
                Err(e) => {
                    wipe_session_state(
                        &mut st,
                        Phase::Ended,
                        &format!("MLS commit verification failed — session terminated: {e}"),
                        true,
                    );
                }
            }
        }
        RelayToClient::MlsMessage {
            epoch,
            ciphertext_b64,
            ..
        } => {
            let mut st = state.borrow_mut();
            let now = now_ms();
            if st.phase != Phase::Active
                || now >= st.room_expires_at_ms
                || !st.is_epoch_synced()
                || epoch != st.local_epoch()
            {
                return;
            }
            let Ok(bytes) = STANDARD.decode(&ciphertext_b64) else {
                return;
            };
            let Some(mls) = st.mls.as_mut() else {
                return;
            };
            if let Ok(MlsIncomingEvent::ChatMessage {
                sender_id,
                is_admin,
                payload,
            }) = mls.process_incoming(&bytes)
            {
                let ttl = st.policy.msg_ttl_secs;
                let room_exp = st.room_expires_at_ms;
                if let Ok(outcome) = st.history.insert(
                    payload.message_id.clone(),
                    sender_id,
                    is_admin,
                    false,
                    &payload.text,
                    payload.sent_at_ms,
                    now,
                    ttl,
                    room_exp,
                ) {
                    emit_incremental_insert(&st, outcome);
                    schedule_next_expiry_timer(&mut st);
                }
            }
        }
        RelayToClient::PolicyUpdated {
            signed_cmd,
            room_expires_at_ms,
        } => {
            let mut st = state.borrow_mut();
            let now = now_ms();
            if st.phase != Phase::Active {
                return;
            }
            if st.room_expires_at_ms > 0 && now >= st.room_expires_at_ms {
                wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
                return;
            }
            let local_epoch = st.local_epoch();
            let Some(verifier) = st.admin_verifier.as_mut() else {
                return;
            };
            if let Err(e) = verifier.check_live(&signed_cmd, local_epoch) {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "invalid_policy_sig".into(),
                        message: format!("Room rule tampering or stale epoch detected: {e}"),
                    },
                );
                return;
            }
            let Some(Ok(new_policy)) = signed_cmd.body.payload.policy() else {
                return;
            };
            if verifier.commit_seq(signed_cmd.body.seq).is_err() {
                return;
            }
            let computed = new_policy.compute_room_expires_at_ms(st.room_created_at_ms);
            let effective_expires = room_expires_at_ms.min(computed);
            st.policy = new_policy;
            st.room_expires_at_ms = effective_expires;
            if let Some((_, code_exp)) = st.active_room_code.as_mut() {
                *code_exp = (*code_exp).min(effective_expires);
            }
            st.history
                .apply_policy_change(new_policy.msg_ttl_secs, effective_expires, now);
            if now >= effective_expires {
                wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
            } else {
                emit_state(&st);
                // Policy change may alter every message's expiry countdown -> full refresh.
                render_full_if_verified(&mut st);
            }
        }
        RelayToClient::MemberStatus {
            members,
            messaging_paused,
            ..
        } => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active {
                return;
            }
            st.members = members;
            st.messaging_paused = messaging_paused;
            if messaging_paused || !st.is_epoch_synced() {
                st.status_text = "Messaging paused — verifying MLS epoch...".into();
            } else {
                let epoch = st.local_epoch();
                st.status_text = format!("Room active (MLS Epoch {epoch})");
            }
            emit_state(&st);
        }
        RelayToClient::MemberRemovalRequired {
            participant_id,
            reason,
        } => {
            let mut st = state.borrow_mut();
            if st.role != Some(ParticipantRole::Admin) || st.phase != Phase::Active {
                return;
            }
            st.messaging_paused = true;
            st.queued_removals.push_back((participant_id, reason));
            process_next_admin_task(&mut st);
        }
        RelayToClient::PanicWipeConfirmed { room_id } => {
            let mut st = state.borrow_mut();
            // Bind confirmation strictly to the current room instance and active wipe wait.
            if st.phase == Phase::WipedLocal && st.wipe_room_id.as_deref() == Some(room_id.as_str())
            {
                wipe_session_state(
                    &mut st,
                    Phase::WipedConfirmed,
                    "Room closure confirmed by relay. Note: this does not certify deletion on remote devices.",
                    true,
                );
            }
        }
        RelayToClient::RoomWiped { reason, .. } => {
            let mut st = state.borrow_mut();
            wipe_session_state(
                &mut st,
                Phase::Ended,
                &format!("Room closed by admin (Panic-Wipe): {reason}"),
                true,
            );
        }
        RelayToClient::RoomClosed { reason, .. } => {
            let mut st = state.borrow_mut();
            wipe_session_state(
                &mut st,
                Phase::Ended,
                &format!("Room closed: {reason}"),
                true,
            );
        }
        RelayToClient::Pong { .. } => {
            // Liveness timestamp already updated in onmessage; pending_ping_sent_at_ms cleared.
        }
        RelayToClient::Error { code, message } => {
            let mut st = state.borrow_mut();
            let fatal = matches!(
                code.as_str(),
                "room_not_found"
                    | "room_expired"
                    | "session_expired"
                    | "resume_expired"
                    | "invalid_resume_token"
                    | "invalid_invite"
                    | "invalid_room_code"
                    | "invite_expired"
                    | "invite_consumed"
                    | "invite_in_use"
                    | "room_full"
                    | "join_timeout"
                    | "epoch_desync"
                    | "stale_connection"
            ) || (code == "rate_limited"
                && matches!(st.phase, Phase::Connecting | Phase::PendingJoin));
            // If an Admin staged commit was rejected (e.g. reservation_expired), clear pending commit cleanly!
            if matches!(
                code.as_str(),
                "reservation_not_found" | "reservation_expired"
            ) && st.pending_admin_commit.is_some()
            {
                st.pending_admin_commit = None;
                if let Some(mls) = st.mls.as_mut() {
                    mls.clear_pending_commit();
                }
                process_next_admin_task(&mut st);
            }
            post_to_ui(
                &st.scope,
                &WorkerToUi::Error {
                    code: code.clone(),
                    message: message.clone(),
                },
            );
            if fatal {
                wipe_session_state(&mut st, Phase::Ended, &message, true);
            }
        }
    }
}
