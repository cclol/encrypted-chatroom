use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use core_crypto::admin::{
    AdminCommandPayload, AdminCommandVerifier, AdminSigningKey, compute_admin_fingerprint,
    decode_pubkey_b64,
};
use core_crypto::ephemeral_store::{EphemeralHistoryStore, VisibleMessage};
use core_crypto::mls::{MlsIncomingEvent, MlsSelftestReport, MlsSession, run_mls_selftest};
use core_crypto::policy::RoomPolicy;
use core_crypto::protocol::{
    ChatAppPayload, ClientToRelay, MemberSummary, ParticipantRole, RelayToClient,
};
use core_crypto::{random_token_b64url, sha256_hex};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent, WebSocket};
use zeroize::Zeroize;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UiToWorker {
    RunMlsSelftest,
    CreateRoom {
        relay_url: String,
        msg_ttl_secs: u64,
        room_ttl_secs: u64,
    },
    JoinRoom {
        relay_url: String,
        room_id: String,
        invite_token: String,
        admin_fingerprint: String,
    },
    GenerateInvite,
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
    UiVisible,
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
    RenderHistory {
        messages: Vec<VisibleMessage>,
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
        }
    }
}

enum PendingConnectAction {
    Create {
        policy: RoomPolicy,
    },
    Join {
        room_id: String,
        invite_token: String,
        client_join_nonce: String,
        key_package_b64: String,
    },
    Resume,
}

struct PendingInvite {
    token: String,
}

struct WorkerState {
    scope: DedicatedWorkerGlobalScope,
    phase: Phase,
    ui_visible: bool,
    relay_url: Option<String>,
    ws: Option<WebSocket>,
    ws_generation: u64,
    pending_action: Option<PendingConnectAction>,

    room_id: Option<String>,
    participant_id: Option<String>,
    role: Option<ParticipantRole>,
    resume_token: Option<String>,
    expected_admin_fingerprint: Option<String>,

    admin_signing_key: Option<AdminSigningKey>,
    admin_verifier: Option<AdminCommandVerifier>,
    mls: Option<MlsSession>,
    relay_to_mls_id: HashMap<String, String>,

    policy: RoomPolicy,
    room_created_at_ms: u64,
    room_expires_at_ms: u64,
    invite_ttl_secs: u64,
    keepalive_interval_secs: u64,
    members: Vec<MemberSummary>,
    messaging_paused: bool,
    status_text: String,

    pending_invites: HashMap<String, PendingInvite>,
    history: EphemeralHistoryStore,
    reconnect_attempts: u32,
    expiry_timer_id: Option<i32>,
    keepalive_timer_id: Option<i32>,
    reconnect_timer_id: Option<i32>,
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
        relay_url: None,
        ws: None,
        ws_generation: 0,
        pending_action: None,
        room_id: None,
        participant_id: None,
        role: None,
        resume_token: None,
        expected_admin_fingerprint: None,
        admin_signing_key: None,
        admin_verifier: None,
        mls: None,
        relay_to_mls_id: HashMap::new(),
        policy: RoomPolicy::default(),
        room_created_at_ms: 0,
        room_expires_at_ms: 0,
        invite_ttl_secs: 300,
        keepalive_interval_secs: 20,
        members: Vec::new(),
        messaging_paused: false,
        status_text: "Ready".into(),
        pending_invites: HashMap::new(),
        history: EphemeralHistoryStore::default(),
        reconnect_attempts: 0,
        expiry_timer_id: None,
        keepalive_timer_id: None,
        reconnect_timer_id: None,
    }));

    let state_for_msg = Rc::clone(&state);
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
        if let Some(text) = ev.data().as_string() {
            match serde_json::from_str::<UiToWorker>(&text) {
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
    onmessage.forget();

    post_to_ui(&scope, &WorkerToUi::WorkerReady);
}

fn post_to_ui(scope: &DedicatedWorkerGlobalScope, msg: &WorkerToUi) {
    if let Ok(json) = serde_json::to_string(msg) {
        let _ = scope.post_message(&JsValue::from_str(&json));
    }
}

fn emit_state(st: &WorkerState) {
    let admin_fingerprint = st
        .admin_signing_key
        .as_ref()
        .map(|k| k.fingerprint())
        .or_else(|| st.expected_admin_fingerprint.clone());
    let epoch = st.mls.as_ref().map(|m| m.current_epoch()).unwrap_or(0);
    post_to_ui(
        &st.scope,
        &WorkerToUi::StateUpdate {
            phase: st.phase.as_str().into(),
            room_id: st.room_id.clone(),
            participant_id: st.participant_id.clone(),
            role: st.role,
            epoch,
            policy: st.policy,
            room_created_at_ms: st.room_created_at_ms,
            room_expires_at_ms: st.room_expires_at_ms,
            members: st.members.clone(),
            messaging_paused: st.messaging_paused,
            status_text: st.status_text.clone(),
            admin_fingerprint,
        },
    );
}

fn send_ws(st: &WorkerState, msg: &ClientToRelay) -> Result<(), String> {
    let ws = st
        .ws
        .as_ref()
        .ok_or_else(|| "No active WebSocket connection".to_string())?;
    if ws.ready_state() != WebSocket::OPEN {
        return Err("WebSocket is not connected".to_string());
    }
    let json = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    ws.send_with_str(&json)
        .map_err(|_| "Failed to send over WebSocket".to_string())
}

fn clear_timers(st: &mut WorkerState) {
    if let Some(id) = st.expiry_timer_id.take() {
        st.scope.clear_timeout_with_handle(id);
    }
    if let Some(id) = st.keepalive_timer_id.take() {
        st.scope.clear_timeout_with_handle(id);
    }
    if let Some(id) = st.reconnect_timer_id.take() {
        st.scope.clear_timeout_with_handle(id);
    }
}

fn wipe_session_state(st: &mut WorkerState, new_phase: Phase, status: &str, close_ws: bool) {
    clear_timers(st);
    st.history.wipe_all();
    if let Some(mut mls) = st.mls.take() {
        mls.wipe();
    }
    st.relay_to_mls_id.clear();
    if let Some(mut tok) = st.resume_token.take() {
        tok.zeroize();
    }
    for (_, mut inv) in st.pending_invites.drain() {
        inv.token.zeroize();
    }
    st.pending_action = None;
    st.admin_verifier = None;
    if close_ws {
        st.admin_signing_key = None;
        st.ws_generation = st.ws_generation.wrapping_add(1);
        if let Some(ws) = st.ws.take() {
            let _ = ws.close();
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
            {
                let mut st = state.borrow_mut();
                wipe_session_state(&mut st, Phase::Connecting, "Connecting to relay...", true);
                st.relay_url = Some(relay_url);
                st.role = Some(ParticipantRole::Admin);
                st.policy = policy;
                st.admin_signing_key = Some(admin_key);
                st.pending_action = Some(PendingConnectAction::Create { policy });
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
            let mls = match MlsSession::new(&room_id, &provisional_id, false, None) {
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
                st.expected_admin_fingerprint = Some(admin_fingerprint.clone());
                st.mls = Some(mls);
                st.pending_action = Some(PendingConnectAction::Join {
                    room_id,
                    invite_token,
                    client_join_nonce,
                    key_package_b64,
                });
                emit_state(&st);
            }
            open_websocket(state);
        }
        UiToWorker::GenerateInvite => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active || st.role != Some(ParticipantRole::Admin) {
                return;
            }
            let Ok(token) = random_token_b64url(24) else {
                return;
            };
            let token_hash_hex = sha256_hex(token.as_bytes());
            let epoch = st.mls.as_ref().map(|m| m.current_epoch()).unwrap_or(0);
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
            if st.messaging_paused {
                text.zeroize();
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::Error {
                        code: "messaging_paused".into(),
                        message: "Messaging paused until membership change completes in the new MLS epoch.".into(),
                    },
                );
                return;
            }
            let trimmed = text.trim().to_string();
            text.zeroize();
            if trimmed.is_empty() {
                return;
            }

            let Ok(message_id) = random_token_b64url(12) else {
                return;
            };
            let payload = ChatAppPayload {
                message_id: message_id.clone(),
                text: trimmed.clone(),
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
            let _ = st.history.insert(
                message_id, self_id, is_admin, true, &trimmed, now, ttl, room_exp,
            );
            drop(st);
            render_if_visible_and_schedule(state);
        }
        UiToWorker::UpdatePolicy {
            msg_ttl_secs,
            room_ttl_secs,
        } => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active || st.role != Some(ParticipantRole::Admin) {
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
            let epoch = st.mls.as_ref().map(|m| m.current_epoch()).unwrap_or(0);
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
            let _ = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd });
        }
        UiToWorker::KickGuest { participant_id } => {
            let mut st = state.borrow_mut();
            if st.phase != Phase::Active || st.role != Some(ParticipantRole::Admin) {
                return;
            }
            let epoch = st.mls.as_ref().map(|m| m.current_epoch()).unwrap_or(0);
            let Some(key) = st.admin_signing_key.as_mut() else {
                return;
            };
            let Ok(signed_cmd) =
                key.sign_command(epoch, AdminCommandPayload::KickGuest { participant_id })
            else {
                return;
            };
            let _ = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd });
        }
        UiToWorker::PanicWipe => {
            // Section 7: Immediately hide & wipe local history, sign PanicWipe for Relay,
            // keep socket open briefly ONLY to receive PanicWipeConfirmed.
            let mut st = state.borrow_mut();
            if st.role != Some(ParticipantRole::Admin) {
                wipe_session_state(&mut st, Phase::Ended, "Local history cleared.", true);
                return;
            }
            let epoch = st.mls.as_ref().map(|m| m.current_epoch()).unwrap_or(0);
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
            // Drop admin signing key right after signing.
            st.admin_signing_key = None;
            if let Some(cmd) = signed_cmd {
                if send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd: cmd }).is_err() {
                    wipe_session_state(
                        &mut st,
                        Phase::WipedLocal,
                        "Cleared locally (relay unreachable — room closure unconfirmed).",
                        true,
                    );
                }
            } else {
                wipe_session_state(&mut st, Phase::WipedLocal, "Cleared locally.", true);
            }
        }
        UiToWorker::LeaveRoom => {
            let mut st = state.borrow_mut();
            let _ = send_ws(&st, &ClientToRelay::LeaveRoom);
            wipe_session_state(&mut st, Phase::Ended, "Left room.", true);
        }
        UiToWorker::UiHidden => {
            // Section 6: Keep encrypted history in worker RAM while tab lives; UI has cleared DOM.
            let mut st = state.borrow_mut();
            st.ui_visible = false;
        }
        UiToWorker::UiVisible => {
            // Section 6: Verify room deadline, status, and membership BEFORE releasing history!
            {
                let mut st = state.borrow_mut();
                st.ui_visible = true;
                let now = now_ms();
                if st.phase == Phase::Active
                    && st.room_expires_at_ms > 0
                    && now >= st.room_expires_at_ms
                {
                    wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
                    return;
                }
            }
            render_if_visible_and_schedule(state);
        }
    }
}

fn open_websocket(state: &Rc<RefCell<WorkerState>>) {
    let (relay_url, generation, scope) = {
        let mut st = state.borrow_mut();
        st.ws_generation = st.ws_generation.wrapping_add(1);
        if let Some(old) = st.ws.take() {
            let _ = old.close();
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
            schedule_reconnect_if_applicable(state);
            return;
        }
    };

    // onopen
    let state_open = Rc::clone(state);
    let onopen = Closure::<dyn FnMut()>::new(move || {
        let mut st = state_open.borrow_mut();
        if st.ws_generation != generation {
            return;
        }
        st.reconnect_attempts = 0;
        let action = st.pending_action.take();
        match action {
            Some(PendingConnectAction::Create { policy }) => {
                if let Some(key) = &st.admin_signing_key {
                    let msg = ClientToRelay::CreateRoom {
                        admin_pubkey_b64: key.verifying_key_b64(),
                        initial_policy: policy,
                    };
                    let _ = send_ws(&st, &msg);
                }
            }
            Some(PendingConnectAction::Join {
                room_id,
                invite_token,
                key_package_b64,
                client_join_nonce,
                ..
            }) => {
                let msg = ClientToRelay::JoinRoom {
                    room_id,
                    invite_token,
                    key_package_b64,
                    client_join_nonce,
                };
                let _ = send_ws(&st, &msg);
            }
            Some(PendingConnectAction::Resume) => {
                if let (Some(room_id), Some(participant_id), Some(resume_token)) = (
                    st.room_id.clone(),
                    st.participant_id.clone(),
                    st.resume_token.clone(),
                ) {
                    let _ = send_ws(
                        &st,
                        &ClientToRelay::ResumeSession {
                            room_id,
                            participant_id,
                            resume_token,
                        },
                    );
                }
            }
            None => {}
        }
        drop(st);
        schedule_keepalive(Rc::clone(&state_open));
    });
    ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
    onopen.forget();

    // onmessage
    let state_msg = Rc::clone(state);
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
        if state_msg.borrow().ws_generation != generation {
            return;
        }
        if let Some(text) = ev.data().as_string()
            && let Ok(parsed) = serde_json::from_str::<RelayToClient>(&text)
        {
            handle_relay_message(&state_msg, parsed);
        }
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    // onclose
    let state_close = Rc::clone(state);
    let onclose = Closure::<dyn FnMut()>::new(move || {
        let should_reconnect = {
            let mut st = state_close.borrow_mut();
            if st.ws_generation != generation {
                return;
            }
            st.ws = None;
            if let Some(id) = st.keepalive_timer_id.take() {
                st.scope.clear_timeout_with_handle(id);
            }
            match st.phase {
                Phase::Active | Phase::Reconnecting => {
                    // Section 6: Keep history hidden while reconnecting within the 60s grace window!
                    st.phase = Phase::Reconnecting;
                    st.status_text =
                        "Connection interrupted — attempting to reconnect (60s window)...".into();
                    post_to_ui(
                        &st.scope,
                        &WorkerToUi::ClearDisplay {
                            reason: "Connection interrupted".into(),
                        },
                    );
                    emit_state(&st);
                    true
                }
                Phase::WipedLocal | Phase::WipedConfirmed | Phase::Ended | Phase::Idle => false,
                Phase::Connecting | Phase::PendingJoin => {
                    wipe_session_state(&mut st, Phase::Ended, "Disconnected from relay.", true);
                    false
                }
            }
        };
        if should_reconnect {
            schedule_reconnect_if_applicable(&state_close);
        }
    });
    ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
    onclose.forget();

    state.borrow_mut().ws = Some(ws);
}

fn handle_relay_message(state: &Rc<RefCell<WorkerState>>, msg: RelayToClient) {
    match msg {
        RelayToClient::RoomCreated {
            room_id,
            participant_id,
            resume_token,
            room_created_at_ms,
            room_expires_at_ms,
            policy,
            invite_ttl_secs,
            keepalive_interval_secs,
        } => {
            {
                let mut st = state.borrow_mut();
                st.room_id = Some(room_id.clone());
                st.participant_id = Some(participant_id.clone());
                st.resume_token = Some(resume_token);
                st.room_created_at_ms = room_created_at_ms;
                st.room_expires_at_ms = room_expires_at_ms;
                st.policy = policy;
                st.invite_ttl_secs = invite_ttl_secs;
                st.keepalive_interval_secs = keepalive_interval_secs;
                st.members = vec![MemberSummary {
                    participant_id: participant_id.clone(),
                    role: ParticipantRole::Admin,
                    connected: true,
                }];

                let Some(admin_key) = st.admin_signing_key.as_mut() else {
                    return;
                };
                admin_key.rebind_room(&room_id);
                let fp = admin_key.fingerprint();
                let verifier = AdminCommandVerifier::new(&room_id, admin_key.verifying_key_bytes());
                let init_policy_cmd = admin_key.sign_command(
                    0,
                    AdminCommandPayload::SetPolicy {
                        msg_ttl_secs: policy.msg_ttl_secs,
                        room_ttl_secs: policy.room_ttl_secs,
                    },
                );

                let mls_res =
                    MlsSession::new(&room_id, &participant_id, true, Some(fp)).and_then(|mut m| {
                        m.create_group()?;
                        Ok(m)
                    });

                match (verifier, init_policy_cmd, mls_res) {
                    (Ok(v), Ok(cmd), Ok(mls)) => {
                        st.admin_verifier = Some(v);
                        st.mls = Some(mls);
                        st.phase = Phase::Active;
                        st.status_text = "Room active (MLS Epoch 0)".into();
                        let _ = send_ws(&st, &ClientToRelay::AdminCommand { signed_cmd: cmd });
                        emit_state(&st);
                    }
                    _ => {
                        wipe_session_state(
                            &mut st,
                            Phase::Ended,
                            "MLS room initialization failed.",
                            true,
                        );
                        return;
                    }
                }
            }
            render_if_visible_and_schedule(state);
        }
        RelayToClient::InviteRegistered {
            token_hash_hex,
            expires_at_ms,
        } => {
            let mut st = state.borrow_mut();
            if let Some(inv) = st.pending_invites.remove(&token_hash_hex)
                && let (Some(room_id), Some(key)) =
                    (st.room_id.clone(), st.admin_signing_key.as_ref())
            {
                post_to_ui(
                    &st.scope,
                    &WorkerToUi::InviteReady {
                        room_id,
                        invite_token: inv.token,
                        admin_fingerprint: key.fingerprint(),
                        expires_at_ms,
                    },
                );
            }
        }
        RelayToClient::JoinPending { reason, .. } => {
            let mut st = state.borrow_mut();
            st.phase = Phase::PendingJoin;
            st.status_text = format!("Join pending: {reason}");
            emit_state(&st);
        }
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => {
            // Section 4: Admin processes GuestJoinRequest automatically without clicking!
            let mut st = state.borrow_mut();
            if st.role != Some(ParticipantRole::Admin) {
                return;
            }
            let Ok(kp_bytes) = STANDARD.decode(&key_package_b64) else {
                return;
            };
            let Some(mls) = st.mls.as_mut() else {
                return;
            };
            match mls.add_member(&kp_bytes) {
                Ok(add_out) => {
                    st.relay_to_mls_id
                        .insert(guest_id.clone(), add_out.added_mls_participant_id);
                    let _ = send_ws(
                        &st,
                        &ClientToRelay::CompleteJoin {
                            reservation_id,
                            guest_id,
                            commit_b64: STANDARD.encode(&add_out.commit_bytes),
                            welcome_b64: STANDARD.encode(&add_out.welcome_bytes),
                            new_epoch: add_out.new_epoch,
                        },
                    );
                    st.status_text = format!("Guest admitted (MLS Epoch {})", add_out.new_epoch);
                    emit_state(&st);
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
        RelayToClient::JoinAccepted {
            room_id,
            participant_id,
            resume_token,
            welcome_b64,
            admin_pubkey_b64,
            latest_policy_cmd,
            room_created_at_ms,
            room_expires_at_ms,
            members,
            keepalive_interval_secs,
        } => {
            // Section 4 & 5: Guest MUST cryptographically verify Admin identity AND signed room rules BEFORE unlocking UI!
            let ok = {
                let mut st = state.borrow_mut();
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
                        wipe_session_state(
                            &mut st,
                            Phase::Ended,
                            "Admin verification failed.",
                            true,
                        );
                        return;
                    }
                };
                if verifier.verify_and_advance(&latest_policy_cmd).is_err() {
                    wipe_session_state(
                        &mut st,
                        Phase::Ended,
                        "Security error: invalid room policy signature!",
                        true,
                    );
                    return;
                }
                let verified_policy = match latest_policy_cmd.body.payload.policy() {
                    Some(Ok(p)) => p,
                    _ => {
                        wipe_session_state(
                            &mut st,
                            Phase::Ended,
                            "Security error: invalid room rules.",
                            true,
                        );
                        return;
                    }
                };
                let computed_expires =
                    verified_policy.compute_room_expires_at_ms(room_created_at_ms);
                let effective_expires = room_expires_at_ms.min(computed_expires);
                if now_ms() >= effective_expires {
                    wipe_session_state(&mut st, Phase::Ended, "Room has already expired.", true);
                    return;
                }

                let Ok(welcome_bytes) = STANDARD.decode(&welcome_b64) else {
                    wipe_session_state(&mut st, Phase::Ended, "Invalid MLS Welcome message.", true);
                    return;
                };
                let join_res = match st.mls.as_mut() {
                    Some(mls) => mls.join_from_welcome(&welcome_bytes, &expected_fp),
                    None => return,
                };
                match join_res {
                    Ok(epoch) => {
                        st.admin_verifier = Some(verifier);
                        st.participant_id = Some(participant_id);
                        st.resume_token = Some(resume_token);
                        st.policy = verified_policy;
                        st.room_created_at_ms = room_created_at_ms;
                        st.room_expires_at_ms = effective_expires;
                        st.members = members;
                        st.keepalive_interval_secs = keepalive_interval_secs;
                        st.phase = Phase::Active;
                        st.status_text = format!(
                            "Connected — admin identity & rules verified (MLS Epoch {epoch})"
                        );
                        emit_state(&st);
                        true
                    }
                    Err(e) => {
                        wipe_session_state(
                            &mut st,
                            Phase::Ended,
                            &format!("MLS join rejected: {e}"),
                            true,
                        );
                        false
                    }
                }
            };
            if ok {
                render_if_visible_and_schedule(state);
            }
        }
        RelayToClient::SessionResumed {
            resume_token,
            room_created_at_ms,
            room_expires_at_ms,
            latest_policy_cmd,
            members,
            messaging_paused,
            keepalive_interval_secs,
            ..
        } => {
            let ok = {
                let mut st = state.borrow_mut();
                let now = now_ms();
                if now >= room_expires_at_ms {
                    wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
                    return;
                }
                if let Some(cmd) = latest_policy_cmd
                    && let Some(verifier) = st.admin_verifier.as_mut()
                    && cmd.body.seq > verifier.last_seq()
                {
                    if verifier.verify_and_advance(&cmd).is_ok()
                        && let Some(Ok(new_pol)) = cmd.body.payload.policy()
                    {
                        let exp = new_pol
                            .compute_room_expires_at_ms(room_created_at_ms)
                            .min(room_expires_at_ms);
                        st.policy = new_pol;
                        st.room_expires_at_ms = exp;
                        st.history
                            .apply_policy_change(new_pol.msg_ttl_secs, exp, now);
                    }
                } else {
                    st.room_expires_at_ms = room_expires_at_ms;
                }
                st.resume_token = Some(resume_token);
                st.members = members;
                st.messaging_paused = messaging_paused;
                st.keepalive_interval_secs = keepalive_interval_secs;
                st.phase = Phase::Active;
                st.status_text = "Session resumed".into();
                emit_state(&st);
                true
            };
            if ok {
                render_if_visible_and_schedule(state);
            }
        }
        RelayToClient::MlsCommit {
            commit_b64,
            members,
            messaging_paused,
            ..
        } => {
            let mut st = state.borrow_mut();
            st.members = members;
            st.messaging_paused = messaging_paused;
            if let (Ok(bytes), Some(mls)) = (STANDARD.decode(&commit_b64), st.mls.as_mut()) {
                match mls.process_incoming(&bytes) {
                    Ok(MlsIncomingEvent::EpochAdvanced { new_epoch }) => {
                        st.status_text = format!("MLS epoch updated (Epoch {new_epoch})");
                    }
                    Err(e) => {
                        post_to_ui(
                            &st.scope,
                            &WorkerToUi::Error {
                                code: "mls_commit_failed".into(),
                                message: e.to_string(),
                            },
                        );
                    }
                    _ => {}
                }
            }
            emit_state(&st);
        }
        RelayToClient::MlsMessage { ciphertext_b64, .. } => {
            let inserted = {
                let mut st = state.borrow_mut();
                let now = now_ms();
                if st.phase != Phase::Active || now >= st.room_expires_at_ms {
                    return;
                }
                let Ok(bytes) = STANDARD.decode(&ciphertext_b64) else {
                    return;
                };
                let Some(mls) = st.mls.as_mut() else {
                    return;
                };
                match mls.process_incoming(&bytes) {
                    Ok(MlsIncomingEvent::ChatMessage {
                        sender_id,
                        is_admin,
                        payload,
                    }) => {
                        let ttl = st.policy.msg_ttl_secs;
                        let room_exp = st.room_expires_at_ms;
                        st.history
                            .insert(
                                payload.message_id,
                                sender_id,
                                is_admin,
                                false,
                                &payload.text,
                                now,
                                ttl,
                                room_exp,
                            )
                            .unwrap_or(false)
                    }
                    _ => false,
                }
            };
            if inserted {
                render_if_visible_and_schedule(state);
            }
        }
        RelayToClient::PolicyUpdated {
            signed_cmd,
            room_expires_at_ms,
        } => {
            let should_refresh = {
                let mut st = state.borrow_mut();
                let now = now_ms();
                let Some(verifier) = st.admin_verifier.as_mut() else {
                    return;
                };
                if let Err(e) = verifier.verify_and_advance(&signed_cmd) {
                    post_to_ui(
                        &st.scope,
                        &WorkerToUi::Error {
                            code: "invalid_policy_sig".into(),
                            message: format!("Room rule tampering detected: {e}"),
                        },
                    );
                    return;
                }
                let Some(Ok(new_policy)) = signed_cmd.body.payload.policy() else {
                    return;
                };
                let computed = new_policy.compute_room_expires_at_ms(st.room_created_at_ms);
                let effective_expires = room_expires_at_ms.min(computed);
                st.policy = new_policy;
                st.room_expires_at_ms = effective_expires;
                st.history
                    .apply_policy_change(new_policy.msg_ttl_secs, effective_expires, now);
                if now >= effective_expires {
                    wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
                    false
                } else {
                    emit_state(&st);
                    true
                }
            };
            if should_refresh {
                render_if_visible_and_schedule(state);
            }
        }
        RelayToClient::MemberStatus {
            members,
            messaging_paused,
            ..
        } => {
            let mut st = state.borrow_mut();
            st.members = members;
            st.messaging_paused = messaging_paused;
            if messaging_paused {
                st.status_text = "Messaging paused — rotating MLS epoch...".into();
            } else if st.phase == Phase::Active {
                let epoch = st.mls.as_ref().map(|m| m.current_epoch()).unwrap_or(0);
                st.status_text = format!("Room active (MLS Epoch {epoch})");
            }
            emit_state(&st);
        }
        RelayToClient::MemberRemovalRequired {
            participant_id,
            reason,
        } => {
            // Section 5: Admin automatically commits MLS Remove for departed/kicked/timed-out guest!
            let mut st = state.borrow_mut();
            if st.role != Some(ParticipantRole::Admin) {
                return;
            }
            st.messaging_paused = true;
            st.status_text = format!("Removing member ({reason}) — rotating MLS keys...");
            emit_state(&st);

            let target_mls_id = st
                .relay_to_mls_id
                .remove(&participant_id)
                .unwrap_or_else(|| participant_id.clone());
            let Some(mls) = st.mls.as_mut() else {
                return;
            };
            match mls.remove_member_by_participant_id(&target_mls_id) {
                Ok((commit_bytes, new_epoch)) => {
                    let _ = send_ws(
                        &st,
                        &ClientToRelay::SendMlsCommit {
                            epoch: new_epoch,
                            commit_b64: STANDARD.encode(&commit_bytes),
                            removed_participant_id: Some(participant_id),
                        },
                    );
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
        }
        RelayToClient::PanicWipeConfirmed { .. } => {
            let mut st = state.borrow_mut();
            wipe_session_state(
                &mut st,
                Phase::WipedConfirmed,
                "Room closure confirmed by relay. Note: this does not certify deletion on remote devices.",
                true,
            );
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
        RelayToClient::Pong { .. } => {}
        RelayToClient::Error { code, message } => {
            let mut st = state.borrow_mut();
            let fatal = matches!(
                code.as_str(),
                "room_not_found"
                    | "room_expired"
                    | "session_expired"
                    | "resume_expired"
                    | "invalid_invite"
                    | "invite_expired"
                    | "invite_consumed"
                    | "invite_in_use"
                    | "room_full"
                    | "join_timeout"
            );
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

/// Checks deadlines, prunes & zeroizes expired entries, renders ONLY when UI is visible & session active,
/// and schedules the next exact expiry wake-up timer (Section 6 & 7).
fn render_if_visible_and_schedule(state: &Rc<RefCell<WorkerState>>) {
    let next_delay_ms = {
        let mut st = state.borrow_mut();
        if let Some(id) = st.expiry_timer_id.take() {
            st.scope.clear_timeout_with_handle(id);
        }
        if st.phase != Phase::Active {
            return;
        }
        let now = now_ms();
        if st.room_expires_at_ms > 0 && now >= st.room_expires_at_ms {
            wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
            return;
        }

        let room_exp = st.room_expires_at_ms;
        st.history.prune_expired(now, room_exp);

        if st.ui_visible
            && let Ok(visible) = st.history.decrypt_visible(now, room_exp)
        {
            post_to_ui(&st.scope, &WorkerToUi::RenderHistory { messages: visible });
        }

        let next_msg_exp = st.history.next_expiry_ms();
        let next_event = match (next_msg_exp, st.room_expires_at_ms) {
            (Some(m), r) if r > 0 => Some(m.min(r)),
            (Some(m), _) => Some(m),
            (None, r) if r > 0 => Some(r),
            _ => None,
        };
        next_event.map(|ts| ts.saturating_sub(now).clamp(100, 60_000) as i32)
    };

    if let Some(delay) = next_delay_ms {
        let state_cb = Rc::clone(state);
        let cb = Closure::once(move || {
            render_if_visible_and_schedule(&state_cb);
        });
        let scope = state.borrow().scope.clone();
        if let Ok(id) = scope.set_timeout_with_callback_and_timeout_and_arguments_0(
            cb.as_ref().unchecked_ref(),
            delay,
        ) {
            state.borrow_mut().expiry_timer_id = Some(id);
        }
        cb.forget();
    }
}

fn schedule_keepalive(state: Rc<RefCell<WorkerState>>) {
    let delay_ms = {
        let mut st = state.borrow_mut();
        if let Some(id) = st.keepalive_timer_id.take() {
            st.scope.clear_timeout_with_handle(id);
        }
        if st.ws.is_none() || !matches!(st.phase, Phase::Active | Phase::PendingJoin) {
            return;
        }
        (st.keepalive_interval_secs.clamp(5, 60) * 1000) as i32
    };

    let state_cb = Rc::clone(&state);
    let cb = Closure::once(move || {
        {
            let st = state_cb.borrow();
            let _ = send_ws(&st, &ClientToRelay::Ping { ts_ms: now_ms() });
        }
        schedule_keepalive(state_cb);
    });
    let scope = state.borrow().scope.clone();
    if let Ok(id) = scope.set_timeout_with_callback_and_timeout_and_arguments_0(
        cb.as_ref().unchecked_ref(),
        delay_ms,
    ) {
        state.borrow_mut().keepalive_timer_id = Some(id);
    }
    cb.forget();
}

fn schedule_reconnect_if_applicable(state: &Rc<RefCell<WorkerState>>) {
    let delay_ms = {
        let mut st = state.borrow_mut();
        if st.phase != Phase::Reconnecting {
            return;
        }
        if st.room_expires_at_ms > 0 && now_ms() >= st.room_expires_at_ms {
            wipe_session_state(&mut st, Phase::Ended, "Room lifetime expired.", true);
            return;
        }
        if st.reconnect_attempts >= 12 {
            wipe_session_state(
                &mut st,
                Phase::Ended,
                "Reconnect window expired. Please request a new invite link.",
                true,
            );
            return;
        }
        st.reconnect_attempts += 1;
        st.pending_action = Some(PendingConnectAction::Resume);
        (1000 * st.reconnect_attempts.min(5)) as i32
    };

    let state_cb = Rc::clone(state);
    let cb = Closure::once(move || {
        if state_cb.borrow().phase == Phase::Reconnecting {
            open_websocket(&state_cb);
        }
    });
    let scope = state.borrow().scope.clone();
    if let Ok(id) = scope.set_timeout_with_callback_and_timeout_and_arguments_0(
        cb.as_ref().unchecked_ref(),
        delay_ms,
    ) {
        state.borrow_mut().reconnect_timer_id = Some(id);
    }
    cb.forget();
}
