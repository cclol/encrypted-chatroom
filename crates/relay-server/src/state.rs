use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use core_crypto::admin::{
    AdminCommandPayload, AdminCommandVerifier, SignedAdminCommand, decode_pubkey_b64,
};
use core_crypto::policy::{MAX_ROOM_MEMBERS, RoomPolicy};
use core_crypto::protocol::{ClientToRelay, MemberSummary, ParticipantRole, RelayToClient};
use core_crypto::{random_token_b64url, sha256_hex};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};

use crate::config::RelayConfig;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Signal pushed to a single WebSocket writer task.
#[derive(Debug, Clone)]
pub enum OutboundSignal {
    Text(String),
    Close,
}

#[derive(Clone)]
pub struct OutboundHandle {
    pub tx: mpsc::Sender<OutboundSignal>,
    pub max_bytes_per_min: usize,
    budget: Arc<std::sync::Mutex<OutboundBudget>>,
}

struct OutboundBudget {
    window_start_ms: u64,
    bytes_sent: usize,
}

impl OutboundHandle {
    pub fn new(tx: mpsc::Sender<OutboundSignal>, max_bytes_per_min: usize) -> Self {
        Self {
            tx,
            max_bytes_per_min,
            budget: Arc::new(std::sync::Mutex::new(OutboundBudget {
                window_start_ms: now_ms(),
                bytes_sent: 0,
            })),
        }
    }

    /// Non-blocking send: if the outbound queue is full or traffic limit is exceeded,
    /// requests immediate socket closure so a slow consumer never blocks other participants.
    pub fn try_send_msg(&self, msg: &RelayToClient) -> bool {
        let Ok(json) = serde_json::to_string(msg) else {
            return false;
        };
        let len = json.len();
        {
            let mut b = self.budget.lock().unwrap_or_else(|e| e.into_inner());
            let now = now_ms();
            if now.saturating_sub(b.window_start_ms) >= 60_000 {
                b.window_start_ms = now;
                b.bytes_sent = 0;
            }
            if b.bytes_sent.saturating_add(len) > self.max_bytes_per_min {
                let _ = self.tx.try_send(OutboundSignal::Close);
                return false;
            }
            b.bytes_sent = b.bytes_sent.saturating_add(len);
        }
        if self.tx.try_send(OutboundSignal::Text(json)).is_err() {
            // Queue saturated or already closed: slow consumer gets closed.
            let _ = self.tx.try_send(OutboundSignal::Close);
            return false;
        }
        true
    }

    pub fn close(&self) {
        let _ = self.tx.try_send(OutboundSignal::Close);
    }
}

/// Tracks which room & participant a given WebSocket connection is bound to.
#[derive(Debug, Clone)]
pub struct ConnBinding {
    pub room_id: String,
    pub participant_id: String,
    pub role: ParticipantRole,
    pub is_pending_reservation: bool,
    pub reservation_token_hash: Option<String>,
}

enum MemberConn {
    Connected {
        conn_id: u64,
        handle: OutboundHandle,
    },
    Disconnected {
        deadline_ms: u64,
    },
}

struct MemberEntry {
    participant_id: String,
    role: ParticipantRole,
    resume_token_hash: String,
    conn: MemberConn,
}

#[derive(Clone)]
struct CachedJoinAccepted {
    guest_id: String,
    resume_token: String,
    welcome_b64: String,
    admin_pubkey_b64: String,
    latest_policy_cmd: SignedAdminCommand,
    room_created_at_ms: u64,
    room_expires_at_ms: u64,
    expires_at_ms: u64,
}

enum InviteState {
    Unused,
    Reserved {
        reservation_id: String,
        guest_id: String,
        client_join_nonce: String,
        key_package_b64: String,
        guest_conn_id: u64,
        guest_handle: OutboundHandle,
        expires_at_ms: u64,
        forwarded_to_admin: bool,
    },
    Consumed {
        guest_id: String,
        client_join_nonce: String,
        /// Short-lived cache allowing idempotent retry if Welcome delivery dropped in flight (Section 4).
        cached_welcome: Option<CachedJoinAccepted>,
    },
}

struct InviteEntry {
    expires_at_ms: u64,
    state: InviteState,
}

struct Room {
    room_id: String,
    admin_id: String,
    admin_pubkey_b64: String,
    admin_verifier: AdminCommandVerifier,
    policy: RoomPolicy,
    latest_policy_cmd: Option<SignedAdminCommand>,
    room_created_at_ms: u64,
    room_expires_at_ms: u64,
    epoch: u64,
    members: HashMap<String, MemberEntry>,
    invites: HashMap<String, InviteEntry>,
    pending_removals: HashSet<String>,
}

impl Room {
    fn messaging_paused(&self) -> bool {
        !self.pending_removals.is_empty()
    }

    fn member_summaries(&self) -> Vec<MemberSummary> {
        let mut out: Vec<MemberSummary> = self
            .members
            .values()
            .map(|m| MemberSummary {
                participant_id: m.participant_id.clone(),
                role: m.role,
                connected: matches!(m.conn, MemberConn::Connected { .. }),
            })
            .collect();
        out.sort_by(|a, b| {
            let role_ord = |r: ParticipantRole| match r {
                ParticipantRole::Admin => 0,
                ParticipantRole::Guest => 1,
            };
            role_ord(a.role)
                .cmp(&role_ord(b.role))
                .then_with(|| a.participant_id.cmp(&b.participant_id))
        });
        out
    }

    fn reserved_slot_count(&self) -> usize {
        self.invites
            .values()
            .filter(|inv| matches!(inv.state, InviteState::Reserved { .. }))
            .count()
    }

    fn total_occupied_slots(&self) -> usize {
        self.members.len() + self.reserved_slot_count()
    }

    fn connected_socket_count(&self) -> usize {
        let member_connected = self
            .members
            .values()
            .filter(|m| matches!(m.conn, MemberConn::Connected { .. }))
            .count();
        let guest_waiting = self.reserved_slot_count();
        member_connected + guest_waiting
    }

    fn all_connected_handles(&self) -> Vec<OutboundHandle> {
        let mut handles = Vec::new();
        for m in self.members.values() {
            if let MemberConn::Connected { handle, .. } = &m.conn {
                handles.push(handle.clone());
            }
        }
        for inv in self.invites.values() {
            if let InviteState::Reserved { guest_handle, .. } = &inv.state {
                handles.push(guest_handle.clone());
            }
        }
        handles
    }

    fn broadcast_members(&self, msg: &RelayToClient, exclude_participant: Option<&str>) {
        for m in self.members.values() {
            if exclude_participant == Some(m.participant_id.as_str()) {
                continue;
            }
            if let MemberConn::Connected { handle, .. } = &m.conn {
                handle.try_send_msg(msg);
            }
        }
    }

    fn send_to_admin(&self, msg: &RelayToClient) -> bool {
        if let Some(admin) = self.members.get(&self.admin_id)
            && let MemberConn::Connected { handle, .. } = &admin.conn
        {
            return handle.try_send_msg(msg);
        }
        false
    }
}

struct IpLimiter {
    active_conns: HashMap<IpAddr, usize>,
    recent_attempts: HashMap<IpAddr, VecDeque<u64>>,
}

impl IpLimiter {
    fn new() -> Self {
        Self {
            active_conns: HashMap::new(),
            recent_attempts: HashMap::new(),
        }
    }

    fn try_acquire(&mut self, ip: IpAddr, cfg: &RelayConfig) -> bool {
        let now = now_ms();
        let attempts = self.recent_attempts.entry(ip).or_default();
        while let Some(&ts) = attempts.front() {
            if now.saturating_sub(ts) >= 60_000 {
                attempts.pop_front();
            } else {
                break;
            }
        }
        if attempts.len() >= cfg.max_connect_rate_per_ip_per_min {
            return false;
        }
        let active = self.active_conns.entry(ip).or_insert(0);
        if *active >= cfg.max_connections_per_ip {
            return false;
        }
        attempts.push_back(now);
        *active += 1;
        true
    }

    fn release(&mut self, ip: IpAddr) {
        if let Some(count) = self.active_conns.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.active_conns.remove(&ip);
            }
        }
    }
}

pub struct RelayState {
    pub config: RelayConfig,
    rooms: Mutex<HashMap<String, Room>>,
    ip_limiter: std::sync::Mutex<IpLimiter>,
    next_conn_id: AtomicU64,
}

impl RelayState {
    pub fn new(config: RelayConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            rooms: Mutex::new(HashMap::new()),
            ip_limiter: std::sync::Mutex::new(IpLimiter::new()),
            next_conn_id: AtomicU64::new(1),
        })
    }

    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn try_acquire_ip(&self, ip: IpAddr) -> bool {
        let mut limiter = self.ip_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.try_acquire(ip, &self.config)
    }

    pub fn release_ip(&self, ip: IpAddr) {
        let mut limiter = self.ip_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.release(ip);
    }

    pub async fn active_room_count(&self) -> usize {
        self.rooms.lock().await.len()
    }

    /// Starts the background timer sweeper that enforces room lifetimes,
    /// invite/reservation timeouts, and 60s participant reconnect windows.
    pub fn spawn_sweeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_millis(state.config.sweep_interval_ms));
            loop {
                interval.tick().await;
                state.sweep_once().await;
            }
        })
    }

    pub async fn sweep_once(&self) {
        let now = now_ms();
        let mut rooms = self.rooms.lock().await;
        let mut rooms_to_close: Vec<(String, String)> = Vec::new();

        for (room_id, room) in rooms.iter_mut() {
            // 1. Hard room lifetime check.
            if now >= room.room_expires_at_ms {
                rooms_to_close.push((room_id.clone(), "Room lifetime expired".into()));
                continue;
            }

            // 2. Expire unused invites & timed-out reservations & expired welcome caches.
            let mut expired_invite_keys = Vec::new();
            for (token_hash, inv) in room.invites.iter_mut() {
                match &mut inv.state {
                    InviteState::Unused => {
                        if now >= inv.expires_at_ms {
                            expired_invite_keys.push(token_hash.clone());
                        }
                    }
                    InviteState::Reserved {
                        guest_handle,
                        expires_at_ms,
                        ..
                    } => {
                        if now >= *expires_at_ms || now >= inv.expires_at_ms {
                            guest_handle.try_send_msg(&RelayToClient::Error {
                                code: "join_timeout".into(),
                                message: "Join reservation expired before admin responded".into(),
                            });
                            guest_handle.close();
                            expired_invite_keys.push(token_hash.clone());
                        }
                    }
                    InviteState::Consumed { cached_welcome, .. } => {
                        if let Some(cw) = cached_welcome
                            && now >= cw.expires_at_ms
                        {
                            *cached_welcome = None;
                        }
                    }
                }
            }
            for key in expired_invite_keys {
                room.invites.remove(&key);
            }

            // 3. Check 60s reconnect grace timeouts.
            let mut timed_out_guests = Vec::new();
            let mut admin_timed_out = false;
            for (pid, member) in &room.members {
                if let MemberConn::Disconnected { deadline_ms } = member.conn
                    && now >= deadline_ms
                {
                    if member.role == ParticipantRole::Admin {
                        admin_timed_out = true;
                    } else {
                        timed_out_guests.push(pid.clone());
                    }
                }
            }

            if admin_timed_out {
                rooms_to_close.push((room_id.clone(), "Admin reconnect window expired".into()));
                continue;
            }

            for guest_id in timed_out_guests {
                room.members.remove(&guest_id);
                room.pending_removals.insert(guest_id.clone());
                let summaries = room.member_summaries();
                let paused = room.messaging_paused();
                room.send_to_admin(&RelayToClient::MemberRemovalRequired {
                    participant_id: guest_id.clone(),
                    reason: "Guest reconnect grace window expired".into(),
                });
                room.broadcast_members(
                    &RelayToClient::MemberStatus {
                        participant_id: guest_id,
                        role: ParticipantRole::Guest,
                        connected: false,
                        members: summaries,
                        messaging_paused: paused,
                    },
                    None,
                );
            }

            // 4. If 0 connected sockets remain after cleanup, terminate room immediately.
            if room.connected_socket_count() == 0 {
                rooms_to_close.push((room_id.clone(), "All participants disconnected".into()));
            }
        }

        for (room_id, reason) in rooms_to_close {
            if let Some(room) = rooms.remove(&room_id) {
                info!(room_id = %room_id, reason = %reason, "closing room");
                let msg = RelayToClient::RoomClosed {
                    room_id: room_id.clone(),
                    reason,
                };
                for handle in room.all_connected_handles() {
                    handle.try_send_msg(&msg);
                    handle.close();
                }
            }
        }
    }

    /// Handles a single incoming protocol message from a WebSocket connection.
    pub async fn handle_message(
        self: &Arc<Self>,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &mut Option<ConnBinding>,
        msg: ClientToRelay,
    ) {
        match msg {
            ClientToRelay::Ping { ts_ms } => {
                handle.try_send_msg(&RelayToClient::Pong { ts_ms });
            }
            ClientToRelay::CreateRoom {
                admin_pubkey_b64,
                initial_policy,
            } => {
                self.handle_create_room(conn_id, handle, binding, admin_pubkey_b64, initial_policy)
                    .await;
            }
            ClientToRelay::JoinRoom {
                room_id,
                invite_token,
                key_package_b64,
                client_join_nonce,
            } => {
                self.handle_join_room(
                    conn_id,
                    handle,
                    binding,
                    room_id,
                    invite_token,
                    key_package_b64,
                    client_join_nonce,
                )
                .await;
            }
            ClientToRelay::ResumeSession {
                room_id,
                participant_id,
                resume_token,
            } => {
                self.handle_resume_session(
                    conn_id,
                    handle,
                    binding,
                    room_id,
                    participant_id,
                    resume_token,
                )
                .await;
            }
            ClientToRelay::CompleteJoin {
                reservation_id,
                guest_id,
                commit_b64,
                welcome_b64,
                new_epoch,
            } => {
                self.handle_complete_join(
                    handle,
                    binding,
                    reservation_id,
                    guest_id,
                    commit_b64,
                    welcome_b64,
                    new_epoch,
                )
                .await;
            }
            ClientToRelay::AdminCommand { signed_cmd } => {
                self.handle_admin_command(handle, binding, signed_cmd).await;
            }
            ClientToRelay::SendMlsMessage {
                epoch,
                message_id,
                ciphertext_b64,
            } => {
                self.handle_send_mls_message(handle, binding, epoch, message_id, ciphertext_b64)
                    .await;
            }
            ClientToRelay::SendMlsCommit {
                epoch,
                commit_b64,
                removed_participant_id,
            } => {
                self.handle_send_mls_commit(
                    handle,
                    binding,
                    epoch,
                    commit_b64,
                    removed_participant_id,
                )
                .await;
            }
            ClientToRelay::LeaveRoom => {
                self.handle_explicit_leave(conn_id, binding).await;
                handle.close();
            }
        }
    }

    async fn handle_create_room(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &mut Option<ConnBinding>,
        admin_pubkey_b64: String,
        initial_policy: RoomPolicy,
    ) {
        if binding.is_some() {
            send_err(
                handle,
                "already_bound",
                "Connection is already bound to a room",
            );
            return;
        }
        if let Err(e) = initial_policy.validate() {
            send_err(handle, "invalid_policy", &e.to_string());
            return;
        }
        let pubkey_bytes = match decode_pubkey_b64(&admin_pubkey_b64) {
            Ok(b) => b,
            Err(e) => {
                send_err(handle, "invalid_key", &e.to_string());
                return;
            }
        };

        let mut rooms = self.rooms.lock().await;
        if rooms.len() >= self.config.max_concurrent_rooms {
            send_err(handle, "capacity_reached", "Relay room capacity reached");
            return;
        }

        let Ok(room_id) = random_token_b64url(16) else {
            send_err(handle, "internal", "RNG failure");
            return;
        };
        let Ok(admin_id) = random_token_b64url(8) else {
            send_err(handle, "internal", "RNG failure");
            return;
        };
        let Ok(resume_token) = random_token_b64url(32) else {
            send_err(handle, "internal", "RNG failure");
            return;
        };

        let verifier = match AdminCommandVerifier::new(&room_id, pubkey_bytes) {
            Ok(v) => v,
            Err(e) => {
                send_err(handle, "invalid_key", &e.to_string());
                return;
            }
        };

        let created_at = now_ms();
        let expires_at = initial_policy.compute_room_expires_at_ms(created_at);

        let mut members = HashMap::new();
        members.insert(
            admin_id.clone(),
            MemberEntry {
                participant_id: admin_id.clone(),
                role: ParticipantRole::Admin,
                resume_token_hash: sha256_hex(resume_token.as_bytes()),
                conn: MemberConn::Connected {
                    conn_id,
                    handle: handle.clone(),
                },
            },
        );

        rooms.insert(
            room_id.clone(),
            Room {
                room_id: room_id.clone(),
                admin_id: admin_id.clone(),
                admin_pubkey_b64,
                admin_verifier: verifier,
                policy: initial_policy,
                latest_policy_cmd: None,
                room_created_at_ms: created_at,
                room_expires_at_ms: expires_at,
                epoch: 0,
                members,
                invites: HashMap::new(),
                pending_removals: HashSet::new(),
            },
        );

        *binding = Some(ConnBinding {
            room_id: room_id.clone(),
            participant_id: admin_id.clone(),
            role: ParticipantRole::Admin,
            is_pending_reservation: false,
            reservation_token_hash: None,
        });

        info!(room_id = %room_id, "room created");
        handle.try_send_msg(&RelayToClient::RoomCreated {
            room_id,
            participant_id: admin_id,
            resume_token,
            room_created_at_ms: created_at,
            room_expires_at_ms: expires_at,
            policy: initial_policy,
            invite_ttl_secs: self.config.invite_ttl_secs,
            keepalive_interval_secs: self.config.keepalive_interval_secs,
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_join_room(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &mut Option<ConnBinding>,
        room_id: String,
        invite_token: String,
        key_package_b64: String,
        client_join_nonce: String,
    ) {
        if binding.is_some() {
            send_err(handle, "already_bound", "Connection is already bound");
            return;
        }
        if invite_token.len() < 16 || client_join_nonce.len() < 8 || key_package_b64.is_empty() {
            send_err(handle, "invalid_join", "Malformed join parameters");
            return;
        }

        let token_hash = sha256_hex(invite_token.as_bytes());
        let now = now_ms();
        let mut rooms = self.rooms.lock().await;

        // Join NEVER creates a room (Section 8).
        let Some(room) = rooms.get_mut(&room_id) else {
            send_err(handle, "room_not_found", "Room does not exist or has ended");
            return;
        };

        if now >= room.room_expires_at_ms {
            send_err(handle, "room_expired", "Room has expired");
            return;
        }

        if room.latest_policy_cmd.is_none() {
            send_err(
                handle,
                "room_not_ready",
                "Room admin has not finished initializing room rules yet",
            );
            return;
        }

        let current_slots = room.total_occupied_slots();
        let members_snapshot = room.member_summaries();

        let Some(invite) = room.invites.get_mut(&token_hash) else {
            send_err(
                handle,
                "invalid_invite",
                "Invite link is invalid or expired",
            );
            return;
        };

        match &mut invite.state {
            InviteState::Unused => {
                if now >= invite.expires_at_ms {
                    room.invites.remove(&token_hash);
                    send_err(handle, "invite_expired", "Invite link has expired");
                    return;
                }
                if current_slots >= MAX_ROOM_MEMBERS {
                    send_err(
                        handle,
                        "room_full",
                        "Room already has the maximum of 4 participants",
                    );
                    return;
                }

                let Ok(reservation_id) = random_token_b64url(12) else {
                    send_err(handle, "internal", "RNG failure");
                    return;
                };
                let Ok(guest_id) = random_token_b64url(8) else {
                    send_err(handle, "internal", "RNG failure");
                    return;
                };
                let res_expiry = now
                    .saturating_add(self.config.join_reservation_ttl_secs.saturating_mul(1000))
                    .min(room.room_expires_at_ms);

                // Atomically transition Unused -> Reserved inside the room mutex.
                invite.state = InviteState::Reserved {
                    reservation_id: reservation_id.clone(),
                    guest_id: guest_id.clone(),
                    client_join_nonce,
                    key_package_b64: key_package_b64.clone(),
                    guest_conn_id: conn_id,
                    guest_handle: handle.clone(),
                    expires_at_ms: res_expiry,
                    forwarded_to_admin: false,
                };

                *binding = Some(ConnBinding {
                    room_id: room_id.clone(),
                    participant_id: guest_id.clone(),
                    role: ParticipantRole::Guest,
                    is_pending_reservation: true,
                    reservation_token_hash: Some(token_hash.clone()),
                });

                let forwarded = room.send_to_admin(&RelayToClient::GuestJoinRequest {
                    reservation_id,
                    guest_id,
                    key_package_b64,
                });

                if let Some(inv_mut) = room.invites.get_mut(&token_hash)
                    && let InviteState::Reserved {
                        forwarded_to_admin, ..
                    } = &mut inv_mut.state
                {
                    *forwarded_to_admin = forwarded;
                }

                let reason = if forwarded {
                    "Admission request sent to room admin".to_string()
                } else {
                    "Room admin is temporarily offline; waiting for admin to return".to_string()
                };
                handle.try_send_msg(&RelayToClient::JoinPending { room_id, reason });
            }
            InviteState::Reserved {
                client_join_nonce: existing_nonce,
                guest_id,
                guest_conn_id,
                guest_handle,
                ..
            } => {
                // Idempotent retry by the exact same pending guest replaces the waiting socket
                // without taking a second slot; any other concurrent joiner is rejected immediately.
                if constant_time_eq_str(existing_nonce, &client_join_nonce) {
                    *guest_conn_id = conn_id;
                    *guest_handle = handle.clone();
                    *binding = Some(ConnBinding {
                        room_id: room_id.clone(),
                        participant_id: guest_id.clone(),
                        role: ParticipantRole::Guest,
                        is_pending_reservation: true,
                        reservation_token_hash: Some(token_hash),
                    });
                    handle.try_send_msg(&RelayToClient::JoinPending {
                        room_id,
                        reason: "Continuing pending admission request".into(),
                    });
                } else {
                    send_err(
                        handle,
                        "invite_in_use",
                        "Invite token is already reserved by another join attempt",
                    );
                }
            }
            InviteState::Consumed {
                guest_id,
                client_join_nonce: existing_nonce,
                cached_welcome,
            } => {
                // Section 4: If admission already succeeded and only the response was lost,
                // retrying with the same token + nonce continues the exact same seat without taking a second slot.
                if constant_time_eq_str(existing_nonce, &client_join_nonce)
                    && let Some(cw) = cached_welcome.clone()
                    && now < cw.expires_at_ms
                {
                    let gid = guest_id.clone();
                    // Rebind the guest's existing member slot to this socket.
                    if let Some(member) = room.members.get_mut(&gid) {
                        member.conn = MemberConn::Connected {
                            conn_id,
                            handle: handle.clone(),
                        };
                    }
                    *binding = Some(ConnBinding {
                        room_id: room_id.clone(),
                        participant_id: gid,
                        role: ParticipantRole::Guest,
                        is_pending_reservation: false,
                        reservation_token_hash: None,
                    });
                    handle.try_send_msg(&RelayToClient::JoinAccepted {
                        room_id,
                        participant_id: cw.guest_id,
                        resume_token: cw.resume_token,
                        welcome_b64: cw.welcome_b64,
                        admin_pubkey_b64: cw.admin_pubkey_b64,
                        latest_policy_cmd: cw.latest_policy_cmd,
                        room_created_at_ms: cw.room_created_at_ms,
                        room_expires_at_ms: cw.room_expires_at_ms,
                        members: members_snapshot,
                        keepalive_interval_secs: self.config.keepalive_interval_secs,
                    });
                } else {
                    send_err(
                        handle,
                        "invite_consumed",
                        "One-time invite token has already been used",
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_complete_join(
        &self,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
        reservation_id: String,
        guest_id: String,
        commit_b64: String,
        welcome_b64: String,
        new_epoch: u64,
    ) {
        let Some(b) = binding else {
            send_err(handle, "unauthorized", "Not bound to a room");
            return;
        };
        if b.role != ParticipantRole::Admin {
            send_err(handle, "forbidden", "Only the room admin can admit guests");
            return;
        }

        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };

        let Some(latest_policy_cmd) = room.latest_policy_cmd.clone() else {
            send_err(handle, "room_not_ready", "Missing signed room policy");
            return;
        };

        // Locate the matching reserved invite.
        let matching_token_hash = room.invites.iter().find_map(|(k, inv)| {
            if let InviteState::Reserved {
                reservation_id: rid,
                guest_id: gid,
                ..
            } = &inv.state
                && rid == &reservation_id
                && gid == &guest_id
            {
                Some(k.clone())
            } else {
                None
            }
        });

        let Some(token_hash) = matching_token_hash else {
            send_err(
                handle,
                "reservation_not_found",
                "Join reservation expired or unknown",
            );
            return;
        };

        let Ok(resume_token) = random_token_b64url(32) else {
            send_err(handle, "internal", "RNG failure");
            return;
        };
        let resume_token_hash = sha256_hex(resume_token.as_bytes());
        let now = now_ms();

        // Extract reservation info and mark invite Consumed.
        let (client_join_nonce, guest_conn_id, guest_handle) = {
            let inv = room.invites.get_mut(&token_hash).unwrap();
            let old_state = std::mem::replace(
                &mut inv.state,
                InviteState::Consumed {
                    guest_id: guest_id.clone(),
                    client_join_nonce: String::new(),
                    cached_welcome: None,
                },
            );
            match old_state {
                InviteState::Reserved {
                    client_join_nonce,
                    guest_conn_id,
                    guest_handle,
                    ..
                } => (client_join_nonce, guest_conn_id, guest_handle),
                _ => unreachable!(),
            }
        };

        room.epoch = new_epoch;
        room.members.insert(
            guest_id.clone(),
            MemberEntry {
                participant_id: guest_id.clone(),
                role: ParticipantRole::Guest,
                resume_token_hash,
                conn: MemberConn::Connected {
                    conn_id: guest_conn_id,
                    handle: guest_handle.clone(),
                },
            },
        );

        let members = room.member_summaries();
        let paused = room.messaging_paused();

        // Store short-lived Welcome cache for idempotent retry if response drops in flight.
        if let Some(inv) = room.invites.get_mut(&token_hash) {
            inv.state = InviteState::Consumed {
                guest_id: guest_id.clone(),
                client_join_nonce,
                cached_welcome: Some(CachedJoinAccepted {
                    guest_id: guest_id.clone(),
                    resume_token: resume_token.clone(),
                    welcome_b64: welcome_b64.clone(),
                    admin_pubkey_b64: room.admin_pubkey_b64.clone(),
                    latest_policy_cmd: latest_policy_cmd.clone(),
                    room_created_at_ms: room.room_created_at_ms,
                    room_expires_at_ms: room.room_expires_at_ms,
                    expires_at_ms: now.saturating_add(30_000).min(room.room_expires_at_ms),
                }),
            };
        }

        // Broadcast MLS Add Commit to all existing members except the newly added guest (who gets Welcome)
        // and the admin (who already applied the pending commit locally).
        let commit_msg = RelayToClient::MlsCommit {
            sender_id: b.participant_id.clone(),
            epoch: new_epoch,
            commit_b64,
            members: members.clone(),
            messaging_paused: paused,
        };
        for m in room.members.values() {
            if m.participant_id == b.participant_id || m.participant_id == guest_id {
                continue;
            }
            if let MemberConn::Connected { handle: mh, .. } = &m.conn {
                mh.try_send_msg(&commit_msg);
            }
        }

        // Notify admin of updated member list.
        room.send_to_admin(&RelayToClient::MemberStatus {
            participant_id: guest_id.clone(),
            role: ParticipantRole::Guest,
            connected: true,
            members: members.clone(),
            messaging_paused: paused,
        });

        // Deliver Welcome + signed room rules to the newly admitted guest.
        guest_handle.try_send_msg(&RelayToClient::JoinAccepted {
            room_id: room.room_id.clone(),
            participant_id: guest_id,
            resume_token,
            welcome_b64,
            admin_pubkey_b64: room.admin_pubkey_b64.clone(),
            latest_policy_cmd,
            room_created_at_ms: room.room_created_at_ms,
            room_expires_at_ms: room.room_expires_at_ms,
            members,
            keepalive_interval_secs: self.config.keepalive_interval_secs,
        });
    }

    async fn handle_resume_session(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &mut Option<ConnBinding>,
        room_id: String,
        participant_id: String,
        resume_token: String,
    ) {
        if binding.is_some() {
            send_err(handle, "already_bound", "Connection is already bound");
            return;
        }
        let now = now_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };
        if now >= room.room_expires_at_ms {
            send_err(handle, "room_expired", "Room has expired");
            return;
        }

        let candidate_hash = sha256_hex(resume_token.as_bytes());
        let Some(member) = room.members.get_mut(&participant_id) else {
            send_err(
                handle,
                "session_expired",
                "Participant is no longer a member",
            );
            return;
        };

        if !constant_time_eq_str(&member.resume_token_hash, &candidate_hash) {
            send_err(
                handle,
                "invalid_resume_token",
                "Invalid session resume proof",
            );
            return;
        }

        if let MemberConn::Disconnected { deadline_ms } = member.conn
            && now >= deadline_ms
        {
            send_err(
                handle,
                "resume_expired",
                "60-second reconnect window expired",
            );
            return;
        }

        // Rotate resume token on successful resume.
        let Ok(new_resume_token) = random_token_b64url(32) else {
            send_err(handle, "internal", "RNG failure");
            return;
        };
        member.resume_token_hash = sha256_hex(new_resume_token.as_bytes());

        // If an older socket was still attached, close it cleanly.
        if let MemberConn::Connected {
            handle: old_handle, ..
        } = &member.conn
        {
            old_handle.close();
        }
        let role = member.role;
        member.conn = MemberConn::Connected {
            conn_id,
            handle: handle.clone(),
        };

        *binding = Some(ConnBinding {
            room_id: room_id.clone(),
            participant_id: participant_id.clone(),
            role,
            is_pending_reservation: false,
            reservation_token_hash: None,
        });

        let members = room.member_summaries();
        let paused = room.messaging_paused();

        handle.try_send_msg(&RelayToClient::SessionResumed {
            room_id: room_id.clone(),
            participant_id: participant_id.clone(),
            resume_token: new_resume_token,
            epoch: room.epoch,
            room_created_at_ms: room.room_created_at_ms,
            room_expires_at_ms: room.room_expires_at_ms,
            latest_policy_cmd: room.latest_policy_cmd.clone(),
            members: members.clone(),
            messaging_paused: paused,
            keepalive_interval_secs: self.config.keepalive_interval_secs,
        });

        room.broadcast_members(
            &RelayToClient::MemberStatus {
                participant_id: participant_id.clone(),
                role,
                connected: true,
                members,
                messaging_paused: paused,
            },
            Some(&participant_id),
        );

        // If the Admin just resumed, deliver any queued GuestJoinRequests or pending removals!
        if role == ParticipantRole::Admin {
            let mut pending_joins = Vec::new();
            for inv in room.invites.values_mut() {
                if let InviteState::Reserved {
                    reservation_id,
                    guest_id,
                    key_package_b64,
                    forwarded_to_admin,
                    ..
                } = &mut inv.state
                    && !*forwarded_to_admin
                {
                    *forwarded_to_admin = true;
                    pending_joins.push((
                        reservation_id.clone(),
                        guest_id.clone(),
                        key_package_b64.clone(),
                    ));
                }
            }
            for (reservation_id, guest_id, key_package_b64) in pending_joins {
                handle.try_send_msg(&RelayToClient::GuestJoinRequest {
                    reservation_id,
                    guest_id,
                    key_package_b64,
                });
            }
            for removed_pid in &room.pending_removals {
                handle.try_send_msg(&RelayToClient::MemberRemovalRequired {
                    participant_id: removed_pid.clone(),
                    reason: "Pending guest removal requires MLS Remove commit".into(),
                });
            }
        }
    }

    async fn handle_admin_command(
        self: &Arc<Self>,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
        signed_cmd: SignedAdminCommand,
    ) {
        let Some(b) = binding else {
            send_err(handle, "unauthorized", "Not bound to a room");
            return;
        };
        if b.role != ParticipantRole::Admin {
            send_err(
                handle,
                "forbidden",
                "Only the room admin may send admin commands",
            );
            return;
        }

        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room does not exist");
            return;
        };

        // Cryptographically verify admin signature, room_id binding, and monotonic seq BEFORE any state mutation.
        if let Err(e) = room.admin_verifier.verify_and_advance(&signed_cmd) {
            warn!(room_id = %room.room_id, error = %e, "rejected invalid admin command");
            send_err(handle, "invalid_admin_command", &e.to_string());
            return;
        }

        let now = now_ms();
        match &signed_cmd.body.payload {
            AdminCommandPayload::SetPolicy {
                msg_ttl_secs,
                room_ttl_secs,
            } => {
                let policy = match RoomPolicy::new(*msg_ttl_secs, *room_ttl_secs) {
                    Ok(p) => p,
                    Err(e) => {
                        send_err(handle, "invalid_policy", &e.to_string());
                        return;
                    }
                };
                let new_expires = policy.compute_room_expires_at_ms(room.room_created_at_ms);
                room.policy = policy;
                room.room_expires_at_ms = new_expires;
                room.latest_policy_cmd = Some(signed_cmd.clone());

                if now >= new_expires {
                    // Shortened room TTL already elapsed relative to original creation time!
                    let removed = rooms.remove(&b.room_id).unwrap();
                    let msg = RelayToClient::RoomClosed {
                        room_id: removed.room_id.clone(),
                        reason: "Room lifetime expired after policy update".into(),
                    };
                    for h in removed.all_connected_handles() {
                        h.try_send_msg(&msg);
                        h.close();
                    }
                    return;
                }

                // Cap existing unused invite expiries at the updated room expiry.
                for inv in room.invites.values_mut() {
                    inv.expires_at_ms = inv.expires_at_ms.min(new_expires);
                }

                room.broadcast_members(
                    &RelayToClient::PolicyUpdated {
                        signed_cmd,
                        room_expires_at_ms: new_expires,
                    },
                    None,
                );
            }
            AdminCommandPayload::RegisterInvite {
                token_hash_hex,
                invite_ttl_secs,
            } => {
                if token_hash_hex.len() != 64
                    || !token_hash_hex.bytes().all(|c| c.is_ascii_hexdigit())
                {
                    send_err(
                        handle,
                        "invalid_invite_hash",
                        "Expected 64-char hex SHA-256 hash",
                    );
                    return;
                }
                if room.invites.len() >= 32 {
                    send_err(handle, "too_many_invites", "Invite limit per room reached");
                    return;
                }
                let effective_ttl = (*invite_ttl_secs).min(self.config.invite_ttl_secs).max(30);
                let expires_at_ms = now
                    .saturating_add(effective_ttl.saturating_mul(1000))
                    .min(room.room_expires_at_ms);

                room.invites.insert(
                    token_hash_hex.clone(),
                    InviteEntry {
                        expires_at_ms,
                        state: InviteState::Unused,
                    },
                );
                handle.try_send_msg(&RelayToClient::InviteRegistered {
                    token_hash_hex: token_hash_hex.clone(),
                    expires_at_ms,
                });
            }
            AdminCommandPayload::KickGuest { participant_id } => {
                if participant_id == &room.admin_id {
                    send_err(handle, "invalid_target", "Admin cannot kick self");
                    return;
                }
                if let Some(kicked) = room.members.remove(participant_id) {
                    if let MemberConn::Connected { handle: kh, .. } = kicked.conn {
                        kh.try_send_msg(&RelayToClient::RoomClosed {
                            room_id: room.room_id.clone(),
                            reason: "Removed from room by admin".into(),
                        });
                        kh.close();
                    }
                    room.pending_removals.insert(participant_id.clone());
                    let members = room.member_summaries();
                    let paused = room.messaging_paused();
                    room.send_to_admin(&RelayToClient::MemberRemovalRequired {
                        participant_id: participant_id.clone(),
                        reason: "Guest kicked by admin".into(),
                    });
                    room.broadcast_members(
                        &RelayToClient::MemberStatus {
                            participant_id: participant_id.clone(),
                            role: ParticipantRole::Guest,
                            connected: false,
                            members,
                            messaging_paused: paused,
                        },
                        None,
                    );
                } else {
                    send_err(handle, "member_not_found", "Guest not found in room");
                }
            }
            AdminCommandPayload::PanicWipe | AdminCommandPayload::CloseRoom => {
                let is_wipe = matches!(signed_cmd.body.payload, AdminCommandPayload::PanicWipe);
                // Immediately remove room from map so NO new joins, invites, or resumes can ever succeed!
                let removed = rooms.remove(&b.room_id).unwrap();
                drop(rooms);

                info!(room_id = %removed.room_id, is_wipe, "room terminated by admin");

                if is_wipe {
                    handle.try_send_msg(&RelayToClient::PanicWipeConfirmed {
                        room_id: removed.room_id.clone(),
                    });
                }

                let notify = if is_wipe {
                    RelayToClient::RoomWiped {
                        room_id: removed.room_id.clone(),
                        reason: "Admin triggered Panic-Wipe".into(),
                    }
                } else {
                    RelayToClient::RoomClosed {
                        room_id: removed.room_id.clone(),
                        reason: "Admin closed the room".into(),
                    }
                };

                let handles = removed.all_connected_handles();
                for h in &handles {
                    h.try_send_msg(&notify);
                }

                // Bounded delivery window before force-closing all room sockets (Section 7).
                let grace_ms = self.config.wipe_delivery_grace_ms;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(grace_ms)).await;
                    for h in handles {
                        h.close();
                    }
                });
            }
        }
    }

    async fn handle_send_mls_message(
        &self,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
        epoch: u64,
        message_id: String,
        ciphertext_b64: String,
    ) {
        let Some(b) = binding else {
            send_err(handle, "unauthorized", "Not bound to a room");
            return;
        };

        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };
        if now_ms() >= room.room_expires_at_ms {
            send_err(handle, "room_expired", "Room has expired");
            return;
        }
        if !room.members.contains_key(&b.participant_id) {
            send_err(
                handle,
                "forbidden",
                "Admission not complete or no longer a member of this room",
            );
            return;
        }
        // Section 5: Pause chat messaging after permanent guest removal until MLS Remove commit finishes!
        if room.messaging_paused() {
            send_err(
                handle,
                "messaging_paused",
                "Messaging paused while MLS group removes departed member",
            );
            return;
        }

        // Clear any cached welcome for this sender once they are actively participating.
        for inv in room.invites.values_mut() {
            if let InviteState::Consumed {
                guest_id,
                cached_welcome,
                ..
            } = &mut inv.state
                && guest_id == &b.participant_id
            {
                *cached_welcome = None;
            }
        }

        // Forward ONLY to currently connected sockets; NEVER buffer offline messages (Section 2 & 5).
        let msg = RelayToClient::MlsMessage {
            sender_id: b.participant_id.clone(),
            epoch,
            message_id,
            ciphertext_b64,
        };
        room.broadcast_members(&msg, Some(&b.participant_id));
    }

    async fn handle_send_mls_commit(
        &self,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
        epoch: u64,
        commit_b64: String,
        removed_participant_id: Option<String>,
    ) {
        let Some(b) = binding else {
            send_err(handle, "unauthorized", "Not bound to a room");
            return;
        };
        if b.role != ParticipantRole::Admin {
            send_err(
                handle,
                "forbidden",
                "Only the room admin sends MLS removal commits",
            );
            return;
        }

        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };

        if let Some(ref removed_pid) = removed_participant_id {
            room.pending_removals.remove(removed_pid);
            room.members.remove(removed_pid);
        }
        room.epoch = epoch;
        let members = room.member_summaries();
        let paused = room.messaging_paused();

        let commit_msg = RelayToClient::MlsCommit {
            sender_id: b.participant_id.clone(),
            epoch,
            commit_b64,
            members: members.clone(),
            messaging_paused: paused,
        };
        room.broadcast_members(&commit_msg, Some(&b.participant_id));

        // Also update admin's own status so UI unpauses messaging cleanly.
        room.send_to_admin(&RelayToClient::MemberStatus {
            participant_id: removed_participant_id.unwrap_or_else(|| b.participant_id.clone()),
            role: ParticipantRole::Guest,
            connected: false,
            members,
            messaging_paused: paused,
        });
    }

    async fn handle_explicit_leave(&self, conn_id: u64, binding: &mut Option<ConnBinding>) {
        let Some(b) = binding.take() else {
            return;
        };
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            return;
        };

        // Only treat as pending reservation if NOT yet promoted into `room.members`.
        if !room.members.contains_key(&b.participant_id) {
            if let Some(hash) = b.reservation_token_hash
                && let Some(inv) = room.invites.get(&hash)
                && matches!(inv.state, InviteState::Reserved { guest_conn_id, .. } if guest_conn_id == conn_id)
            {
                room.invites.remove(&hash);
            }
            return;
        }

        if b.role == ParticipantRole::Admin {
            // Section 6: Admin leaves explicitly -> Room ends immediately!
            let removed = rooms.remove(&b.room_id).unwrap();
            let msg = RelayToClient::RoomClosed {
                room_id: removed.room_id.clone(),
                reason: "Admin left the room".into(),
            };
            for h in removed.all_connected_handles() {
                h.try_send_msg(&msg);
                h.close();
            }
            return;
        }

        // Guest leaves explicitly -> permanent removal -> pause messaging until Admin commits MLS Remove!
        room.members.remove(&b.participant_id);
        if room.connected_socket_count() == 0 {
            rooms.remove(&b.room_id);
            return;
        }
        room.pending_removals.insert(b.participant_id.clone());
        let members = room.member_summaries();
        let paused = room.messaging_paused();
        room.send_to_admin(&RelayToClient::MemberRemovalRequired {
            participant_id: b.participant_id.clone(),
            reason: "Guest left the room".into(),
        });
        room.broadcast_members(
            &RelayToClient::MemberStatus {
                participant_id: b.participant_id,
                role: ParticipantRole::Guest,
                connected: false,
                members,
                messaging_paused: paused,
            },
            None,
        );
    }

    /// Called when a WebSocket connection drops unexpectedly (network loss, tab killed, phone sleep).
    pub async fn handle_disconnect(&self, conn_id: u64, binding: Option<ConnBinding>) {
        let Some(b) = binding else {
            return;
        };
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            return;
        };

        // Check if this socket was a pending reservation that hasn't been promoted yet.
        if !room.members.contains_key(&b.participant_id) {
            if let Some(ref hash) = b.reservation_token_hash
                && let Some(inv) = room.invites.get(hash)
                && matches!(inv.state, InviteState::Reserved { guest_conn_id, .. } if guest_conn_id == conn_id)
            {
                room.invites.remove(hash);
                if room.connected_socket_count() == 0 {
                    rooms.remove(&b.room_id);
                }
            }
            return;
        }

        let now = now_ms();
        let mut was_active_conn = false;
        if let Some(member) = room.members.get_mut(&b.participant_id)
            && matches!(member.conn, MemberConn::Connected { conn_id: cid, .. } if cid == conn_id)
        {
            was_active_conn = true;
            member.conn = MemberConn::Disconnected {
                deadline_ms: now
                    .saturating_add(self.config.reconnect_grace_secs.saturating_mul(1000)),
            };
        }

        if !was_active_conn {
            return;
        }

        // Section 6: When the last WebSocket disconnects, terminate the room immediately.
        // The 60-second reconnect grace period only applies while at least one other socket remains open.
        if room.connected_socket_count() == 0 {
            info!(room_id = %b.room_id, "last WebSocket disconnected; terminating room immediately");
            rooms.remove(&b.room_id);
            return;
        }

        // Otherwise, at least one other participant is still connected: hold slot for 60s.
        let members = room.member_summaries();
        let paused = room.messaging_paused();
        room.broadcast_members(
            &RelayToClient::MemberStatus {
                participant_id: b.participant_id,
                role: b.role,
                connected: false,
                members,
                messaging_paused: paused,
            },
            None,
        );
    }
}

fn send_err(handle: &OutboundHandle, code: &str, message: &str) {
    handle.try_send_msg(&RelayToClient::Error {
        code: code.to_string(),
        message: message.to_string(),
    });
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
