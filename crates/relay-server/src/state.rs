use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use core_crypto::admin::{
    AdminCommandPayload, AdminCommandVerifier, SignedAdminCommand, decode_pubkey_b64,
};
use core_crypto::policy::{MAX_ROOM_MEMBERS, RoomPolicy};
use core_crypto::protocol::{
    ClientToRelay, MemberSummary, MissedCommit, ParticipantRole, RelayToClient,
};
use core_crypto::{random_token_b64url, sha256_hex};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{info, warn};

use crate::config::RelayConfig;

const MAX_COMMIT_LOG_LEN: usize = 64;
const RESUME_RETRY_WINDOW_MS: u64 = 30_000;
const WELCOME_CACHE_WINDOW_MS: u64 = 30_000;
const MAX_ROOM_CREATIONS_PER_IP_PER_MIN: usize = 10;
const CHAT_MESSAGE_REFILL_MS: u64 = 1_500; // 40 messages per minute
const CHAT_MESSAGE_BURST: u64 = 10;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Data signal pushed to a single WebSocket writer task.
/// Closing/aborting is carried out-of-band via `watch::Sender<bool>` so a full queue never blocks close.
#[derive(Debug, Clone)]
pub enum OutboundSignal {
    Text(String),
}

#[derive(Clone)]
pub struct OutboundHandle {
    pub tx: mpsc::Sender<OutboundSignal>,
    close_tx: watch::Sender<bool>,
    pub max_bytes_per_min: usize,
    budget: Arc<std::sync::Mutex<OutboundBudget>>,
}

struct OutboundBudget {
    window_start_ms: u64,
    bytes_sent: usize,
}

impl OutboundHandle {
    pub fn new(
        tx: mpsc::Sender<OutboundSignal>,
        close_tx: watch::Sender<bool>,
        max_bytes_per_min: usize,
    ) -> Self {
        Self {
            tx,
            close_tx,
            max_bytes_per_min,
            budget: Arc::new(std::sync::Mutex::new(OutboundBudget {
                window_start_ms: now_ms(),
                bytes_sent: 0,
            })),
        }
    }

    /// Non-blocking send: if the outbound queue is full or traffic limit is exceeded,
    /// triggers the out-of-band close signal immediately so both reader and writer abort cleanly.
    pub fn try_send_msg(&self, msg: &RelayToClient) -> bool {
        if *self.close_tx.borrow() {
            return false;
        }
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
                self.close();
                return false;
            }
            b.bytes_sent = b.bytes_sent.saturating_add(len);
        }
        if self.tx.try_send(OutboundSignal::Text(json)).is_err() {
            // Queue saturated or already closed: slow consumer is aborted out-of-band.
            self.close();
            return false;
        }
        true
    }

    /// Out-of-band close signal that always succeeds even if the data queue is full.
    pub fn close(&self) {
        let _ = self.close_tx.send(true);
    }

    pub fn is_closed(&self) -> bool {
        *self.close_tx.borrow()
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

/// Short-lived idempotent resume cache so a lost `SessionResumed` frame can be retried
/// with the exact same previous token and `resume_attempt_id`.
#[derive(Clone)]
struct PendingResume {
    prev_token_hash: String,
    attempt_id: String,
    new_resume_token: String,
    expires_at_ms: u64,
}

struct MemberEntry {
    participant_id: String,
    role: ParticipantRole,
    resume_token_hash: String,
    pending_resume: Option<PendingResume>,
    confirmed_epoch: u64,
    chat_send_budget: ChatSendBudget,
    conn: MemberConn,
}

struct ChatSendBudget {
    credit_ms: u64,
    updated_at_ms: u64,
}

impl ChatSendBudget {
    fn new(now: u64) -> Self {
        Self {
            credit_ms: CHAT_MESSAGE_BURST * CHAT_MESSAGE_REFILL_MS,
            updated_at_ms: now,
        }
    }

    fn try_consume(&mut self, now: u64) -> bool {
        self.credit_ms = self
            .credit_ms
            .saturating_add(now.saturating_sub(self.updated_at_ms))
            .min(CHAT_MESSAGE_BURST * CHAT_MESSAGE_REFILL_MS);
        self.updated_at_ms = self.updated_at_ms.max(now);
        if self.credit_ms < CHAT_MESSAGE_REFILL_MS {
            return false;
        }
        self.credit_ms -= CHAT_MESSAGE_REFILL_MS;
        true
    }
}

#[derive(Clone)]
struct CachedJoinAccepted {
    guest_id: String,
    resume_token: String,
    key_package_b64: String,
    commit_id: String,
    welcome_epoch: u64,
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
        guest_conn_id: Option<u64>,
        guest_handle: Option<OutboundHandle>,
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
    /// Minimum epoch that all connected members must acknowledge before messaging unpauses after a removal.
    removal_barrier_epoch: u64,
    /// Bounded ordered MLS commit log for catch-up during Resume or retried JoinAccepted.
    commit_log: VecDeque<MissedCommit>,
    members: HashMap<String, MemberEntry>,
    invites: HashMap<String, InviteEntry>,
    pending_removals: HashSet<String>,
    /// Fixed deadline for holding an empty room in RAM while a valid unconsumed invite exists.
    /// Never extended by repeated join or resume attempts; cleared only on verified member resume.
    empty_hold_deadline_ms: Option<u64>,
}

impl Room {
    fn has_unacked_removal_barrier(&self) -> bool {
        self.removal_barrier_epoch > 0
            && self.members.values().any(|m| {
                matches!(m.conn, MemberConn::Connected { .. })
                    && m.confirmed_epoch < self.removal_barrier_epoch
            })
    }

    fn messaging_paused(&self) -> bool {
        !self.pending_removals.is_empty() || self.has_unacked_removal_barrier()
    }

    fn is_current_member_conn(&self, participant_id: &str, conn_id: u64) -> bool {
        matches!(
            self.members.get(participant_id),
            Some(MemberEntry {
                conn: MemberConn::Connected { conn_id: cid, .. },
                ..
            }) if *cid == conn_id
        )
    }

    fn record_commit(&mut self, commit: MissedCommit) {
        if self.commit_log.len() >= MAX_COMMIT_LOG_LEN {
            self.commit_log.pop_front();
        }
        self.commit_log.push_back(commit);
    }

    /// Returns the exact contiguous sequence of commits from `from_epoch` up to `self.epoch`.
    /// Returns `None` if `from_epoch > self.epoch` or required commits were evicted from the log.
    fn commits_since(&self, from_epoch: u64) -> Option<Vec<MissedCommit>> {
        if from_epoch > self.epoch {
            return None;
        }
        if from_epoch == self.epoch {
            return Some(Vec::new());
        }
        let mut expected = from_epoch;
        let mut out = Vec::new();
        for c in &self.commit_log {
            if c.prev_epoch == expected && c.epoch == expected + 1 {
                out.push(c.clone());
                expected = c.epoch;
            }
        }
        if expected == self.epoch {
            Some(out)
        } else {
            None
        }
    }

    fn has_commit_for_epoch(&self, commit_id: &str, epoch: u64) -> bool {
        if epoch == 0 {
            return true;
        }
        self.commit_log
            .iter()
            .any(|c| c.epoch == epoch && c.commit_id == commit_id)
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

    fn max_open_invite_expiry_ms(&self, now: u64) -> Option<u64> {
        self.invites
            .values()
            .filter(|inv| {
                matches!(
                    inv.state,
                    InviteState::Unused | InviteState::Reserved { .. }
                ) && now < inv.expires_at_ms
            })
            .map(|inv| inv.expires_at_ms)
            .max()
    }

    fn admin_disconnect_deadline_ms(&self) -> Option<u64> {
        match self.members.get(&self.admin_id).map(|m| &m.conn) {
            Some(MemberConn::Disconnected { deadline_ms }) => Some(*deadline_ms),
            _ => None,
        }
    }

    fn is_hold_expired(&self, now: u64) -> bool {
        if let Some(hold) = self.empty_hold_deadline_ms
            && now >= hold
        {
            return true;
        }
        if let Some(admin_dl) = self.admin_disconnect_deadline_ms()
            && now >= admin_dl
        {
            return true;
        }
        false
    }

    fn should_hold_empty(&self, now: u64) -> bool {
        if now >= self.room_expires_at_ms {
            return false;
        }
        let Some(hold_dl) = self.empty_hold_deadline_ms else {
            return false;
        };
        if now >= hold_dl {
            return false;
        }
        let Some(admin_dl) = self.admin_disconnect_deadline_ms() else {
            return false;
        };
        if now >= admin_dl {
            return false;
        }
        self.max_open_invite_expiry_ms(now).is_some()
    }

    fn connected_member_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| matches!(m.conn, MemberConn::Connected { .. }))
            .count()
    }

    fn connected_socket_count(&self) -> usize {
        let member_connected = self.connected_member_count();
        let guest_waiting = self
            .invites
            .values()
            .filter(|inv| {
                matches!(
                    inv.state,
                    InviteState::Reserved {
                        guest_handle: Some(_),
                        ..
                    }
                )
            })
            .count();
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
            if let InviteState::Reserved {
                guest_handle: Some(h),
                ..
            } = &inv.state
            {
                handles.push(h.clone());
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
    total_active_conns: usize,
    active_conns: HashMap<IpAddr, usize>,
    recent_attempts: HashMap<IpAddr, VecDeque<u64>>,
    recent_room_creations: HashMap<IpAddr, VecDeque<u64>>,
}

impl IpLimiter {
    fn new() -> Self {
        Self {
            total_active_conns: 0,
            active_conns: HashMap::new(),
            recent_attempts: HashMap::new(),
            recent_room_creations: HashMap::new(),
        }
    }

    fn prune_stale(&mut self, now: u64) {
        self.recent_attempts.retain(|_, attempts| {
            while let Some(&ts) = attempts.front() {
                if now.saturating_sub(ts) >= 60_000 {
                    attempts.pop_front();
                } else {
                    break;
                }
            }
            !attempts.is_empty()
        });
    }

    fn try_record_room_creation(&mut self, ip: IpAddr, now: u64, max_tracked_ips: usize) -> bool {
        if !self.recent_room_creations.contains_key(&ip)
            && self.recent_room_creations.len() >= max_tracked_ips
        {
            self.recent_room_creations.retain(|_, times| {
                times
                    .back()
                    .is_some_and(|&ts| now.saturating_sub(ts) < 60_000)
            });
            if self.recent_room_creations.len() >= max_tracked_ips {
                return false;
            }
        }

        let times = self.recent_room_creations.entry(ip).or_default();
        while times
            .front()
            .is_some_and(|&ts| now.saturating_sub(ts) >= 60_000)
        {
            times.pop_front();
        }
        if times.len() >= MAX_ROOM_CREATIONS_PER_IP_PER_MIN {
            return false;
        }
        times.push_back(now);
        true
    }

    fn try_acquire(&mut self, ip: IpAddr, now: u64, cfg: &RelayConfig) -> bool {
        if self.total_active_conns >= cfg.max_total_connections {
            return false;
        }

        if !self.recent_attempts.contains_key(&ip)
            && self.recent_attempts.len() >= cfg.max_tracked_ips
        {
            self.prune_stale(now);
            if self.recent_attempts.len() >= cfg.max_tracked_ips {
                // Evict the oldest idle IP entry to keep memory strictly bounded.
                let victim = self
                    .recent_attempts
                    .iter()
                    .filter(|(k, _)| !self.active_conns.contains_key(*k))
                    .min_by_key(|(_, q)| q.back().copied().unwrap_or(0))
                    .map(|(k, _)| *k);
                if let Some(v) = victim {
                    self.recent_attempts.remove(&v);
                } else {
                    return false;
                }
            }
        }

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
            if *active == 0 {
                self.active_conns.remove(&ip);
            }
            return false;
        }
        attempts.push_back(now);
        *active += 1;
        self.total_active_conns += 1;
        true
    }

    fn release(&mut self, ip: IpAddr, now: u64) {
        if let Some(count) = self.active_conns.get_mut(&ip) {
            if *count > 0 {
                *count -= 1;
                self.total_active_conns = self.total_active_conns.saturating_sub(1);
            }
            if *count == 0 {
                self.active_conns.remove(&ip);
            }
        }
        if let Some(attempts) = self.recent_attempts.get_mut(&ip) {
            while let Some(&ts) = attempts.front() {
                if now.saturating_sub(ts) >= 60_000 {
                    attempts.pop_front();
                } else {
                    break;
                }
            }
            if attempts.is_empty() {
                self.recent_attempts.remove(&ip);
            }
        }
    }
}

pub struct RelayState {
    pub config: RelayConfig,
    clock: ClockFn,
    rooms: Mutex<HashMap<String, Room>>,
    ip_limiter: std::sync::Mutex<IpLimiter>,
    next_conn_id: AtomicU64,
}

impl RelayState {
    pub fn new(config: RelayConfig) -> Arc<Self> {
        Self::new_with_clock(config, Arc::new(now_ms))
    }

    pub fn new_with_clock(config: RelayConfig, clock: ClockFn) -> Arc<Self> {
        Arc::new(Self {
            config,
            clock,
            rooms: Mutex::new(HashMap::new()),
            ip_limiter: std::sync::Mutex::new(IpLimiter::new()),
            next_conn_id: AtomicU64::new(1),
        })
    }

    pub fn current_time_ms(&self) -> u64 {
        (self.clock)()
    }

    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn try_acquire_ip(&self, ip: IpAddr) -> bool {
        let now = self.current_time_ms();
        let mut limiter = self.ip_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.try_acquire(ip, now, &self.config)
    }

    pub fn release_ip(&self, ip: IpAddr) {
        let now = self.current_time_ms();
        let mut limiter = self.ip_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.release(ip, now);
    }

    pub fn tracked_ip_count(&self) -> usize {
        let limiter = self.ip_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.recent_attempts.len()
    }

    pub fn total_active_connections(&self) -> usize {
        let limiter = self.ip_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.total_active_conns
    }

    pub async fn active_room_count(&self) -> usize {
        self.rooms.lock().await.len()
    }

    /// Starts the background timer sweeper that enforces room lifetimes,
    /// invite/reservation timeouts, 60s participant reconnect windows, and IP limiter cleanup.
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
        let now = self.current_time_ms();

        // Periodically prune stale IP keys so recent_attempts stays bounded.
        {
            let mut limiter = self.ip_limiter.lock().unwrap_or_else(|e| e.into_inner());
            limiter.prune_stale(now);
        }

        let mut rooms = self.rooms.lock().await;
        let mut rooms_to_close: Vec<(String, String)> = Vec::new();

        for (room_id, room) in rooms.iter_mut() {
            // 1. Hard room lifetime check.
            if now >= room.room_expires_at_ms {
                rooms_to_close.push((room_id.clone(), "Room lifetime expired".into()));
                continue;
            }

            // 2. Expire unused invites, timed-out reservations, welcome caches, and resume caches.
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
                        if now >= inv.expires_at_ms {
                            if let Some(gh) = guest_handle {
                                gh.try_send_msg(&RelayToClient::Error {
                                    code: "invite_expired".into(),
                                    message: "Invite link has expired".into(),
                                });
                                gh.close();
                            }
                            expired_invite_keys.push(token_hash.clone());
                        } else if now >= *expires_at_ms {
                            // Reservation timed out while invite is still valid and unused:
                            // release the reserved slot and allow a retry with the same link.
                            if let Some(gh) = guest_handle {
                                gh.try_send_msg(&RelayToClient::Error {
                                    code: "join_timeout".into(),
                                    message: "Join reservation expired before admin responded. You can try again while the invite link is still valid.".into(),
                                });
                                gh.close();
                            }
                            inv.state = InviteState::Unused;
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

            for member in room.members.values_mut() {
                if let Some(pr) = &member.pending_resume
                    && now >= pr.expires_at_ms
                {
                    member.pending_resume = None;
                }
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

            // 4. If 0 connected sockets remain after cleanup, terminate room unless held for a valid open invite.
            if room.connected_socket_count() == 0 && !room.should_hold_empty(now) {
                rooms_to_close.push((room_id.clone(), "All participants disconnected".into()));
            }
        }

        for (room_id, reason) in rooms_to_close {
            close_room_locked(&mut rooms, &room_id, reason);
        }
    }

    /// Handles a single incoming protocol message from a WebSocket connection.
    pub async fn handle_message(
        self: &Arc<Self>,
        conn_id: u64,
        client_ip: IpAddr,
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
                self.handle_create_room(
                    conn_id,
                    client_ip,
                    handle,
                    binding,
                    admin_pubkey_b64,
                    initial_policy,
                )
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
                resume_attempt_id,
                last_epoch,
            } => {
                self.handle_resume_session(
                    conn_id,
                    handle,
                    binding,
                    room_id,
                    participant_id,
                    resume_token,
                    resume_attempt_id,
                    last_epoch,
                )
                .await;
            }
            ClientToRelay::AckResume => {
                self.handle_ack_resume(conn_id, handle, binding).await;
            }
            ClientToRelay::AckCommit { commit_id, epoch } => {
                self.handle_ack_commit(conn_id, handle, binding, commit_id, epoch)
                    .await;
            }
            ClientToRelay::VerifySession {
                check_id,
                local_epoch,
            } => {
                self.handle_verify_session(conn_id, handle, binding, check_id, local_epoch)
                    .await;
            }
            ClientToRelay::CompleteJoin {
                reservation_id,
                guest_id,
                commit_id,
                expected_epoch,
                commit_b64,
                welcome_b64,
                new_epoch,
            } => {
                self.handle_complete_join(
                    conn_id,
                    handle,
                    binding,
                    reservation_id,
                    guest_id,
                    commit_id,
                    expected_epoch,
                    commit_b64,
                    welcome_b64,
                    new_epoch,
                )
                .await;
            }
            ClientToRelay::AdminCommand { signed_cmd } => {
                self.handle_admin_command(conn_id, handle, binding, signed_cmd)
                    .await;
            }
            ClientToRelay::SendMlsMessage {
                epoch,
                message_id,
                ciphertext_b64,
            } => {
                self.handle_send_mls_message(
                    conn_id,
                    handle,
                    binding,
                    epoch,
                    message_id,
                    ciphertext_b64,
                )
                .await;
            }
            ClientToRelay::SendMlsCommit {
                commit_id,
                expected_epoch,
                epoch,
                commit_b64,
                removed_participant_id,
            } => {
                self.handle_send_mls_commit(
                    conn_id,
                    handle,
                    binding,
                    commit_id,
                    expected_epoch,
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
        client_ip: IpAddr,
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

        let created_at = self.current_time_ms();
        let expires_at = initial_policy.compute_room_expires_at_ms(created_at);

        let mut members = HashMap::new();
        members.insert(
            admin_id.clone(),
            MemberEntry {
                participant_id: admin_id.clone(),
                role: ParticipantRole::Admin,
                resume_token_hash: sha256_hex(resume_token.as_bytes()),
                pending_resume: None,
                confirmed_epoch: 0,
                chat_send_budget: ChatSendBudget::new(created_at),
                conn: MemberConn::Connected {
                    conn_id,
                    handle: handle.clone(),
                },
            },
        );

        let admitted = self
            .ip_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .try_record_room_creation(client_ip, created_at, self.config.max_tracked_ips);
        if !admitted {
            send_err(
                handle,
                "rate_limited",
                "Room creation rate limit reached. Try again shortly.",
            );
            return;
        }
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
                removal_barrier_epoch: 0,
                commit_log: VecDeque::new(),
                members,
                invites: HashMap::new(),
                pending_removals: HashSet::new(),
                empty_hold_deadline_ms: None,
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
        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;

        // Join NEVER creates a room (Section 8).
        let Some(room) = rooms.get_mut(&room_id) else {
            send_err(handle, "room_not_found", "Room does not exist or has ended");
            return;
        };

        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &room_id, "Room lifetime expired".into());
            send_err(handle, "room_expired", "Room has expired");
            return;
        }
        if room.is_hold_expired(now) {
            close_room_locked(
                &mut rooms,
                &room_id,
                "Admin reconnect window expired".into(),
            );
            send_err(handle, "room_not_found", "Room does not exist or has ended");
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

        enum JoinFollowUp {
            None,
            ForwardToAdmin {
                reservation_id: String,
                guest_id: String,
                key_package_b64: String,
                reason_is_retry: bool,
            },
            RemoveExpiredInvite {
                code: &'static str,
                message: &'static str,
            },
        }

        let mut follow_up = JoinFollowUp::None;

        match &mut invite.state {
            InviteState::Unused => {
                if now >= invite.expires_at_ms {
                    follow_up = JoinFollowUp::RemoveExpiredInvite {
                        code: "invite_expired",
                        message: "Invite link has expired",
                    };
                } else if current_slots >= MAX_ROOM_MEMBERS {
                    send_err(
                        handle,
                        "room_full",
                        "Room already has the maximum of 4 participants",
                    );
                    return;
                } else {
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
                        .min(invite.expires_at_ms)
                        .min(room.room_expires_at_ms);

                    // Atomically transition Unused -> Reserved inside the room mutex.
                    invite.state = InviteState::Reserved {
                        reservation_id: reservation_id.clone(),
                        guest_id: guest_id.clone(),
                        client_join_nonce,
                        key_package_b64: key_package_b64.clone(),
                        guest_conn_id: Some(conn_id),
                        guest_handle: Some(handle.clone()),
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

                    follow_up = JoinFollowUp::ForwardToAdmin {
                        reservation_id,
                        guest_id,
                        key_package_b64,
                        reason_is_retry: false,
                    };
                }
            }
            InviteState::Reserved {
                reservation_id,
                client_join_nonce: existing_nonce,
                key_package_b64: existing_kp,
                guest_id,
                guest_conn_id,
                guest_handle,
                expires_at_ms,
                forwarded_to_admin,
            } => {
                if now >= invite.expires_at_ms {
                    if let Some(old_h) = guest_handle.take() {
                        old_h.close();
                    }
                    follow_up = JoinFollowUp::RemoveExpiredInvite {
                        code: "invite_expired",
                        message: "Invite link has expired",
                    };
                } else if now >= *expires_at_ms {
                    // Previous reservation expired while the invite is still valid and unused:
                    // release the stale reservation and allow this fresh attempt without extending any deadline.
                    if let Some(old_h) = guest_handle.take() {
                        old_h.try_send_msg(&RelayToClient::Error {
                            code: "join_timeout".into(),
                            message: "Join reservation expired before admin responded. You can try again while the invite link is still valid.".into(),
                        });
                        old_h.close();
                    }
                    let freed_slots = current_slots.saturating_sub(1);
                    if freed_slots >= MAX_ROOM_MEMBERS {
                        invite.state = InviteState::Unused;
                        send_err(
                            handle,
                            "room_full",
                            "Room already has the maximum of 4 participants",
                        );
                        return;
                    }
                    let Ok(new_res_id) = random_token_b64url(12) else {
                        invite.state = InviteState::Unused;
                        send_err(handle, "internal", "RNG failure");
                        return;
                    };
                    let Ok(new_guest_id) = random_token_b64url(8) else {
                        invite.state = InviteState::Unused;
                        send_err(handle, "internal", "RNG failure");
                        return;
                    };
                    let res_expiry = now
                        .saturating_add(self.config.join_reservation_ttl_secs.saturating_mul(1000))
                        .min(invite.expires_at_ms)
                        .min(room.room_expires_at_ms);

                    invite.state = InviteState::Reserved {
                        reservation_id: new_res_id.clone(),
                        guest_id: new_guest_id.clone(),
                        client_join_nonce,
                        key_package_b64: key_package_b64.clone(),
                        guest_conn_id: Some(conn_id),
                        guest_handle: Some(handle.clone()),
                        expires_at_ms: res_expiry,
                        forwarded_to_admin: false,
                    };

                    *binding = Some(ConnBinding {
                        room_id: room_id.clone(),
                        participant_id: new_guest_id.clone(),
                        role: ParticipantRole::Guest,
                        is_pending_reservation: true,
                        reservation_token_hash: Some(token_hash.clone()),
                    });

                    follow_up = JoinFollowUp::ForwardToAdmin {
                        reservation_id: new_res_id,
                        guest_id: new_guest_id,
                        key_package_b64,
                        reason_is_retry: false,
                    };
                } else if constant_time_eq_str(existing_nonce, &client_join_nonce)
                    && constant_time_eq_str(existing_kp, &key_package_b64)
                {
                    // Idempotent retry by the exact same pending guest replaces the waiting socket
                    // without taking a second slot.
                    if let Some(old_h) = guest_handle.replace(handle.clone()) {
                        old_h.close();
                    }
                    *guest_conn_id = Some(conn_id);
                    *binding = Some(ConnBinding {
                        room_id: room_id.clone(),
                        participant_id: guest_id.clone(),
                        role: ParticipantRole::Guest,
                        is_pending_reservation: true,
                        reservation_token_hash: Some(token_hash.clone()),
                    });
                    if !*forwarded_to_admin {
                        follow_up = JoinFollowUp::ForwardToAdmin {
                            reservation_id: reservation_id.clone(),
                            guest_id: guest_id.clone(),
                            key_package_b64: existing_kp.clone(),
                            reason_is_retry: true,
                        };
                    } else {
                        handle.try_send_msg(&RelayToClient::JoinPending {
                            room_id: room_id.clone(),
                            reason: "Continuing pending admission request".into(),
                        });
                    }
                } else {
                    send_err(
                        handle,
                        "invite_in_use",
                        "Invite token is already reserved by another join attempt",
                    );
                    return;
                }
            }
            InviteState::Consumed {
                guest_id,
                client_join_nonce: existing_nonce,
                cached_welcome,
            } => {
                // Section 4: If admission already succeeded and only the response was lost,
                // retrying with the exact same token + nonce + KeyPackage continues the same seat.
                if constant_time_eq_str(existing_nonce, &client_join_nonce)
                    && let Some(cw) = cached_welcome.clone()
                    && now < cw.expires_at_ms
                    && constant_time_eq_str(&cw.key_package_b64, &key_package_b64)
                    && room.members.contains_key(guest_id)
                {
                    let gid = guest_id.clone();
                    let Some(missed_commits) = room.commits_since(cw.welcome_epoch) else {
                        send_err(
                            handle,
                            "epoch_desync",
                            "Room epoch advanced beyond cached welcome; request a new invite",
                        );
                        return;
                    };
                    if let Some(member) = room.members.get_mut(&gid) {
                        if let MemberConn::Connected {
                            handle: old_handle, ..
                        } = &member.conn
                        {
                            old_handle.close();
                        }
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
                    let room_epoch = room.epoch;
                    let paused = room.messaging_paused();
                    handle.try_send_msg(&RelayToClient::JoinAccepted {
                        room_id,
                        participant_id: cw.guest_id,
                        resume_token: cw.resume_token,
                        commit_id: cw.commit_id,
                        welcome_epoch: cw.welcome_epoch,
                        epoch: room_epoch,
                        missed_commits,
                        welcome_b64: cw.welcome_b64,
                        admin_pubkey_b64: cw.admin_pubkey_b64,
                        latest_policy_cmd: cw.latest_policy_cmd,
                        room_created_at_ms: cw.room_created_at_ms,
                        room_expires_at_ms: cw.room_expires_at_ms,
                        members: members_snapshot,
                        messaging_paused: paused,
                        keepalive_interval_secs: self.config.keepalive_interval_secs,
                    });
                } else {
                    send_err(
                        handle,
                        "invite_consumed",
                        "One-time invite token has already been used",
                    );
                }
                return;
            }
        }

        match follow_up {
            JoinFollowUp::None => {}
            JoinFollowUp::RemoveExpiredInvite { code, message } => {
                room.invites.remove(&token_hash);
                send_err(handle, code, message);
            }
            JoinFollowUp::ForwardToAdmin {
                reservation_id,
                guest_id,
                key_package_b64,
                reason_is_retry,
            } => {
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
                    if reason_is_retry {
                        "Continuing pending admission request".to_string()
                    } else {
                        "Admission request sent to room admin".to_string()
                    }
                } else {
                    "Room admin is temporarily offline; waiting for admin to return".to_string()
                };
                handle.try_send_msg(&RelayToClient::JoinPending { room_id, reason });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_complete_join(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
        reservation_id: String,
        guest_id: String,
        commit_id: String,
        expected_epoch: u64,
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
        if commit_id.is_empty() || commit_b64.is_empty() || welcome_b64.is_empty() {
            send_err(handle, "invalid_commit", "Malformed join commit");
            return;
        }

        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };

        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &b.room_id, "Room lifetime expired".into());
            send_err(handle, "room_expired", "Room has expired");
            return;
        }
        if !room.is_current_member_conn(&b.participant_id, conn_id) {
            send_err(handle, "stale_connection", "Connection has been superseded");
            handle.close();
            return;
        }
        if let Some(admin_m) = room.members.get_mut(&b.participant_id) {
            admin_m.pending_resume = None;
        }

        if expected_epoch != room.epoch || new_epoch != room.epoch.saturating_add(1) {
            send_err(
                handle,
                "epoch_mismatch",
                &format!(
                    "Commit transition {expected_epoch}->{new_epoch} does not match current room epoch {}",
                    room.epoch
                ),
            );
            return;
        }

        let Some(latest_policy_cmd) = room.latest_policy_cmd.clone() else {
            send_err(handle, "room_not_ready", "Missing signed room policy");
            return;
        };

        // Locate the matching reserved invite AND check its deadlines under the same mutex lock.
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

        // Enforce reservation and invite hard deadlines BEFORE mutating room state.
        let reservation_expired = {
            let inv = room.invites.get(&token_hash).unwrap();
            match &inv.state {
                InviteState::Reserved { expires_at_ms, .. } => {
                    now >= *expires_at_ms || now >= inv.expires_at_ms
                }
                _ => true,
            }
        };
        if reservation_expired {
            let invite_expired = room
                .invites
                .get(&token_hash)
                .is_none_or(|inv| now >= inv.expires_at_ms);
            if invite_expired {
                if let Some(inv) = room.invites.remove(&token_hash)
                    && let InviteState::Reserved {
                        guest_handle: Some(gh),
                        ..
                    } = inv.state
                {
                    gh.try_send_msg(&RelayToClient::Error {
                        code: "invite_expired".into(),
                        message: "Invite link has expired".into(),
                    });
                    gh.close();
                }
            } else if let Some(inv) = room.invites.get_mut(&token_hash) {
                let prev = std::mem::replace(&mut inv.state, InviteState::Unused);
                if let InviteState::Reserved {
                    guest_handle: Some(gh),
                    ..
                } = prev
                {
                    gh.try_send_msg(&RelayToClient::Error {
                        code: "join_timeout".into(),
                        message: "Join reservation expired before admin responded. You can try again while the invite link is still valid.".into(),
                    });
                    gh.close();
                }
            }
            send_err(
                handle,
                "reservation_expired",
                "Join reservation has already expired",
            );
            return;
        }

        let Ok(resume_token) = random_token_b64url(32) else {
            send_err(handle, "internal", "RNG failure");
            return;
        };
        let resume_token_hash = sha256_hex(resume_token.as_bytes());

        // Extract reservation info and mark invite Consumed.
        let (client_join_nonce, key_package_b64, guest_conn_id, guest_handle) = {
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
                    key_package_b64,
                    guest_conn_id,
                    guest_handle,
                    ..
                } => (
                    client_join_nonce,
                    key_package_b64,
                    guest_conn_id,
                    guest_handle,
                ),
                _ => unreachable!(),
            }
        };

        let prev_epoch = room.epoch;
        room.epoch = new_epoch;
        room.record_commit(MissedCommit {
            commit_id: commit_id.clone(),
            sender_id: b.participant_id.clone(),
            prev_epoch,
            epoch: new_epoch,
            commit_b64: commit_b64.clone(),
        });

        let guest_conn = match (guest_conn_id, guest_handle.clone()) {
            (Some(cid), Some(gh)) if !gh.is_closed() => MemberConn::Connected {
                conn_id: cid,
                handle: gh,
            },
            _ => MemberConn::Disconnected {
                deadline_ms: now
                    .saturating_add(self.config.reconnect_grace_secs.saturating_mul(1000)),
            },
        };

        room.members.insert(
            guest_id.clone(),
            MemberEntry {
                participant_id: guest_id.clone(),
                role: ParticipantRole::Guest,
                resume_token_hash,
                pending_resume: None,
                // Guest must verify Welcome and send AckCommit(new_epoch) before sending messages.
                confirmed_epoch: prev_epoch,
                chat_send_budget: ChatSendBudget::new(now),
                conn: guest_conn,
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
                    key_package_b64,
                    commit_id: commit_id.clone(),
                    welcome_epoch: new_epoch,
                    welcome_b64: welcome_b64.clone(),
                    admin_pubkey_b64: room.admin_pubkey_b64.clone(),
                    latest_policy_cmd: latest_policy_cmd.clone(),
                    room_created_at_ms: room.room_created_at_ms,
                    room_expires_at_ms: room.room_expires_at_ms,
                    expires_at_ms: now
                        .saturating_add(WELCOME_CACHE_WINDOW_MS)
                        .min(room.room_expires_at_ms),
                }),
            };
        }

        // Confirm commit acceptance to Admin so Admin can now apply its staged pending commit locally.
        room.send_to_admin(&RelayToClient::CommitAccepted {
            commit_id: commit_id.clone(),
            prev_epoch,
            new_epoch,
            members: members.clone(),
            messaging_paused: paused,
        });

        // Broadcast MLS Add Commit to all existing connected members except Admin and newly added guest.
        let commit_msg = RelayToClient::MlsCommit {
            commit_id: commit_id.clone(),
            sender_id: b.participant_id.clone(),
            prev_epoch,
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

        // Deliver Welcome + signed room rules to the newly admitted guest if currently attached.
        if let Some(gh) = guest_handle {
            gh.try_send_msg(&RelayToClient::JoinAccepted {
                room_id: room.room_id.clone(),
                participant_id: guest_id,
                resume_token,
                commit_id,
                welcome_epoch: new_epoch,
                epoch: new_epoch,
                missed_commits: Vec::new(),
                welcome_b64,
                admin_pubkey_b64: room.admin_pubkey_b64.clone(),
                latest_policy_cmd,
                room_created_at_ms: room.room_created_at_ms,
                room_expires_at_ms: room.room_expires_at_ms,
                members,
                messaging_paused: paused,
                keepalive_interval_secs: self.config.keepalive_interval_secs,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_resume_session(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &mut Option<ConnBinding>,
        room_id: String,
        participant_id: String,
        resume_token: String,
        resume_attempt_id: String,
        last_epoch: u64,
    ) {
        if binding.is_some() {
            send_err(handle, "already_bound", "Connection is already bound");
            return;
        }
        if resume_attempt_id.len() < 8 {
            send_err(handle, "invalid_resume", "Missing resume_attempt_id");
            return;
        }
        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };
        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &room_id, "Room lifetime expired".into());
            send_err(handle, "room_expired", "Room has expired");
            return;
        }
        if room.is_hold_expired(now) {
            close_room_locked(
                &mut rooms,
                &room_id,
                "Admin reconnect window expired".into(),
            );
            send_err(handle, "resume_expired", "Reconnect window expired");
            return;
        }

        // Validate epoch catch-up feasibility before mutating member state.
        let Some(missed_commits) = room.commits_since(last_epoch) else {
            send_err(
                handle,
                "epoch_desync",
                "Local MLS epoch cannot be synchronized with room epoch",
            );
            return;
        };

        let candidate_hash = sha256_hex(resume_token.as_bytes());
        let Some(member) = room.members.get_mut(&participant_id) else {
            send_err(
                handle,
                "session_expired",
                "Participant is no longer a member",
            );
            return;
        };

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

        let new_resume_token = if constant_time_eq_str(&member.resume_token_hash, &candidate_hash) {
            // Fresh resume: rotate token and cache previous token briefly for idempotent retry
            // in case SessionResumed drops in flight before the client acknowledges it.
            let Ok(rotated) = random_token_b64url(32) else {
                send_err(handle, "internal", "RNG failure");
                return;
            };
            let prev_hash = member.resume_token_hash.clone();
            member.resume_token_hash = sha256_hex(rotated.as_bytes());
            member.pending_resume = Some(PendingResume {
                prev_token_hash: prev_hash,
                attempt_id: resume_attempt_id,
                new_resume_token: rotated.clone(),
                expires_at_ms: now
                    .saturating_add(RESUME_RETRY_WINDOW_MS)
                    .min(room.room_expires_at_ms),
            });
            rotated
        } else if let Some(pr) = member.pending_resume.clone()
            && now < pr.expires_at_ms
            && constant_time_eq_str(&pr.prev_token_hash, &candidate_hash)
            && constant_time_eq_str(&pr.attempt_id, &resume_attempt_id)
        {
            // Idempotent retry of a lost SessionResumed response using the exact same attempt ID.
            pr.new_resume_token
        } else {
            send_err(
                handle,
                "invalid_resume_token",
                "Invalid session resume proof",
            );
            return;
        };

        // If an older socket was still attached, close it immediately out-of-band.
        if let MemberConn::Connected {
            handle: old_handle, ..
        } = &member.conn
        {
            old_handle.close();
        }
        let role = member.role;
        member.confirmed_epoch = last_epoch.min(room.epoch);
        member.conn = MemberConn::Connected {
            conn_id,
            handle: handle.clone(),
        };
        // Verified member resume ends any empty-room invite hold window.
        room.empty_hold_deadline_ms = None;

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
            conn_generation: conn_id,
            epoch: room.epoch,
            missed_commits,
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

        // If the Admin just resumed, deliver any non-expired queued GuestJoinRequests or pending removals.
        if role == ParticipantRole::Admin {
            let mut pending_joins = Vec::new();
            for inv in room.invites.values_mut() {
                if let InviteState::Reserved {
                    reservation_id,
                    guest_id,
                    key_package_b64,
                    forwarded_to_admin,
                    expires_at_ms,
                    ..
                } = &mut inv.state
                    && !*forwarded_to_admin
                    && now < *expires_at_ms
                    && now < inv.expires_at_ms
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

    async fn handle_ack_resume(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
    ) {
        let Some(b) = binding else {
            return;
        };
        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            return;
        };
        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &b.room_id, "Room lifetime expired".into());
            return;
        }
        if !room.is_current_member_conn(&b.participant_id, conn_id) {
            send_err(handle, "stale_connection", "Connection has been superseded");
            handle.close();
            return;
        }
        if let Some(m) = room.members.get_mut(&b.participant_id) {
            m.pending_resume = None;
        }
    }

    async fn handle_ack_commit(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
        commit_id: String,
        epoch: u64,
    ) {
        let Some(b) = binding else {
            send_err(handle, "unauthorized", "Not bound to a room");
            return;
        };
        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };
        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &b.room_id, "Room lifetime expired".into());
            send_err(handle, "room_expired", "Room has expired");
            return;
        }
        if !room.is_current_member_conn(&b.participant_id, conn_id) {
            send_err(handle, "stale_connection", "Connection has been superseded");
            handle.close();
            return;
        }
        if epoch > room.epoch || !room.has_commit_for_epoch(&commit_id, epoch) {
            send_err(
                handle,
                "invalid_commit_ack",
                "Unknown commit_id or epoch in AckCommit",
            );
            return;
        }

        let was_paused = room.messaging_paused();
        if let Some(member) = room.members.get_mut(&b.participant_id) {
            member.pending_resume = None;
            member.confirmed_epoch = member.confirmed_epoch.max(epoch);
        }

        // Clear any cached welcome once this guest has confirmed their MLS epoch.
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

        let is_paused = room.messaging_paused();
        if was_paused && !is_paused {
            let members = room.member_summaries();
            room.broadcast_members(
                &RelayToClient::MemberStatus {
                    participant_id: b.participant_id.clone(),
                    role: b.role,
                    connected: true,
                    members,
                    messaging_paused: false,
                },
                None,
            );
        }
    }

    async fn handle_verify_session(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
        check_id: String,
        local_epoch: u64,
    ) {
        let Some(b) = binding else {
            send_err(handle, "unauthorized", "Not bound to a room");
            return;
        };
        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };
        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &b.room_id, "Room lifetime expired".into());
            send_err(handle, "room_expired", "Room has expired");
            return;
        }
        if !room.is_current_member_conn(&b.participant_id, conn_id) {
            send_err(handle, "stale_connection", "Connection has been superseded");
            handle.close();
            return;
        }
        let Some(member) = room.members.get_mut(&b.participant_id) else {
            send_err(handle, "session_expired", "No longer a member");
            return;
        };
        member.pending_resume = None;
        if local_epoch != room.epoch || member.confirmed_epoch != room.epoch {
            send_err(
                handle,
                "epoch_desync",
                "Local MLS epoch does not match current room epoch",
            );
            return;
        }
        let members = room.member_summaries();
        let paused = room.messaging_paused();
        handle.try_send_msg(&RelayToClient::SessionVerified {
            check_id,
            epoch: room.epoch,
            room_expires_at_ms: room.room_expires_at_ms,
            members,
            messaging_paused: paused,
        });
    }

    async fn handle_admin_command(
        self: &Arc<Self>,
        conn_id: u64,
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

        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room does not exist");
            return;
        };

        // 1. Enforce hard room expiry BEFORE any verification or mutation (Finding 5).
        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &b.room_id, "Room lifetime expired".into());
            send_err(handle, "room_expired", "Room has expired");
            return;
        }

        // 2. Enforce active connection generation (Finding 4).
        if !room.is_current_member_conn(&b.participant_id, conn_id) {
            send_err(handle, "stale_connection", "Connection has been superseded");
            handle.close();
            return;
        }
        if let Some(admin_m) = room.members.get_mut(&b.participant_id) {
            admin_m.pending_resume = None;
        }

        // 3. Cryptographically verify signature, room_id, sequence > last_seq, AND epoch == room.epoch
        // WITHOUT mutating last_seq until all payload preconditions succeed!
        if let Err(e) = room.admin_verifier.check_live(&signed_cmd, room.epoch) {
            warn!(room_id = %room.room_id, error = %e, "rejected invalid admin command");
            send_err(handle, "invalid_admin_command", &e.to_string());
            return;
        }

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
                if let Err(e) = room.admin_verifier.commit_seq(signed_cmd.body.seq) {
                    send_err(handle, "invalid_admin_command", &e.to_string());
                    return;
                }
                let new_expires = policy.compute_room_expires_at_ms(room.room_created_at_ms);
                room.policy = policy;
                room.room_expires_at_ms = new_expires;
                room.latest_policy_cmd = Some(signed_cmd.clone());

                if now >= new_expires {
                    // Shortened room TTL already elapsed relative to original creation time!
                    close_room_locked(
                        &mut rooms,
                        &b.room_id,
                        "Room lifetime expired after policy update".into(),
                    );
                    return;
                }

                // Cap existing invites, caches, and any empty-hold deadline at the updated room expiry.
                if let Some(hold) = &mut room.empty_hold_deadline_ms {
                    *hold = (*hold).min(new_expires);
                }
                for inv in room.invites.values_mut() {
                    inv.expires_at_ms = inv.expires_at_ms.min(new_expires);
                    match &mut inv.state {
                        InviteState::Reserved { expires_at_ms, .. } => {
                            *expires_at_ms = (*expires_at_ms).min(new_expires);
                        }
                        InviteState::Consumed {
                            cached_welcome: Some(cw),
                            ..
                        } => {
                            cw.room_expires_at_ms = cw.room_expires_at_ms.min(new_expires);
                            cw.expires_at_ms = cw.expires_at_ms.min(new_expires);
                        }
                        _ => {}
                    }
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
                if let Err(e) = room.admin_verifier.commit_seq(signed_cmd.body.seq) {
                    send_err(handle, "invalid_admin_command", &e.to_string());
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
                if !room.members.contains_key(participant_id) {
                    send_err(handle, "member_not_found", "Guest not found in room");
                    return;
                }
                if let Err(e) = room.admin_verifier.commit_seq(signed_cmd.body.seq) {
                    send_err(handle, "invalid_admin_command", &e.to_string());
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
                }
            }
            AdminCommandPayload::PanicWipe | AdminCommandPayload::CloseRoom => {
                let is_wipe = matches!(signed_cmd.body.payload, AdminCommandPayload::PanicWipe);
                if let Err(e) = room.admin_verifier.commit_seq(signed_cmd.body.seq) {
                    send_err(handle, "invalid_admin_command", &e.to_string());
                    return;
                }
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
        conn_id: u64,
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

        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };
        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &b.room_id, "Room lifetime expired".into());
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
        if !room.is_current_member_conn(&b.participant_id, conn_id) {
            send_err(handle, "stale_connection", "Connection has been superseded");
            handle.close();
            return;
        }
        // Enforce strict epoch equality between message, sender's confirmed epoch, and room epoch FIRST
        // so stale-epoch clients always receive an explicit epoch_mismatch rejection.
        let sender_confirmed_epoch = room
            .members
            .get(&b.participant_id)
            .map(|m| m.confirmed_epoch)
            .unwrap_or(0);
        if epoch != room.epoch || sender_confirmed_epoch != room.epoch {
            send_err(
                handle,
                "epoch_mismatch",
                &format!(
                    "Message epoch {epoch} (confirmed {sender_confirmed_epoch}) does not match room epoch {}",
                    room.epoch
                ),
            );
            return;
        }
        // Section 5: Pause chat messaging after permanent guest removal until MLS Remove commit
        // completes AND all connected members acknowledge the new epoch!
        if room.messaging_paused() {
            send_err(
                handle,
                "messaging_paused",
                "Messaging paused while MLS group completes membership change",
            );
            return;
        }

        if let Some(m) = room.members.get_mut(&b.participant_id) {
            if !m.chat_send_budget.try_consume(now) {
                send_err(
                    handle,
                    "rate_limited",
                    "Message rate limit reached. Try again shortly.",
                );
                return;
            }
            m.pending_resume = None;
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

        // Forward ONLY to currently connected sockets; NEVER buffer offline messages.
        // Because MlsCommit / JoinAccepted / SessionResumed frames are strictly FIFO-ordered ahead of
        // MlsMessage on each WebSocket, and Remove epochs enforce removal_barrier_epoch before any send,
        // every connected recipient processes the epoch transition before this ciphertext.
        let msg = RelayToClient::MlsMessage {
            sender_id: b.participant_id.clone(),
            epoch,
            message_id,
            ciphertext_b64,
        };
        room.broadcast_members(&msg, Some(&b.participant_id));
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_send_mls_commit(
        &self,
        conn_id: u64,
        handle: &OutboundHandle,
        binding: &Option<ConnBinding>,
        commit_id: String,
        expected_epoch: u64,
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
        if commit_id.is_empty() || commit_b64.is_empty() {
            send_err(handle, "invalid_commit", "Malformed MLS commit");
            return;
        }

        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            send_err(handle, "room_not_found", "Room no longer exists");
            return;
        };
        if now >= room.room_expires_at_ms {
            close_room_locked(&mut rooms, &b.room_id, "Room lifetime expired".into());
            send_err(handle, "room_expired", "Room has expired");
            return;
        }
        if !room.is_current_member_conn(&b.participant_id, conn_id) {
            send_err(handle, "stale_connection", "Connection has been superseded");
            handle.close();
            return;
        }
        if let Some(admin_m) = room.members.get_mut(&b.participant_id) {
            admin_m.pending_resume = None;
        }

        if expected_epoch != room.epoch || epoch != room.epoch.saturating_add(1) {
            send_err(
                handle,
                "epoch_mismatch",
                &format!(
                    "Commit transition {expected_epoch}->{epoch} does not match current room epoch {}",
                    room.epoch
                ),
            );
            return;
        }

        let is_removal = removed_participant_id.is_some();
        if let Some(ref removed_pid) = removed_participant_id {
            room.pending_removals.remove(removed_pid);
            if let Some(removed_member) = room.members.remove(removed_pid)
                && let MemberConn::Connected { handle: rh, .. } = removed_member.conn
            {
                rh.close();
            }
        }

        let prev_epoch = room.epoch;
        room.epoch = epoch;
        if is_removal {
            // Keep messaging paused until ALL connected remaining members acknowledge this new epoch!
            room.removal_barrier_epoch = room.removal_barrier_epoch.max(epoch);
        }
        room.record_commit(MissedCommit {
            commit_id: commit_id.clone(),
            sender_id: b.participant_id.clone(),
            prev_epoch,
            epoch,
            commit_b64: commit_b64.clone(),
        });

        let members = room.member_summaries();
        let paused = room.messaging_paused();

        // Confirm acceptance to Admin so Admin applies its staged pending commit locally and sends AckCommit.
        room.send_to_admin(&RelayToClient::CommitAccepted {
            commit_id: commit_id.clone(),
            prev_epoch,
            new_epoch: epoch,
            members: members.clone(),
            messaging_paused: paused,
        });

        let commit_msg = RelayToClient::MlsCommit {
            commit_id,
            sender_id: b.participant_id.clone(),
            prev_epoch,
            epoch,
            commit_b64,
            members,
            messaging_paused: paused,
        };
        room.broadcast_members(&commit_msg, Some(&b.participant_id));
    }

    async fn handle_explicit_leave(&self, conn_id: u64, binding: &mut Option<ConnBinding>) {
        let Some(b) = binding.take() else {
            return;
        };
        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            return;
        };

        // Explicit cancel of a pending reservation releases the slot back to Unused while the invite is still valid.
        if !room.members.contains_key(&b.participant_id) {
            if let Some(hash) = b.reservation_token_hash
                && let Some(inv) = room.invites.get_mut(&hash)
                && matches!(inv.state, InviteState::Reserved { guest_conn_id: Some(cid), .. } if cid == conn_id)
            {
                if now < inv.expires_at_ms {
                    inv.state = InviteState::Unused;
                } else {
                    room.invites.remove(&hash);
                }
                if room.connected_socket_count() == 0 && !room.should_hold_empty(now) {
                    rooms.remove(&b.room_id);
                }
            }
            return;
        }

        // Ignore LeaveRoom coming from an already-superseded socket generation.
        if !room.is_current_member_conn(&b.participant_id, conn_id) {
            return;
        }

        if b.role == ParticipantRole::Admin {
            // Section 6: Admin leaves explicitly -> Room ends immediately (even if invites are open)!
            close_room_locked(&mut rooms, &b.room_id, "Admin left the room".into());
            return;
        }

        // Guest leaves explicitly -> permanent removal -> pause messaging until Admin commits MLS Remove!
        room.members.remove(&b.participant_id);
        if room.connected_socket_count() == 0 && !room.should_hold_empty(now) {
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
        let now = self.current_time_ms();
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&b.room_id) else {
            return;
        };

        // Pending reservation disconnect: DO NOT discard the reservation or invite!
        // Keep the reservation alive until its fixed expiry so the browser can retry with the same nonce.
        // Never extend any room hold or admin resume deadline on guest disconnect.
        if !room.members.contains_key(&b.participant_id) {
            if let Some(ref hash) = b.reservation_token_hash
                && let Some(inv) = room.invites.get_mut(hash)
                && let InviteState::Reserved {
                    guest_conn_id,
                    guest_handle,
                    ..
                } = &mut inv.state
                && *guest_conn_id == Some(conn_id)
            {
                *guest_conn_id = None;
                *guest_handle = None;
                if room.connected_socket_count() == 0 && !room.should_hold_empty(now) {
                    rooms.remove(&b.room_id);
                }
            }
            return;
        }

        let mut was_active_conn = false;
        let was_paused = room.messaging_paused();
        let normal_deadline = now
            .saturating_add(self.config.reconnect_grace_secs.saturating_mul(1000))
            .min(room.room_expires_at_ms);
        if let Some(member) = room.members.get_mut(&b.participant_id)
            && matches!(member.conn, MemberConn::Connected { conn_id: cid, .. } if cid == conn_id)
        {
            was_active_conn = true;
            member.conn = MemberConn::Disconnected {
                deadline_ms: normal_deadline,
            };
        }

        if !was_active_conn {
            return;
        }

        // If Admin disconnected with any uncompleted Reserved invites, allow them to be
        // re-forwarded upon verified Admin resume (in case the previous socket was half-open).
        if b.role == ParticipantRole::Admin {
            for inv in room.invites.values_mut() {
                if let InviteState::Reserved {
                    forwarded_to_admin, ..
                } = &mut inv.state
                {
                    *forwarded_to_admin = false;
                }
            }
        }

        // When no admitted members remain connected (even if waiting guests are still attached):
        // - If a valid, unconsumed invite exists, hold the room in Relay RAM for up to
        //   `invite_hold_max_secs` (5 min), capped at the remaining invite validity and original room
        //   expiry, and use the exact same deadline for the admin's resume window.
        // - Never extend an already-established empty-room hold deadline.
        // - If no valid unconsumed invite exists, terminate the room immediately as before.
        if room.connected_member_count() == 0 {
            if let Some(max_invite_exp) = room.max_open_invite_expiry_ms(now) {
                let candidate_hold = now
                    .saturating_add(self.config.invite_hold_max_secs.saturating_mul(1000))
                    .min(max_invite_exp)
                    .min(room.room_expires_at_ms);

                let hold_deadline = match room.empty_hold_deadline_ms {
                    Some(existing) => existing.min(max_invite_exp).min(room.room_expires_at_ms),
                    None => candidate_hold,
                };

                let admin_alive = match room.members.get_mut(&room.admin_id) {
                    Some(admin) => match &mut admin.conn {
                        MemberConn::Disconnected { deadline_ms } if now < *deadline_ms => {
                            if room.empty_hold_deadline_ms.is_none() {
                                *deadline_ms = hold_deadline;
                            } else {
                                *deadline_ms = (*deadline_ms).min(hold_deadline);
                            }
                            now < *deadline_ms
                        }
                        _ => false,
                    },
                    None => false,
                };

                if admin_alive && now < hold_deadline {
                    room.empty_hold_deadline_ms = Some(hold_deadline);
                    info!(
                        room_id = %b.room_id,
                        hold_deadline_ms = hold_deadline,
                        waiting_guests = room.connected_socket_count(),
                        "last member disconnected with open invite; holding room in RAM for admin resume"
                    );
                    return;
                }
            }

            info!(room_id = %b.room_id, "last WebSocket disconnected; terminating room immediately");
            close_room_locked(
                &mut rooms,
                &b.room_id,
                "All participants disconnected".into(),
            );
            return;
        }

        // Otherwise, at least one other participant is still connected: hold slot for 60s.
        let members = room.member_summaries();
        let paused = room.messaging_paused();
        let _ = was_paused;
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

fn close_room_locked(rooms: &mut HashMap<String, Room>, room_id: &str, reason: String) {
    if let Some(room) = rooms.remove(room_id) {
        info!(room_id = %room_id, reason = %reason, "closing room");
        let msg = RelayToClient::RoomClosed {
            room_id: room_id.to_string(),
            reason,
        };
        for handle in room.all_connected_handles() {
            handle.try_send_msg(&msg);
            handle.close();
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn chat_send_budget_allows_a_burst_and_refills_gradually() {
        let mut budget = ChatSendBudget::new(1_000);
        for _ in 0..10 {
            assert!(budget.try_consume(1_000));
        }
        assert!(!budget.try_consume(1_000));
        assert!(!budget.try_consume(2_499));
        assert!(budget.try_consume(2_500));
        assert!(!budget.try_consume(2_500));
        for _ in 0..10 {
            assert!(budget.try_consume(62_500));
        }
        assert!(!budget.try_consume(62_500));
    }

    #[test]
    fn room_creation_limit_is_per_ip_and_uses_a_rolling_window() {
        let mut limiter = IpLimiter::new();
        let ip = "192.0.2.1".parse().unwrap();
        let other = "192.0.2.2".parse().unwrap();
        for now in 1_000..1_010 {
            assert!(limiter.try_record_room_creation(ip, now, 4));
        }
        limiter.release(ip, 1_010);
        assert!(!limiter.try_record_room_creation(ip, 60_999, 4));
        assert!(limiter.try_record_room_creation(other, 60_999, 4));
        assert!(limiter.try_record_room_creation(ip, 61_000, 4));
        assert!(!limiter.try_record_room_creation(ip, 61_000, 4));
    }

    #[test]
    fn ip_limiter_prunes_stale_keys_and_enforces_global_cap() {
        let cfg = RelayConfig {
            max_total_connections: 3,
            max_connections_per_ip: 2,
            max_connect_rate_per_ip_per_min: 5,
            max_tracked_ips: 4,
            ..Default::default()
        };
        let mut limiter = IpLimiter::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let ip4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let ip5 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

        assert!(limiter.try_acquire(ip1, 1000, &cfg));
        assert!(limiter.try_acquire(ip2, 1001, &cfg));
        assert!(limiter.try_acquire(ip3, 1002, &cfg));
        // Global cap of 3 reached.
        assert!(!limiter.try_acquire(ip4, 1003, &cfg));

        limiter.release(ip1, 1010);
        limiter.release(ip2, 1010);
        assert!(limiter.try_acquire(ip4, 1020, &cfg));
        limiter.release(ip4, 1025);
        // After 61s, stale keys are pruned and ip5 fits cleanly.
        limiter.prune_stale(70_000);
        assert_eq!(limiter.recent_attempts.len(), 0);
        assert!(limiter.try_acquire(ip5, 70_001, &cfg));
        assert_eq!(limiter.recent_attempts.len(), 1);
    }

    #[test]
    fn outbound_handle_signals_close_out_of_band_when_queue_is_full() {
        let (tx, _rx) = mpsc::channel::<OutboundSignal>(1);
        let (close_tx, close_rx) = watch::channel(false);
        let handle = OutboundHandle::new(tx, close_tx, 1024 * 1024);

        let ping_msg = RelayToClient::Pong { ts_ms: 1 };
        // First message fills the 1-slot channel.
        assert!(handle.try_send_msg(&ping_msg));
        assert!(!*close_rx.borrow());

        // Second message hits full channel -> MUST trigger out-of-band close signal immediately!
        assert!(!handle.try_send_msg(&ping_msg));
        assert!(*close_rx.borrow());
        assert!(handle.is_closed());
    }
}
