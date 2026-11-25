// Minimal vanilla JS browser entry, UI binding, visibility shield, and Worker bridge.
// All MLS cryptography, WebSocket protocol, ephemeral RAM history, and timers run in the Rust/WASM Worker.

const els = {
  statusLine: document.getElementById("status-line"),
  shieldView: document.getElementById("shield-view"),
  shieldReason: document.getElementById("shield-reason"),
  landingView: document.getElementById("landing-view"),
  pendingView: document.getElementById("pending-view"),
  pendingText: document.getElementById("pending-text"),
  chatView: document.getElementById("chat-view"),
  endedView: document.getElementById("ended-view"),
  endedTitle: document.getElementById("ended-title"),
  endedReason: document.getElementById("ended-reason"),
  errorToast: document.getElementById("error-toast"),
  createMsgTtl: document.getElementById("create-msg-ttl"),
  createRoomTtl: document.getElementById("create-room-ttl"),
  relayUrlInput: document.getElementById("relay-url-input"),
  btnCreateRoom: document.getElementById("btn-create-room"),
  btnMlsSelftest: document.getElementById("btn-mls-selftest"),
  selftestOutput: document.getElementById("selftest-output"),
  btnCancelJoin: document.getElementById("btn-cancel-join"),
  metaRoomId: document.getElementById("meta-room-id"),
  metaEpoch: document.getElementById("meta-epoch"),
  metaRoomCountdown: document.getElementById("meta-room-countdown"),
  metaMsgTtl: document.getElementById("meta-msg-ttl"),
  memberCount: document.getElementById("member-count"),
  memberList: document.getElementById("member-list"),
  adminControls: document.getElementById("admin-controls"),
  btnGenerateInvite: document.getElementById("btn-generate-invite"),
  btnPanicWipe: document.getElementById("btn-panic-wipe"),
  inviteOutputBox: document.getElementById("invite-output-box"),
  inviteLinkOutput: document.getElementById("invite-link-output"),
  btnCopyInvite: document.getElementById("btn-copy-invite"),
  liveMsgTtl: document.getElementById("live-msg-ttl"),
  liveRoomTtl: document.getElementById("live-room-ttl"),
  btnApplyPolicy: document.getElementById("btn-apply-policy"),
  btnLeaveRoom: document.getElementById("btn-leave-room"),
  pauseBanner: document.getElementById("pause-banner"),
  messageList: document.getElementById("message-list"),
  composerForm: document.getElementById("composer-form"),
  messageInput: document.getElementById("message-input"),
  btnSend: document.getElementById("btn-send"),
  btnRestart: document.getElementById("btn-restart"),
};

function defaultRelayUrl() {
  const host = window.location.hostname;
  if (host === "localhost" || host === "127.0.0.1") {
    return "ws://127.0.0.1:8080/ws";
  }
  const meta = document.querySelector('meta[name="geistr-relay-url"]');
  return meta ? meta.getAttribute("content") : "wss://geistr-relay.onrender.com/ws";
}

// Section 4: Read invite fragment early and immediately strip it from the visible URL.
function extractAndStripInviteFragment() {
  const rawHash = window.location.hash;
  if (!rawHash || rawHash.length < 2) return null;
  const params = new URLSearchParams(rawHash.slice(1));
  const roomId = params.get("r");
  const token = params.get("t");
  const fp = params.get("fp");
  const relayOverride = params.get("relay");
  // Remove fragment immediately so it does not linger in the address bar.
  window.history.replaceState(null, "", window.location.pathname);
  if (roomId && token && fp) {
    return { roomId, token, fp, relayOverride };
  }
  return null;
}

// Mutable so invite credentials are released immediately after handoff to the Worker (Finding 7).
let pendingInvite = extractAndStripInviteFragment();
els.relayUrlInput.value = (pendingInvite && pendingInvite.relayOverride) || defaultRelayUrl();

let currentState = {
  phase: "idle",
  role: null,
  roomExpiresAtMs: 0,
  messagingPaused: false,
};

// Monotonic visibility token ensures stale pre-hide render frames can NEVER flash on return (Finding 6).
let visibilityToken = 0;
let visibilityShieldLocked = false;
let countdownTimerId = null;

const worker = new Worker("./worker.js", { type: "module" });

function sendWorker(cmd) {
  worker.postMessage(JSON.stringify(cmd));
}

function clearVisibleMessagesDom() {
  while (els.messageList.firstChild) {
    els.messageList.removeChild(els.messageList.firstChild);
  }
  els.inviteLinkOutput.value = "";
  els.inviteOutputBox.classList.add("hidden");
}

function updateCountdownTimerState() {
  const shouldRun =
    currentState.phase === "active" && !document.hidden && !visibilityShieldLocked;
  if (shouldRun && countdownTimerId === null) {
    countdownTimerId = window.setInterval(tickCountdowns, 1000);
  } else if (!shouldRun && countdownTimerId !== null) {
    window.clearInterval(countdownTimerId);
    countdownTimerId = null;
  }
}

function tickCountdowns() {
  if (currentState.phase !== "active" || document.hidden || visibilityShieldLocked) {
    updateCountdownTimerState();
    return;
  }
  if (currentState.roomExpiresAtMs > 0) {
    els.metaRoomCountdown.textContent = formatCountdown(currentState.roomExpiresAtMs);
  }
  for (const node of els.messageList.querySelectorAll(".msg-exp")) {
    const ts = Number(node.dataset.expiresAt || "0");
    if (ts > 0) {
      node.textContent = formatCountdown(ts) + " left";
    }
  }
}

function showError(msg) {
  els.errorToast.textContent = msg;
  els.errorToast.classList.remove("hidden");
  window.setTimeout(() => {
    if (els.errorToast.textContent === msg) {
      els.errorToast.classList.add("hidden");
    }
  }, 7000);
}

function formatTtl(secs) {
  if (secs === 300) return "5m";
  if (secs === 1800) return "30m";
  if (secs === 3600) return "1h";
  return `${secs}s`;
}

function formatCountdown(targetMs) {
  const remainingSec = Math.max(0, Math.ceil((targetMs - Date.now()) / 1000));
  const m = Math.floor(remainingSec / 60);
  const s = remainingSec % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function showOnlyView(viewName) {
  els.shieldView.classList.toggle("hidden", viewName !== "shield");
  els.landingView.classList.toggle("hidden", viewName !== "landing");
  els.pendingView.classList.toggle("hidden", viewName !== "pending");
  els.chatView.classList.toggle("hidden", viewName !== "chat");
  els.endedView.classList.toggle("hidden", viewName !== "ended");
  updateCountdownTimerState();
}

function renderMembers(members, isAdmin) {
  els.memberCount.textContent = String(members.length);
  while (els.memberList.firstChild) {
    els.memberList.removeChild(els.memberList.firstChild);
  }
  for (const m of members) {
    const li = document.createElement("li");
    li.className = "member-chip";

    const dot = document.createElement("span");
    dot.className = "dot " + (m.connected ? "online" : "offline");
    li.appendChild(dot);

    const label = document.createElement("span");
    const roleLabel = m.role === "admin" ? "Admin" : "Guest";
    const statusLabel = m.connected ? "" : " (disconnected)";
    label.textContent = `${roleLabel} ${m.participant_id.slice(0, 6)}${statusLabel}`;
    li.appendChild(label);

    if (isAdmin && m.role === "guest") {
      const kickBtn = document.createElement("button");
      kickBtn.type = "button";
      kickBtn.className = "secondary small-btn";
      kickBtn.textContent = "Remove";
      kickBtn.addEventListener("click", () => {
        sendWorker({ type: "kick_guest", participant_id: m.participant_id });
      });
      li.appendChild(kickBtn);
    }
    els.memberList.appendChild(li);
  }
}

function buildMessageElement(m) {
  const li = document.createElement("li");
  li.className = "message-item " + (m.is_self ? "self" : "peer");
  li.dataset.messageId = m.message_id;

  const hdr = document.createElement("div");
  hdr.className = "msg-header";
  const who = document.createElement("span");
  who.textContent = m.is_self
    ? "You"
    : `${m.is_admin ? "Admin" : "Guest"} ${m.sender_id.slice(0, 6)}`;
  const exp = document.createElement("span");
  exp.className = "msg-exp mono";
  exp.dataset.expiresAt = String(m.expires_at_ms);
  exp.textContent = formatCountdown(m.expires_at_ms) + " left";
  hdr.appendChild(who);
  hdr.appendChild(exp);

  const body = document.createElement("p");
  body.className = "msg-text";
  body.textContent = m.text;

  li.appendChild(hdr);
  li.appendChild(body);
  return li;
}

function scrollMessagesToBottom() {
  const container = els.messageList.parentElement;
  if (container) container.scrollTop = container.scrollHeight;
}

function renderMessages(messages) {
  while (els.messageList.firstChild) {
    els.messageList.removeChild(els.messageList.firstChild);
  }
  const frag = document.createDocumentFragment();
  for (const m of messages) {
    frag.appendChild(buildMessageElement(m));
  }
  els.messageList.appendChild(frag);
  scrollMessagesToBottom();
}

function appendMessageIncremental(m) {
  if (!m || !m.message_id) return;
  for (const node of els.messageList.children) {
    if (node.dataset.messageId === m.message_id) return;
  }
  els.messageList.appendChild(buildMessageElement(m));
  scrollMessagesToBottom();
}

function removeMessagesIncremental(ids) {
  if (!ids || ids.length === 0) return;
  const idSet = new Set(ids);
  for (let node = els.messageList.firstChild; node; ) {
    const next = node.nextSibling;
    if (node.dataset && idSet.has(node.dataset.messageId)) {
      els.messageList.removeChild(node);
    }
    node = next;
  }
}

function canAcceptRenderMessage(msg) {
  return (
    !document.hidden &&
    !visibilityShieldLocked &&
    currentState.phase === "active" &&
    msg.visibility_token === visibilityToken
  );
}

worker.addEventListener("message", (ev) => {
  let msg;
  try {
    msg = JSON.parse(ev.data);
  } catch {
    return;
  }

  switch (msg.type) {
    case "worker_ready":
      els.statusLine.textContent = "Ready (WASM worker active)";
      if (pendingInvite) {
        const invite = pendingInvite;
        pendingInvite = null;
        sendWorker({
          type: "join_room",
          relay_url: els.relayUrlInput.value.trim(),
          room_id: invite.roomId,
          invite_token: invite.token,
          admin_fingerprint: invite.fp,
        });
        invite.roomId = null;
        invite.token = null;
        invite.fp = null;
        invite.relayOverride = null;
      }
      break;

    case "mls_selftest_result":
      if (msg.ok && msg.report) {
        els.selftestOutput.textContent = `OK (${msg.report.cipher_suite}, epochs 0->${msg.report.epoch_after_add}->${msg.report.epoch_after_remove}, removal isolated)`;
      } else {
        els.selftestOutput.textContent = "ERROR: " + (msg.error || "Unknown");
      }
      break;

    case "clear_display":
      clearVisibleMessagesDom();
      if (currentState.phase === "reconnecting" || document.hidden || visibilityShieldLocked) {
        els.shieldReason.textContent = msg.reason || "History hidden.";
        showOnlyView("shield");
      }
      break;

    case "visibility_verified":
      if (
        !document.hidden &&
        currentState.phase === "active" &&
        msg.visibility_token === visibilityToken
      ) {
        visibilityShieldLocked = false;
        showOnlyView("chat");
      }
      break;

    case "render_history":
      if (canAcceptRenderMessage(msg)) {
        renderMessages(msg.messages || []);
      }
      break;

    case "append_message":
      if (canAcceptRenderMessage(msg)) {
        appendMessageIncremental(msg.message);
      }
      break;

    case "remove_messages":
      if (canAcceptRenderMessage(msg)) {
        removeMessagesIncremental(msg.message_ids || []);
      }
      break;

    case "invite_ready": {
      // Section 1: Invite links ALWAYS use the actual assigned Pages origin.
      const base = `${window.location.origin}${window.location.pathname}`;
      const frag = new URLSearchParams({
        r: msg.room_id,
        t: msg.invite_token,
        fp: msg.admin_fingerprint,
      });
      els.inviteLinkOutput.value = `${base}#${frag.toString()}`;
      els.inviteOutputBox.classList.remove("hidden");
      break;
    }

    case "state_update":
      currentState = {
        phase: msg.phase,
        role: msg.role,
        roomExpiresAtMs: msg.room_expires_at_ms || 0,
        messagingPaused: Boolean(msg.messaging_paused),
      };
      els.statusLine.textContent = msg.status_text || msg.phase;

      if (msg.phase === "idle") {
        visibilityShieldLocked = false;
        clearVisibleMessagesDom();
        showOnlyView("landing");
      } else if (msg.phase === "connecting" || msg.phase === "pending_join") {
        visibilityShieldLocked = false;
        els.pendingText.textContent = msg.status_text;
        showOnlyView("pending");
      } else if (msg.phase === "reconnecting") {
        visibilityShieldLocked = true;
        clearVisibleMessagesDom();
        els.shieldReason.textContent = msg.status_text;
        showOnlyView("shield");
      } else if (msg.phase === "active") {
        const isAdmin = msg.role === "admin";
        els.metaRoomId.textContent = msg.room_id || "";
        els.metaEpoch.textContent = String(msg.epoch ?? 0);
        els.metaMsgTtl.textContent = formatTtl(msg.policy.msg_ttl_secs);
        els.metaRoomCountdown.textContent = formatCountdown(msg.room_expires_at_ms);
        els.liveMsgTtl.value = String(msg.policy.msg_ttl_secs);
        els.liveRoomTtl.value = String(msg.policy.room_ttl_secs);
        els.adminControls.classList.toggle("hidden", !isAdmin);
        els.pauseBanner.classList.toggle("hidden", !msg.messaging_paused);
        els.messageInput.disabled = Boolean(msg.messaging_paused);
        els.btnSend.disabled = Boolean(msg.messaging_paused);
        renderMembers(msg.members || [], isAdmin);
        if (document.hidden || visibilityShieldLocked) {
          clearVisibleMessagesDom();
          showOnlyView("shield");
        } else {
          showOnlyView("chat");
        }
      } else if (msg.phase === "wiped_local") {
        visibilityShieldLocked = false;
        clearVisibleMessagesDom();
        els.endedTitle.textContent = "Cleared locally (Panic-Wipe)";
        els.endedReason.textContent = msg.status_text;
        showOnlyView("ended");
      } else if (msg.phase === "wiped_confirmed") {
        visibilityShieldLocked = false;
        clearVisibleMessagesDom();
        els.endedTitle.textContent = "Room closure confirmed by relay";
        els.endedReason.textContent = msg.status_text;
        showOnlyView("ended");
      } else if (msg.phase === "wiped_unconfirmed") {
        visibilityShieldLocked = false;
        clearVisibleMessagesDom();
        els.endedTitle.textContent = "Cleared locally — room closure unconfirmed";
        els.endedReason.textContent = msg.status_text;
        showOnlyView("ended");
      } else if (msg.phase === "ended") {
        visibilityShieldLocked = false;
        clearVisibleMessagesDom();
        els.endedTitle.textContent = "Chat room ended";
        els.endedReason.textContent = msg.status_text;
        showOnlyView("ended");
      }
      break;

    case "error":
      showError(msg.message || msg.code);
      break;
  }
});

// Section 6: Immediately clear visible DOM & lock shield on tab switch / app switch / phone lock.
function handleVisibilityHidden() {
  visibilityToken += 1;
  if (currentState.phase === "active" || currentState.phase === "reconnecting") {
    visibilityShieldLocked = true;
    clearVisibleMessagesDom();
    els.messageInput.value = "";
    els.shieldReason.textContent =
      "Tab or app hidden. Deadlines, membership, and MLS epoch will be re-verified when you return.";
    showOnlyView("shield");
  }
  updateCountdownTimerState();
  sendWorker({ type: "ui_hidden" });
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    handleVisibilityHidden();
  } else {
    visibilityToken += 1;
    if (currentState.phase === "active" || currentState.phase === "reconnecting") {
      // Keep the shield UP and DOM empty until Worker confirms fresh relay verification!
      visibilityShieldLocked = true;
      clearVisibleMessagesDom();
      els.shieldReason.textContent =
        "Verifying room status, deadlines, and MLS epoch with relay...";
      showOnlyView("shield");
    }
    sendWorker({ type: "ui_visible", visibility_token: visibilityToken });
  }
});

window.addEventListener("pagehide", () => {
  handleVisibilityHidden();
});

// UI event handlers
els.btnCreateRoom.addEventListener("click", () => {
  sendWorker({
    type: "create_room",
    relay_url: els.relayUrlInput.value.trim(),
    msg_ttl_secs: Number(els.createMsgTtl.value),
    room_ttl_secs: Number(els.createRoomTtl.value),
  });
});

els.btnMlsSelftest.addEventListener("click", () => {
  els.selftestOutput.textContent = "Running...";
  sendWorker({ type: "run_mls_selftest" });
});

els.btnGenerateInvite.addEventListener("click", () => {
  sendWorker({ type: "generate_invite" });
});

els.btnCopyInvite.addEventListener("click", async () => {
  if (!els.inviteLinkOutput.value) return;
  try {
    await navigator.clipboard.writeText(els.inviteLinkOutput.value);
    els.btnCopyInvite.textContent = "Copied";
    window.setTimeout(() => {
      els.btnCopyInvite.textContent = "Copy";
    }, 1500);
  } catch {
    els.inviteLinkOutput.select();
  }
});

els.btnApplyPolicy.addEventListener("click", () => {
  sendWorker({
    type: "update_policy",
    msg_ttl_secs: Number(els.liveMsgTtl.value),
    room_ttl_secs: Number(els.liveRoomTtl.value),
  });
});

els.btnPanicWipe.addEventListener("click", () => {
  els.messageInput.value = "";
  clearVisibleMessagesDom();
  sendWorker({ type: "panic_wipe" });
});

els.btnLeaveRoom.addEventListener("click", () => {
  els.messageInput.value = "";
  clearVisibleMessagesDom();
  sendWorker({ type: "leave_room" });
});

els.btnCancelJoin.addEventListener("click", () => {
  sendWorker({ type: "leave_room" });
  showOnlyView("landing");
});

els.btnRestart.addEventListener("click", () => {
  clearVisibleMessagesDom();
  showOnlyView("landing");
  els.statusLine.textContent = "Ready (WASM worker active)";
});

els.composerForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const text = els.messageInput.value;
  if (!text.trim()) return;
  els.messageInput.value = "";
  sendWorker({ type: "send_message", text });
});
