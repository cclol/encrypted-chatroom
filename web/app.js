// Minimal vanilla JS browser entry, mobile viewport & scroll management, visibility shield, and Worker bridge.
// All MLS cryptography, WebSocket protocol, ephemeral RAM history, and timers run in the Rust/WASM Worker.

const els = {
  appTopbar: document.getElementById("app-topbar"),
  statusLine: document.getElementById("status-line"),
  unsupportedView: document.getElementById("unsupported-view"),
  unsupportedTitle: document.getElementById("unsupported-title"),
  unsupportedSummary: document.getElementById("unsupported-summary"),
  unsupportedNextStep: document.getElementById("unsupported-next-step"),
  unsupportedDetail: document.getElementById("unsupported-detail"),
  shieldView: document.getElementById("shield-view"),
  shieldBadge: document.getElementById("shield-badge"),
  shieldSpinner: document.getElementById("shield-spinner"),
  shieldTitle: document.getElementById("shield-title"),
  shieldReason: document.getElementById("shield-reason"),
  landingView: document.getElementById("landing-view"),
  pendingView: document.getElementById("pending-view"),
  pendingBadge: document.getElementById("pending-badge"),
  pendingTitle: document.getElementById("pending-title"),
  pendingText: document.getElementById("pending-text"),
  pendingSubhint: document.getElementById("pending-subhint"),
  chatView: document.getElementById("chat-view"),
  endedView: document.getElementById("ended-view"),
  endedBadge: document.getElementById("ended-badge"),
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
  btnRoomDrawer: document.getElementById("btn-room-drawer"),
  roomDrawer: document.getElementById("room-drawer"),
  chatStatusDot: document.getElementById("chat-status-dot"),
  metaRoomId: document.getElementById("meta-room-id"),
  metaEpoch: document.getElementById("meta-epoch"),
  metaRoomCountdown: document.getElementById("meta-room-countdown"),
  metaMsgTtl: document.getElementById("meta-msg-ttl"),
  metaMsgTtlPill: document.getElementById("meta-msg-ttl-pill"),
  memberCount: document.getElementById("member-count"),
  memberList: document.getElementById("member-list"),
  adminControls: document.getElementById("admin-controls"),
  adminWipeBar: document.getElementById("admin-wipe-bar"),
  btnGenerateInvite: document.getElementById("btn-generate-invite"),
  btnQuickInvite: document.getElementById("btn-quick-invite"),
  btnPanicWipe: document.getElementById("btn-panic-wipe"),
  inviteOutputBox: document.getElementById("invite-output-box"),
  inviteLinkOutput: document.getElementById("invite-link-output"),
  inviteValidityHint: document.getElementById("invite-validity-hint"),
  btnCopyInvite: document.getElementById("btn-copy-invite"),
  liveMsgTtl: document.getElementById("live-msg-ttl"),
  liveRoomTtl: document.getElementById("live-room-ttl"),
  btnApplyPolicy: document.getElementById("btn-apply-policy"),
  btnLeaveRoom: document.getElementById("btn-leave-room"),
  pauseBanner: document.getElementById("pause-banner"),
  messagesScroll: document.getElementById("messages-scroll"),
  emptyChatHint: document.getElementById("empty-chat-hint"),
  messageList: document.getElementById("message-list"),
  btnNewMessages: document.getElementById("btn-new-messages"),
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
    return { valid: true, roomId, token, fp, relayOverride };
  }
  if (roomId || token || fp) {
    return { valid: false };
  }
  return null;
}

function checkRuntimeSupport() {
  if (typeof Worker !== "function") {
    return { ok: false, reason: "Web Workers are not available in this browser." };
  }
  try {
    if (typeof WebAssembly !== "object" || typeof WebAssembly.instantiate !== "function") {
      return { ok: false, reason: "WebAssembly is disabled or unsupported." };
    }
    // Minimal 8-byte valid WASM module header to catch iPhone Lockdown Mode / JIT blocks synchronously.
    const probe = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const mod = new WebAssembly.Module(probe);
    if (!(mod instanceof WebAssembly.Module)) {
      return { ok: false, reason: "WebAssembly compilation is disabled." };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

// Detect if Safari/browser discarded and reloaded this tab while an admin session was active.
// Uses only an ephemeral, secret-free boolean in history.state (no persistent browser storage).
const hadUnloadedAdminSession = Boolean(
  window.history.state && window.history.state.geistrActiveAdminSession,
);

function setAdminTabMarker(active) {
  try {
    window.history.replaceState(
      active ? { geistrActiveAdminSession: true } : null,
      "",
      window.location.pathname,
    );
  } catch {
    // Ignore history state restrictions.
  }
}

// Mutable so invite credentials are released immediately after handoff to the Worker (Finding 7).
let pendingInvite = extractAndStripInviteFragment();
if (hadUnloadedAdminSession) {
  setAdminTabMarker(false);
}
const openedViaInvite = Boolean(pendingInvite && pendingInvite.valid);
els.relayUrlInput.value =
  (pendingInvite && pendingInvite.valid && pendingInvite.relayOverride) || defaultRelayUrl();

let currentState = {
  phase: "idle",
  role: null,
  roomExpiresAtMs: 0,
  messagingPaused: false,
  memberCount: 0,
};

// Monotonic visibility token ensures stale pre-hide render frames can NEVER flash on return (Finding 6).
let visibilityToken = 0;
let visibilityShieldLocked = false;
let countdownTimerId = null;
let worker = null;
let unreadWhileScrolledUp = 0;
let baseViewportHeight = window.innerHeight || 0;
let currentInviteExpiresAtMs = 0;
let inviteCopiedUntilMs = 0;

function clearPendingInviteMemory() {
  if (!pendingInvite) return;
  pendingInvite.roomId = null;
  pendingInvite.token = null;
  pendingInvite.fp = null;
  pendingInvite.relayOverride = null;
  pendingInvite = null;
}

function sendWorker(cmd) {
  if (!worker) return;
  worker.postMessage(JSON.stringify(cmd));
}

function setDrawerOpen(open) {
  const nextOpen = Boolean(open);
  els.roomDrawer.classList.toggle("hidden", !nextOpen);
  els.btnRoomDrawer.setAttribute("aria-expanded", nextOpen ? "true" : "false");
}

function updateEmptyChatHint() {
  const hasMessages = els.messageList.childElementCount > 0;
  els.emptyChatHint.classList.toggle("hidden", hasMessages);
  const showQuickInvite =
    !hasMessages && currentState.role === "admin" && currentState.memberCount <= 1;
  els.btnQuickInvite.classList.toggle("hidden", !showQuickInvite);
}

function updateInviteValidityHint() {
  if (!els.inviteValidityHint) return;
  if (!currentInviteExpiresAtMs || els.inviteOutputBox.classList.contains("hidden")) {
    els.inviteValidityHint.textContent = "";
    els.inviteValidityHint.className = "invite-validity-hint small muted";
    return;
  }
  const now = Date.now();
  if (now >= currentInviteExpiresAtMs) {
    els.inviteValidityHint.textContent = "Invite link expired — generate a new link.";
    els.inviteValidityHint.className = "invite-validity-hint small is-expired";
    return;
  }
  const remaining = formatCountdown(currentInviteExpiresAtMs);
  if (now < inviteCopiedUntilMs) {
    els.inviteValidityHint.textContent = `Copied — invite valid for ${remaining}. Return to this tab to admit your guest.`;
    els.inviteValidityHint.className = "invite-validity-hint small is-copied";
  } else {
    els.inviteValidityHint.textContent = `Invite valid for ${remaining}.`;
    els.inviteValidityHint.className = "invite-validity-hint small muted";
  }
}

function clearVisibleMessagesDom() {
  while (els.messageList.firstChild) {
    els.messageList.removeChild(els.messageList.firstChild);
  }
  els.inviteLinkOutput.value = "";
  els.inviteOutputBox.classList.add("hidden");
  currentInviteExpiresAtMs = 0;
  inviteCopiedUntilMs = 0;
  updateInviteValidityHint();
  unreadWhileScrolledUp = 0;
  els.btnNewMessages.classList.add("hidden");
  setDrawerOpen(false);
  updateEmptyChatHint();
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
  updateInviteValidityHint();
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
  const isChat = viewName === "chat";
  document.body.classList.toggle("in-chat", isChat);
  els.unsupportedView.classList.toggle("hidden", viewName !== "unsupported");
  els.shieldView.classList.toggle("hidden", viewName !== "shield");
  els.landingView.classList.toggle("hidden", viewName !== "landing");
  els.pendingView.classList.toggle("hidden", viewName !== "pending");
  els.chatView.classList.toggle("hidden", !isChat);
  els.endedView.classList.toggle("hidden", viewName !== "ended");
  syncVisualViewport();
  updateCountdownTimerState();
}

function showUnsupportedBrowser(reasonDetail) {
  clearPendingInviteMemory();
  clearVisibleMessagesDom();
  els.statusLine.textContent = "WebAssembly unavailable";
  if (openedViaInvite) {
    els.unsupportedNextStep.textContent =
      "Your one-time invite link was not consumed. Open the original invite link you received on another compatible device or browser (or allow WebAssembly for this site in Safari Website Settings if you intentionally choose to).";
  } else {
    els.unsupportedNextStep.textContent =
      "Open geistr in a browser with WebAssembly enabled, or use another compatible device. If you received an invite link, open the original link there.";
  }
  if (reasonDetail) {
    els.unsupportedDetail.textContent = `Technical detail: ${reasonDetail}`;
    els.unsupportedDetail.classList.remove("hidden");
  } else {
    els.unsupportedDetail.classList.add("hidden");
  }
  showOnlyView("unsupported");
}

function configureShieldView(kind, reasonText) {
  els.shieldView.dataset.shieldKind = kind;
  if (kind === "reconnecting") {
    els.shieldBadge.textContent = "Reconnecting";
    els.shieldBadge.className = "status-pill pill-warn";
    els.shieldSpinner.classList.remove("hidden");
    els.shieldTitle.textContent = "Connection interrupted";
    els.shieldReason.textContent =
      reasonText || "Attempting to reconnect. History stays hidden until verified.";
  } else if (kind === "verifying") {
    els.shieldBadge.textContent = "Verifying session";
    els.shieldBadge.className = "status-pill pill-accent";
    els.shieldSpinner.classList.remove("hidden");
    els.shieldTitle.textContent = "Checking room status…";
    els.shieldReason.textContent =
      reasonText || "Verifying room status, deadlines, and MLS epoch with the relay before showing messages.";
  } else {
    els.shieldBadge.textContent = "Session hidden";
    els.shieldBadge.className = "status-pill";
    els.shieldSpinner.classList.add("hidden");
    els.shieldTitle.textContent = "History hidden";
    els.shieldReason.textContent =
      reasonText || "Tab or app hidden. Deadlines, membership, and MLS epoch will be re-verified when you return.";
  }
}

function configurePendingView(mode, statusText) {
  if (mode === "waiting_admin") {
    els.pendingBadge.textContent = "Waiting for admin";
    els.pendingBadge.className = "status-pill pill-accent";
    els.pendingTitle.textContent = "Waiting for room admin…";
    els.pendingText.textContent =
      statusText || "Admission request sent. Waiting for the admin’s browser to admit you.";
    els.pendingSubhint.textContent =
      "Keep this tab open. Admission happens automatically once the admin responds and their cryptographic key is verified.";
  } else {
    els.pendingBadge.textContent = openedViaInvite ? "Opening invite link" : "Connecting";
    els.pendingBadge.className = "status-pill pill-accent";
    els.pendingTitle.textContent = openedViaInvite ? "Joining room…" : "Connecting to relay…";
    els.pendingText.textContent =
      statusText || "Starting end-to-end encryption and contacting the relay.";
    els.pendingSubhint.textContent =
      "No group keys are stored in the URL. Your device generates a fresh MLS KeyPackage automatically.";
  }
}

function configureEndedView(phase, statusText) {
  els.endedView.dataset.endedKind = phase;
  if (phase === "wiped_local") {
    els.endedBadge.textContent = "Cleared locally · Confirming";
    els.endedBadge.className = "status-pill pill-warn";
    els.endedTitle.textContent = "Cleared locally (Panic-Wipe)";
    els.endedReason.textContent =
      statusText || "Local RAM history wiped — waiting for relay room-closure confirmation…";
  } else if (phase === "wiped_confirmed") {
    els.endedBadge.textContent = "Room closure confirmed by relay";
    els.endedBadge.className = "status-pill pill-ok";
    els.endedTitle.textContent = "Room closed & confirmed by relay";
    els.endedReason.textContent = statusText;
  } else if (phase === "wiped_unconfirmed") {
    els.endedBadge.textContent = "Cleared locally · Relay unconfirmed";
    els.endedBadge.className = "status-pill pill-warn";
    els.endedTitle.textContent = "Cleared locally — room closure unconfirmed";
    els.endedReason.textContent = statusText;
  } else if (phase === "tab_unloaded") {
    els.endedBadge.textContent = "Admin session ended";
    els.endedBadge.className = "status-pill pill-warn";
    els.endedTitle.textContent = "Original admin session cannot be restored";
    els.endedReason.textContent =
      statusText ||
      "Safari or your browser unloaded this tab in the background and cleared its temporary RAM. Because encryption keys are never saved to storage, the original admin session cannot be restored and open invites can no longer be admitted from this tab. Start a new room to continue.";
  } else {
    els.endedBadge.textContent = "Room ended";
    els.endedBadge.className = "status-pill pill-danger";
    els.endedTitle.textContent = "Chat room ended";
    els.endedReason.textContent = statusText || "This ephemeral room has ended.";
  }
}

// ===== Mobile Virtual Keyboard & Visual Viewport Handling =====
function isNearBottom() {
  const el = els.messagesScroll;
  if (!el) return true;
  const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
  return distanceFromBottom <= 56;
}

function scrollMessagesToBottom() {
  const el = els.messagesScroll;
  if (!el) return;
  el.scrollTop = el.scrollHeight;
  unreadWhileScrolledUp = 0;
  els.btnNewMessages.classList.add("hidden");
}

function isTextInputFocused() {
  const el = document.activeElement;
  if (!el) return false;
  if (el === els.messageInput) return true;
  const tag = el.tagName;
  return (tag === "INPUT" || tag === "TEXTAREA") && !el.readOnly && !el.disabled;
}

function syncVisualViewport() {
  const vv = window.visualViewport;
  const height = vv ? Math.round(vv.height) : window.innerHeight;
  const offsetTop = vv ? Math.max(0, Math.round(vv.offsetTop)) : 0;
  const isZoomed = Boolean(vv && vv.scale > 1.05);
  const inputFocused = isTextInputFocused();
  const wasNearBottom = isNearBottom();

  if (!isZoomed && (!inputFocused || height > baseViewportHeight)) {
    baseViewportHeight = Math.max(window.innerHeight || 0, height);
  }

  document.documentElement.style.setProperty("--vvh", `${height}px`);
  document.documentElement.style.setProperty("--vv-offset-top", `${offsetTop}px`);

  const referenceHeight = Math.max(window.innerHeight || 0, baseViewportHeight);
  const heightDrop = referenceHeight - height;
  const keyboardLikelyOpen =
    !isZoomed &&
    inputFocused &&
    referenceHeight > 0 &&
    heightDrop >= 120 &&
    height < referenceHeight * 0.85;
  document.body.classList.toggle("keyboard-open", keyboardLikelyOpen);

  if (document.body.classList.contains("in-chat") && wasNearBottom) {
    window.requestAnimationFrame(scrollMessagesToBottom);
  }
}

if (window.visualViewport) {
  window.visualViewport.addEventListener("resize", syncVisualViewport);
  window.visualViewport.addEventListener("scroll", syncVisualViewport);
}
window.addEventListener("resize", () => {
  baseViewportHeight = window.innerHeight || baseViewportHeight;
  syncVisualViewport();
});
window.addEventListener("orientationchange", () => {
  window.setTimeout(() => {
    baseViewportHeight = window.innerHeight || baseViewportHeight;
    syncVisualViewport();
  }, 150);
});
syncVisualViewport();

els.messagesScroll.addEventListener(
  "scroll",
  () => {
    if (isNearBottom() && unreadWhileScrolledUp > 0) {
      unreadWhileScrolledUp = 0;
      els.btnNewMessages.classList.add("hidden");
    }
  },
  { passive: true },
);

els.btnNewMessages.addEventListener("click", () => {
  scrollMessagesToBottom();
});

els.messageInput.addEventListener("focus", () => {
  const wasAtBottom = isNearBottom();
  setDrawerOpen(false);
  window.setTimeout(() => {
    syncVisualViewport();
    if (wasAtBottom) {
      scrollMessagesToBottom();
    }
  }, 180);
});

els.messageInput.addEventListener("click", () => {
  if (!els.roomDrawer.classList.contains("hidden")) {
    setDrawerOpen(false);
  }
});

els.messageInput.addEventListener("blur", () => {
  window.setTimeout(syncVisualViewport, 120);
});

// ===== Rendering =====
function renderMembers(members, isAdmin) {
  els.memberCount.textContent = String(members.length);
  while (els.memberList.firstChild) {
    els.memberList.removeChild(els.memberList.firstChild);
  }
  for (const m of members) {
    const li = document.createElement("li");
    li.className = "member-chip";

    const info = document.createElement("span");
    info.className = "member-chip-info";

    const dot = document.createElement("span");
    dot.className = "dot " + (m.connected ? "online" : "offline");
    info.appendChild(dot);

    const label = document.createElement("span");
    const roleLabel = m.role === "admin" ? "Admin" : "Guest";
    const statusLabel = m.connected ? "" : " (reconnecting)";
    label.textContent = `${roleLabel} ${m.participant_id.slice(0, 6)}${statusLabel}`;
    info.appendChild(label);
    li.appendChild(info);

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

function renderMessages(messages) {
  while (els.messageList.firstChild) {
    els.messageList.removeChild(els.messageList.firstChild);
  }
  const frag = document.createDocumentFragment();
  for (const m of messages) {
    frag.appendChild(buildMessageElement(m));
  }
  els.messageList.appendChild(frag);
  updateEmptyChatHint();
  scrollMessagesToBottom();
}

function appendMessageIncremental(m) {
  if (!m || !m.message_id) return;
  for (const node of els.messageList.children) {
    if (node.dataset.messageId === m.message_id) return;
  }
  // Check scroll position BEFORE inserting new DOM node so reading older history is respected!
  const shouldAutoScroll = Boolean(m.is_self) || isNearBottom();
  els.messageList.appendChild(buildMessageElement(m));
  updateEmptyChatHint();
  if (shouldAutoScroll) {
    scrollMessagesToBottom();
  } else {
    unreadWhileScrolledUp += 1;
    els.btnNewMessages.textContent =
      unreadWhileScrolledUp === 1 ? "New message ↓" : `${unreadWhileScrolledUp} new messages ↓`;
    els.btnNewMessages.classList.remove("hidden");
  }
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
  updateEmptyChatHint();
}

function canAcceptRenderMessage(msg) {
  return (
    !document.hidden &&
    !visibilityShieldLocked &&
    currentState.phase === "active" &&
    msg.visibility_token === visibilityToken
  );
}

// ===== Pre-flight WebAssembly Check & Immediate Invite Feedback =====
const runtimeSupport = checkRuntimeSupport();

if (!runtimeSupport.ok) {
  showUnsupportedBrowser(runtimeSupport.reason);
} else {
  // Show join progress IMMEDIATELY when opened via an invite link (never flash Create Room!).
  if (pendingInvite && pendingInvite.valid) {
    configurePendingView(
      "connecting",
      "Opening invite link — initializing end-to-end encryption…",
    );
    showOnlyView("pending");
  } else if (pendingInvite && !pendingInvite.valid) {
    clearPendingInviteMemory();
    configureEndedView(
      "ended",
      "This invite link is incomplete or corrupted. Please ask the room admin for a fresh one-time invite link.",
    );
    showOnlyView("ended");
  } else if (hadUnloadedAdminSession) {
    configureEndedView("tab_unloaded");
    showOnlyView("ended");
  }

  try {
    worker = new Worker("./worker.js", { type: "module" });
  } catch (err) {
    showUnsupportedBrowser(err instanceof Error ? err.message : String(err));
  }
}

if (worker) {
  worker.addEventListener("error", (ev) => {
    const detail = ev && ev.message ? ev.message : "Worker failed to initialize.";
    if (currentState.phase === "idle" || currentState.phase === "connecting" || openedViaInvite) {
      showUnsupportedBrowser(detail);
    } else {
      showError(detail);
    }
  });

  worker.addEventListener("message", (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }

    switch (msg.type) {
      case "worker_ready":
        els.statusLine.textContent = "Ready (WASM encryption active)";
        if (pendingInvite && pendingInvite.valid) {
          const invite = pendingInvite;
          pendingInvite = null;
          configurePendingView("connecting", "Connecting to relay with your one-time invite…");
          showOnlyView("pending");
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
          configureShieldView(
            currentState.phase === "reconnecting" ? "reconnecting" : "hidden",
            msg.reason || "History hidden.",
          );
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
        currentInviteExpiresAtMs = msg.expires_at_ms || 0;
        inviteCopiedUntilMs = 0;
        els.inviteOutputBox.classList.remove("hidden");
        updateInviteValidityHint();
        setDrawerOpen(true);
        break;
      }

      case "state_update": {
        const members = msg.members || [];
        currentState = {
          phase: msg.phase,
          role: msg.role,
          roomExpiresAtMs: msg.room_expires_at_ms || 0,
          messagingPaused: Boolean(msg.messaging_paused),
          memberCount: members.length,
        };
        els.statusLine.textContent = msg.status_text || msg.phase;

        if (msg.phase === "idle") {
          setAdminTabMarker(false);
          visibilityShieldLocked = false;
          clearVisibleMessagesDom();
          showOnlyView("landing");
        } else if (msg.phase === "connecting") {
          visibilityShieldLocked = false;
          configurePendingView("connecting", msg.status_text);
          showOnlyView("pending");
        } else if (msg.phase === "pending_join") {
          visibilityShieldLocked = false;
          configurePendingView("waiting_admin", msg.status_text);
          showOnlyView("pending");
        } else if (msg.phase === "reconnecting") {
          visibilityShieldLocked = true;
          clearVisibleMessagesDom();
          configureShieldView("reconnecting", msg.status_text);
          showOnlyView("shield");
        } else if (msg.phase === "active") {
          const isAdmin = msg.role === "admin";
          setAdminTabMarker(isAdmin);
          if (currentInviteExpiresAtMs > 0 && msg.room_expires_at_ms > 0) {
            currentInviteExpiresAtMs = Math.min(currentInviteExpiresAtMs, msg.room_expires_at_ms);
            updateInviteValidityHint();
          }
          const ttlLabel = formatTtl(msg.policy.msg_ttl_secs);
          els.metaRoomId.textContent = msg.room_id || "";
          els.metaEpoch.textContent = String(msg.epoch ?? 0);
          els.metaMsgTtl.textContent = ttlLabel;
          els.metaMsgTtlPill.textContent = ttlLabel;
          els.metaRoomCountdown.textContent = formatCountdown(msg.room_expires_at_ms);
          els.liveMsgTtl.value = String(msg.policy.msg_ttl_secs);
          els.liveRoomTtl.value = String(msg.policy.room_ttl_secs);
          els.adminControls.classList.toggle("hidden", !isAdmin);
          els.adminWipeBar.classList.toggle("hidden", !isAdmin);
          els.pauseBanner.classList.toggle("hidden", !msg.messaging_paused);
          els.chatStatusDot.className =
            "status-dot " + (msg.messaging_paused ? "paused" : "online");
          els.messageInput.disabled = Boolean(msg.messaging_paused);
          els.btnSend.disabled = Boolean(msg.messaging_paused);
          renderMembers(members, isAdmin);
          updateEmptyChatHint();
          if (document.hidden || visibilityShieldLocked) {
            clearVisibleMessagesDom();
            configureShieldView(document.hidden ? "hidden" : "verifying");
            showOnlyView("shield");
          } else {
            showOnlyView("chat");
          }
        } else if (
          msg.phase === "wiped_local" ||
          msg.phase === "wiped_confirmed" ||
          msg.phase === "wiped_unconfirmed" ||
          msg.phase === "ended"
        ) {
          setAdminTabMarker(false);
          visibilityShieldLocked = false;
          clearVisibleMessagesDom();
          configureEndedView(msg.phase, msg.status_text);
          showOnlyView("ended");
        }
        break;
      }

      case "error":
        if (msg.code === "wasm_boot_failed" || msg.code === "wasm_unavailable") {
          showUnsupportedBrowser(msg.message || msg.code);
        } else {
          showError(msg.message || msg.code);
        }
        break;
    }
  });
}

// Section 6: Immediately clear visible DOM & lock shield on tab switch / app switch / phone lock.
function handleVisibilityHidden() {
  visibilityToken += 1;
  if (currentState.phase === "active" || currentState.phase === "reconnecting") {
    visibilityShieldLocked = true;
    clearVisibleMessagesDom();
    els.messageInput.value = "";
    configureShieldView(
      currentState.phase === "reconnecting" ? "reconnecting" : "hidden",
      "Tab or app hidden. Deadlines, membership, and MLS epoch will be re-verified when you return.",
    );
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
      configureShieldView(
        currentState.phase === "reconnecting" ? "reconnecting" : "verifying",
        currentState.phase === "reconnecting"
          ? "Connection interrupted — attempting to reconnect…"
          : "Verifying room status, deadlines, and MLS epoch with relay…",
      );
      showOnlyView("shield");
    }
    sendWorker({ type: "ui_visible", visibility_token: visibilityToken });
  }
});

window.addEventListener("pagehide", () => {
  handleVisibilityHidden();
});

// ===== UI Event Handlers =====
els.btnRoomDrawer.addEventListener("click", () => {
  const isOpen = !els.roomDrawer.classList.contains("hidden");
  setDrawerOpen(!isOpen);
});

els.btnCreateRoom.addEventListener("click", () => {
  sendWorker({
    type: "create_room",
    relay_url: els.relayUrlInput.value.trim(),
    msg_ttl_secs: Number(els.createMsgTtl.value),
    room_ttl_secs: Number(els.createRoomTtl.value),
  });
});

els.btnMlsSelftest.addEventListener("click", () => {
  els.selftestOutput.textContent = "Running…";
  sendWorker({ type: "run_mls_selftest" });
});

els.btnGenerateInvite.addEventListener("click", () => {
  sendWorker({ type: "generate_invite" });
});

els.btnQuickInvite.addEventListener("click", () => {
  setDrawerOpen(true);
  sendWorker({ type: "generate_invite" });
});

els.btnCopyInvite.addEventListener("click", async () => {
  if (!els.inviteLinkOutput.value) return;
  try {
    await navigator.clipboard.writeText(els.inviteLinkOutput.value);
    const remaining =
      currentInviteExpiresAtMs > Date.now()
        ? formatCountdown(currentInviteExpiresAtMs)
        : null;
    els.btnCopyInvite.textContent = remaining ? `Copied (${remaining})` : "Copied";
    inviteCopiedUntilMs = Date.now() + 8000;
    updateInviteValidityHint();
    window.setTimeout(() => {
      els.btnCopyInvite.textContent = "Copy";
    }, 2500);
  } catch {
    els.inviteLinkOutput.select();
    inviteCopiedUntilMs = Date.now() + 8000;
    updateInviteValidityHint();
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
  setAdminTabMarker(false);
  els.messageInput.value = "";
  clearVisibleMessagesDom();
  sendWorker({ type: "panic_wipe" });
});

els.btnLeaveRoom.addEventListener("click", () => {
  setAdminTabMarker(false);
  els.messageInput.value = "";
  clearVisibleMessagesDom();
  sendWorker({ type: "leave_room" });
});

els.btnCancelJoin.addEventListener("click", () => {
  clearPendingInviteMemory();
  sendWorker({ type: "leave_room" });
  showOnlyView("landing");
});

els.btnRestart.addEventListener("click", () => {
  setAdminTabMarker(false);
  clearVisibleMessagesDom();
  showOnlyView("landing");
  els.statusLine.textContent = "Ready (WASM encryption active)";
});

els.composerForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const text = els.messageInput.value;
  if (!text.trim()) return;
  els.messageInput.value = "";
  sendWorker({ type: "send_message", text });
  // Keep focus for smooth continuous mobile typing without dismissing keyboard.
  els.messageInput.focus();
});
