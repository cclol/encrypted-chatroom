# encrypted-chatroom (`geistr`)

End-to-end encrypted zero-trace browser chat (Version 1) for up to four participants per room (1 admin + up to 3 guests), built on classical **MLS (RFC 9420)** via `mls-rs` and `mls-rs-crypto-rustcrypto`.

| Component | Name / Value |
|---|---|
| GitHub repository & Cargo workspace | `encrypted-chatroom` |
| Cloudflare Pages project | `geistr` |
| Planned production origin | `https://geistr.pages.dev` (configurable via `ALLOWED_ORIGIN`) |
| Relay hosting | Koyeb Free (Frankfurt), native Rust/Axum container (`Dockerfile`) |

## Architecture & Layout

```text
encrypted-chatroom/
├── Cargo.toml
├── .cargo/config.toml              # wasm32 getrandom_backend="wasm_js"
├── crates/
│   ├── core-crypto/                # MLS (RFC 9420), Ed25519 admin commands, padding classes, ephemeral RAM store, wire protocol
│   ├── web-client/                 # Rust/WASM Dedicated Web Worker (MLS, WSS, RAM history, lifetimes, reconnect/resume)
│   └── relay-server/               # Axum WSS relay (in-RAM room state, atomic join reservations, timers, hardening)
├── web/                            # Minimal HTML/CSS, vanilla JS entry, worker bootstrap, _headers (CSP)
├── .github/workflows/              # CI (fmt, clippy, tests, WASM build) & protected Pages deployment
└── Dockerfile                      # Native distroless relay container for Koyeb
```

## Security Model & Scope (Version 1)

- **Classical MLS (RFC 9420, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`)**: Version 1 does not include post-quantum protection.
- **Strict key separation**: MLS identity keys, admin command signing keys (Ed25519), per-message RAM history encryption keys (ChaCha20-Poly1305), and session resume tokens are generated and managed independently.
- **Ephemeral RAM-only history**: No `localStorage`, `sessionStorage`, `IndexedDB`, cookies, or Service Worker. Switching tabs/apps or locking the device immediately clears the visible DOM; upon return, deadlines and room membership are verified before decrypting and rendering still-valid entries.
- **Lifetimes**:
  - Messages: `5m`, `30m` (default), `1h` (shortening applies retroactively from each message's original start time; lengthening applies only to new messages).
  - Rooms: `5m`, `30m`, `1h` (default, hard maximum of 1 hour from creation).
  - Reconnect grace period: `60 seconds` while at least one other WebSocket remains open in the room. Disconnecting the last WebSocket terminates the room immediately.
- **Panic-Wipe**: Immediately hides the UI and wipes local RAM state; the relay locks the room, invalidates all invites and resume tokens, and returns a confirmation (explicitly noting that this does not certify deletion on remote devices).

## Configurable Parameters (First Commit)

The three operational parameters left configurable for the first commit are exposed via environment variables in `crates/relay-server/src/config.rs`:

| Parameter | Environment Variable | Default |
|---|---|---|
| One-time invite lifetime | `INVITE_TTL_SECS` | `300` (5 min, capped at room expiry) |
| Keep-alive interval / liveness timeout | `KEEPALIVE_INTERVAL_SECS` / `KEEPALIVE_TIMEOUT_SECS` | `20`s / `15`s (separate from 60s resume grace window) |
| Load limits | `MAX_CONCURRENT_ROOMS` | `256` |
| | `MAX_CONNECTIONS_PER_IP` | `16` |
| | `MAX_CONNECT_RATE_PER_IP_PER_MIN` | `60` |
| | `MAX_FRAME_BYTES` | `32768` (32 KiB) |
| | `MAX_OUTBOUND_QUEUE` | `64` frames per socket |
| | `MAX_OUTBOUND_BYTES_PER_MIN` | `1048576` (1 MiB/min per socket) |

## Local Build & Test

### 1. Run unit and integration tests

```bash
cargo test -p core-crypto -p relay-server -p web-client
```

### 2. Build the WASM worker bundle

```bash
cargo build --release --target wasm32-unknown-unknown -p web-client
wasm-bindgen --target web --no-typescript --out-dir web/pkg target/wasm32-unknown-unknown/release/web_client.wasm
```

### 3. Run the relay and static frontend locally

Terminal 1 (relay with local dev origin opt-in):

```bash
ALLOW_LOCALHOST_DEV=true PORT=8080 cargo run -p relay-server
```

Terminal 2 (static frontend):

```bash
python3 -m http.server 8000 --directory web
```

Open `http://127.0.0.1:8000` in your browser:
1. Optionally expand **Relay connection & browser MLS verification** and click **Run browser MLS self-test**.
2. Click **Create room** → **Generate one-time link** → open the link in a second browser tab → verify automatic join → exchange encrypted messages → close the room or trigger **Panic-Wipe**.

## Deployment

- **Relay (Koyeb Free, Frankfurt)**: Build/deploy `Dockerfile` and configure `ALLOWED_ORIGIN=https://geistr.pages.dev` (or the actual assigned Pages origin).
- **Frontend (Cloudflare Pages `geistr`)**: Trigger `.github/workflows/deploy-pages.yml` with the production Koyeb WSS URL (protected `production` GitHub Environment). The workflow injects the exact Koyeb origin into both `web/index.html` and the `connect-src` CSP directive in `web/_headers`.
