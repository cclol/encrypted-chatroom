use std::env;

use core_crypto::policy::RECONNECT_GRACE_SECS;

/// Runtime configuration for the Koyeb relay server.
///
/// The three parameters explicitly left configurable for the first commit (Section 10):
/// 1. `invite_ttl_secs` (`INVITE_TTL_SECS`)
/// 2. `keepalive_interval_secs` / `keepalive_timeout_secs` (`KEEPALIVE_INTERVAL_SECS`, `KEEPALIVE_TIMEOUT_SECS`)
/// 3. Concrete load limits (`MAX_CONCURRENT_ROOMS`, `MAX_CONNECTIONS_PER_IP`, `MAX_CONNECT_RATE_PER_IP_PER_MIN`,
///    `MAX_FRAME_BYTES`, `MAX_OUTBOUND_QUEUE`, `MAX_OUTBOUND_BYTES_PER_MIN`)
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind_addr: String,
    pub port: u16,
    /// Allowed production frontend origin checked on WebSocket HTTP handshake.
    pub allowed_origin: String,
    /// When true, also permits `http://localhost:*` and `http://127.0.0.1:*` origins for local development.
    pub allow_localhost_dev: bool,
    /// Configurable one-time invite link lifetime in seconds (always capped at room expiry).
    pub invite_ttl_secs: u64,
    /// Configurable WebSocket keep-alive ping interval in seconds (separate from the 60s reconnect window).
    pub keepalive_interval_secs: u64,
    /// Maximum seconds to wait for a pong before declaring a socket dead.
    pub keepalive_timeout_secs: u64,
    /// Reconnect grace window in seconds (fixed to 60s in production per Section 6).
    pub reconnect_grace_secs: u64,
    /// Maximum time a pending join reservation is held before timing out.
    pub join_reservation_ttl_secs: u64,
    /// Bounded delivery window in ms after PanicWipe before force-closing room sockets.
    pub wipe_delivery_grace_ms: u64,
    /// Load limit: maximum concurrent active rooms on this relay instance.
    pub max_concurrent_rooms: usize,
    /// Load limit: maximum simultaneous open WebSockets per client IP.
    pub max_connections_per_ip: usize,
    /// Load limit: maximum new WebSocket connection attempts per IP per 60 seconds.
    pub max_connect_rate_per_ip_per_min: usize,
    /// Load limit: maximum incoming WebSocket frame/message size in bytes.
    pub max_frame_bytes: usize,
    /// Load limit: bounded outbound queue depth per connected socket (slow consumers are dropped).
    pub max_outbound_queue: usize,
    /// Load limit: maximum outbound bytes per socket per 60 seconds.
    pub max_outbound_bytes_per_min: usize,
    /// Background timer sweep cadence in ms.
    pub sweep_interval_ms: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".into(),
            port: 8080,
            allowed_origin: "https://geistr.pages.dev".into(),
            allow_localhost_dev: false,
            invite_ttl_secs: 300,
            keepalive_interval_secs: 20,
            keepalive_timeout_secs: 15,
            reconnect_grace_secs: RECONNECT_GRACE_SECS,
            join_reservation_ttl_secs: 30,
            wipe_delivery_grace_ms: 400,
            max_concurrent_rooms: 256,
            max_connections_per_ip: 16,
            max_connect_rate_per_ip_per_min: 60,
            max_frame_bytes: 32 * 1024,
            max_outbound_queue: 64,
            max_outbound_bytes_per_min: 1024 * 1024,
            sweep_interval_ms: 500,
        }
    }
}

impl RelayConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = env::var("BIND_ADDR") {
            cfg.bind_addr = v;
        }
        if let Ok(v) = env::var("PORT")
            && let Ok(parsed) = v.parse()
        {
            cfg.port = parsed;
        }
        if let Ok(v) = env::var("ALLOWED_ORIGIN") {
            cfg.allowed_origin = v.trim_end_matches('/').to_string();
        }
        if let Ok(v) = env::var("ALLOW_LOCALHOST_DEV") {
            cfg.allow_localhost_dev =
                matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }
        cfg.invite_ttl_secs = parse_env_u64("INVITE_TTL_SECS", cfg.invite_ttl_secs).clamp(30, 3600);
        cfg.keepalive_interval_secs =
            parse_env_u64("KEEPALIVE_INTERVAL_SECS", cfg.keepalive_interval_secs).clamp(5, 120);
        cfg.keepalive_timeout_secs =
            parse_env_u64("KEEPALIVE_TIMEOUT_SECS", cfg.keepalive_timeout_secs).clamp(5, 60);
        cfg.max_concurrent_rooms =
            parse_env_usize("MAX_CONCURRENT_ROOMS", cfg.max_concurrent_rooms).max(1);
        cfg.max_connections_per_ip =
            parse_env_usize("MAX_CONNECTIONS_PER_IP", cfg.max_connections_per_ip).max(1);
        cfg.max_connect_rate_per_ip_per_min = parse_env_usize(
            "MAX_CONNECT_RATE_PER_IP_PER_MIN",
            cfg.max_connect_rate_per_ip_per_min,
        )
        .max(1);
        cfg.max_frame_bytes =
            parse_env_usize("MAX_FRAME_BYTES", cfg.max_frame_bytes).clamp(4096, 262_144);
        cfg.max_outbound_queue =
            parse_env_usize("MAX_OUTBOUND_QUEUE", cfg.max_outbound_queue).clamp(8, 512);
        cfg.max_outbound_bytes_per_min =
            parse_env_usize("MAX_OUTBOUND_BYTES_PER_MIN", cfg.max_outbound_bytes_per_min)
                .max(65_536);
        cfg
    }

    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        let normalized = origin.trim_end_matches('/');
        if normalized == self.allowed_origin.trim_end_matches('/') {
            return true;
        }
        if self.allow_localhost_dev {
            return is_localhost_origin(normalized);
        }
        false
    }
}

fn is_localhost_origin(origin: &str) -> bool {
    let rest = match origin.strip_prefix("http://") {
        Some(r) => r,
        None => return false,
    };
    let host = rest.split(':').next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1")
}

fn parse_env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}
