use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use core_crypto::policy::RECONNECT_GRACE_SECS;

/// Simple IPv4/IPv6 CIDR matcher for verifying trusted reverse proxies before honoring `X-Forwarded-For`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpCidr {
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim();
        if s.is_empty() {
            return None;
        }
        if let Some((ip_part, prefix_part)) = s.split_once('/') {
            let ip: IpAddr = ip_part.trim().parse().ok()?;
            let prefix: u8 = prefix_part.trim().parse().ok()?;
            match ip {
                IpAddr::V4(v4) if prefix <= 32 => {
                    let mask = ipv4_mask(prefix);
                    Some(Self::V4 {
                        network: u32::from(v4) & mask,
                        prefix,
                    })
                }
                IpAddr::V6(v6) if prefix <= 128 => {
                    let mask = ipv6_mask(prefix);
                    Some(Self::V6 {
                        network: u128::from(v6) & mask,
                        prefix,
                    })
                }
                _ => None,
            }
        } else {
            let ip: IpAddr = s.parse().ok()?;
            Some(match ip {
                IpAddr::V4(v4) => Self::V4 {
                    network: u32::from(v4),
                    prefix: 32,
                },
                IpAddr::V6(v6) => Self::V6 {
                    network: u128::from(v6),
                    prefix: 128,
                },
            })
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpCidr::V4 { network, prefix }, IpAddr::V4(v4)) => {
                (u32::from(v4) & ipv4_mask(*prefix)) == *network
            }
            (IpCidr::V6 { network, prefix }, IpAddr::V6(v6)) => {
                (u128::from(v6) & ipv6_mask(*prefix)) == *network
            }
            // Also match IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) against IPv4 CIDRs.
            (IpCidr::V4 { network, prefix }, IpAddr::V6(v6)) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    (u32::from(v4) & ipv4_mask(*prefix)) == *network
                } else {
                    false
                }
            }
            (IpCidr::V6 { .. }, IpAddr::V4(_)) => false,
        }
    }

    pub fn from_v4(ip: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        Self::V4 {
            network: u32::from(ip) & ipv4_mask(prefix),
            prefix,
        }
    }

    pub fn from_v6(ip: Ipv6Addr, prefix: u8) -> Self {
        let prefix = prefix.min(128);
        Self::V6 {
            network: u128::from(ip) & ipv6_mask(prefix),
            prefix,
        }
    }
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Runtime configuration for the Koyeb relay server.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind_addr: String,
    pub port: u16,
    /// Allowed production frontend origin checked on WebSocket HTTP handshake.
    pub allowed_origin: String,
    /// When true, also permits `http://localhost:*` and `http://127.0.0.1:*` origins for local development.
    pub allow_localhost_dev: bool,
    /// Trusted reverse-proxy CIDRs allowed to supply `X-Forwarded-For`.
    /// Empty by default (fail-closed: `X-Forwarded-For` is ignored unless peer IP is trusted).
    pub trusted_proxy_cidrs: Vec<IpCidr>,
    /// Configurable one-time invite link lifetime in seconds (always capped at room expiry).
    pub invite_ttl_secs: u64,
    /// Configurable WebSocket keep-alive ping interval in seconds (separate from the 60s reconnect window).
    pub keepalive_interval_secs: u64,
    /// Maximum seconds to wait for a pong/frame before declaring a socket dead.
    pub keepalive_timeout_secs: u64,
    /// Maximum seconds a single WebSocket write/ping may block before disconnecting a slow consumer.
    pub ws_write_timeout_secs: u64,
    /// Reconnect grace window in seconds (fixed to 60s in production per Section 6).
    pub reconnect_grace_secs: u64,
    /// Maximum time a pending join reservation is held before timing out.
    pub join_reservation_ttl_secs: u64,
    /// Bounded delivery window in ms after PanicWipe before force-closing room sockets.
    pub wipe_delivery_grace_ms: u64,
    /// Load limit: maximum concurrent active rooms on this relay instance.
    pub max_concurrent_rooms: usize,
    /// Load limit: global cap on simultaneous open WebSocket connections across all IPs.
    pub max_total_connections: usize,
    /// Load limit: maximum simultaneous open WebSockets per client IP.
    pub max_connections_per_ip: usize,
    /// Load limit: maximum new WebSocket connection attempts per IP per 60 seconds.
    pub max_connect_rate_per_ip_per_min: usize,
    /// Load limit: hard upper bound on distinct IP keys tracked in the rate limiter.
    pub max_tracked_ips: usize,
    /// Load limit: maximum incoming WebSocket frame/message size in bytes.
    pub max_frame_bytes: usize,
    /// Load limit: maximum inbound protocol frames per socket per 60 seconds.
    pub max_inbound_frames_per_min: usize,
    /// Load limit: maximum inbound bytes per socket per 60 seconds.
    pub max_inbound_bytes_per_min: usize,
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
            trusted_proxy_cidrs: Vec::new(),
            invite_ttl_secs: 300,
            keepalive_interval_secs: 20,
            keepalive_timeout_secs: 15,
            ws_write_timeout_secs: 10,
            reconnect_grace_secs: RECONNECT_GRACE_SECS,
            join_reservation_ttl_secs: 30,
            wipe_delivery_grace_ms: 400,
            max_concurrent_rooms: 256,
            max_total_connections: 1024,
            max_connections_per_ip: 16,
            max_connect_rate_per_ip_per_min: 60,
            max_tracked_ips: 10_000,
            max_frame_bytes: 32 * 1024,
            max_inbound_frames_per_min: 300,
            max_inbound_bytes_per_min: 512 * 1024,
            max_outbound_queue: 64,
            max_outbound_bytes_per_min: 1024 * 1024,
            sweep_interval_ms: 1000,
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
        if let Ok(v) = env::var("TRUSTED_PROXY_CIDRS") {
            cfg.trusted_proxy_cidrs = v.split(',').filter_map(IpCidr::parse).collect();
        }
        cfg.invite_ttl_secs = parse_env_u64("INVITE_TTL_SECS", cfg.invite_ttl_secs).clamp(30, 3600);
        cfg.keepalive_interval_secs =
            parse_env_u64("KEEPALIVE_INTERVAL_SECS", cfg.keepalive_interval_secs).clamp(5, 120);
        cfg.keepalive_timeout_secs =
            parse_env_u64("KEEPALIVE_TIMEOUT_SECS", cfg.keepalive_timeout_secs).clamp(5, 60);
        cfg.ws_write_timeout_secs =
            parse_env_u64("WS_WRITE_TIMEOUT_SECS", cfg.ws_write_timeout_secs).clamp(2, 30);
        cfg.max_concurrent_rooms =
            parse_env_usize("MAX_CONCURRENT_ROOMS", cfg.max_concurrent_rooms).max(1);
        cfg.max_total_connections =
            parse_env_usize("MAX_TOTAL_CONNECTIONS", cfg.max_total_connections).max(4);
        cfg.max_connections_per_ip =
            parse_env_usize("MAX_CONNECTIONS_PER_IP", cfg.max_connections_per_ip).max(1);
        cfg.max_connect_rate_per_ip_per_min = parse_env_usize(
            "MAX_CONNECT_RATE_PER_IP_PER_MIN",
            cfg.max_connect_rate_per_ip_per_min,
        )
        .max(1);
        cfg.max_tracked_ips = parse_env_usize("MAX_TRACKED_IPS", cfg.max_tracked_ips).max(64);
        cfg.max_frame_bytes =
            parse_env_usize("MAX_FRAME_BYTES", cfg.max_frame_bytes).clamp(4096, 262_144);
        cfg.max_inbound_frames_per_min =
            parse_env_usize("MAX_INBOUND_FRAMES_PER_MIN", cfg.max_inbound_frames_per_min).max(10);
        cfg.max_inbound_bytes_per_min =
            parse_env_usize("MAX_INBOUND_BYTES_PER_MIN", cfg.max_inbound_bytes_per_min).max(16_384);
        cfg.max_outbound_queue =
            parse_env_usize("MAX_OUTBOUND_QUEUE", cfg.max_outbound_queue).clamp(8, 512);
        cfg.max_outbound_bytes_per_min =
            parse_env_usize("MAX_OUTBOUND_BYTES_PER_MIN", cfg.max_outbound_bytes_per_min)
                .max(65_536);
        cfg.sweep_interval_ms =
            parse_env_u64("SWEEP_INTERVAL_MS", cfg.sweep_interval_ms).clamp(50, 5000);
        cfg
    }

    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        let normalized = origin.trim_end_matches('/');
        if self
            .allowed_origin
            .split(',')
            .map(|entry| entry.trim().trim_end_matches('/'))
            .any(|entry| !entry.is_empty() && normalized == entry)
        {
            return true;
        }
        if self.allow_localhost_dev {
            return is_localhost_origin(normalized);
        }
        false
    }

    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted_proxy_cidrs
            .iter()
            .any(|cidr| cidr.contains(ip))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching_works_for_v4_v6_and_mapped() {
        let c4 = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(c4.contains("10.25.1.4".parse().unwrap()));
        assert!(!c4.contains("192.168.1.1".parse().unwrap()));
        assert!(c4.contains("::ffff:10.1.2.3".parse().unwrap()));

        let exact = IpCidr::parse("127.0.0.1").unwrap();
        assert!(exact.contains("127.0.0.1".parse().unwrap()));
        assert!(!exact.contains("127.0.0.2".parse().unwrap()));

        let c6 = IpCidr::parse("fd00::/8").unwrap();
        assert!(c6.contains("fd12:3456::1".parse().unwrap()));
        assert!(!c6.contains("2001:db8::1".parse().unwrap()));
    }
}
