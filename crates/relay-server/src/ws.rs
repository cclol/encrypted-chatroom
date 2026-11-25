use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use core_crypto::protocol::{ClientToRelay, RelayToClient};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::config::RelayConfig;
use crate::state::{ConnBinding, OutboundHandle, OutboundSignal, RelayState};

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<RelayState>>,
) -> Response {
    // 1. Strict Origin validation on WebSocket HTTP handshake (Section 8).
    let Some(origin_val) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        warn!("rejected WebSocket handshake: missing Origin header");
        return (StatusCode::FORBIDDEN, "Missing Origin header").into_response();
    };
    if !state.config.is_origin_allowed(origin_val) {
        warn!(origin = %origin_val, "rejected WebSocket handshake: disallowed Origin");
        return (StatusCode::FORBIDDEN, "Origin not allowed").into_response();
    }

    // 2. Determine client IP ONLY honoring X-Forwarded-For from a verified trusted proxy chain.
    let client_ip = extract_client_ip(&headers, addr.ip(), &state.config);
    if !state.try_acquire_ip(client_ip) {
        warn!(ip = %client_ip, "rejected WebSocket handshake: IP/global connection limit exceeded");
        return (StatusCode::TOO_MANY_REQUESTS, "Connection limit exceeded").into_response();
    }

    let max_frame = state.config.max_frame_bytes;
    ws.max_message_size(max_frame)
        .max_frame_size(max_frame)
        .on_upgrade(move |socket| handle_socket(socket, state, client_ip))
}

/// Extracts the real client IP using right-to-left proxy chain walking.
/// If `peer_ip` is NOT in `config.trusted_proxy_cidrs`, `X-Forwarded-For` is ignored completely.
pub fn extract_client_ip(headers: &HeaderMap, peer_ip: IpAddr, config: &RelayConfig) -> IpAddr {
    if !config.is_trusted_proxy(peer_ip) {
        return peer_ip;
    }
    let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return peer_ip;
    };
    let parsed_chain: Vec<IpAddr> = xff
        .split(',')
        .filter_map(|part| part.trim().parse::<IpAddr>().ok())
        .collect();
    if parsed_chain.is_empty() {
        return peer_ip;
    }
    // Walk right-to-left (closest to our proxy first), skipping trusted proxy hops.
    for &ip in parsed_chain.iter().rev() {
        if !config.is_trusted_proxy(ip) {
            return ip;
        }
    }
    // All hops were trusted proxies; fall back to leftmost parsed hop.
    parsed_chain[0]
}

async fn wait_closed(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|&closed| closed).await;
}

async fn handle_socket(socket: WebSocket, state: Arc<RelayState>, client_ip: IpAddr) {
    let conn_id = state.next_conn_id();
    let (mut ws_sink, mut ws_stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<OutboundSignal>(state.config.max_outbound_queue);
    let (close_tx, mut writer_close_rx) = watch::channel(false);
    let mut reader_close_rx = close_tx.subscribe();
    let handle = OutboundHandle::new(
        tx,
        close_tx.clone(),
        state.config.max_outbound_bytes_per_min,
    );

    let keepalive_interval = Duration::from_secs(state.config.keepalive_interval_secs);
    let keepalive_timeout = Duration::from_secs(state.config.keepalive_timeout_secs);
    let write_timeout = Duration::from_secs(state.config.ws_write_timeout_secs);

    // Writer task: forwards outbound JSON frames and WebSocket-level keepalive Pings,
    // with bounded send timeouts and out-of-band abort signaling back to the reader.
    let writer_close_tx = close_tx.clone();
    let writer_task = tokio::spawn(async move {
        let mut ping_ticker = tokio::time::interval(keepalive_interval);
        ping_ticker.tick().await; // skip immediate tick
        loop {
            tokio::select! {
                biased;
                _ = wait_closed(&mut writer_close_rx) => {
                    // Best-effort bounded flush of up to 2 already-queued control frames (e.g. RoomClosed/Error)
                    // without ever stalling on a slow consumer.
                    for _ in 0..2 {
                        match rx.try_recv() {
                            Ok(OutboundSignal::Text(text)) => {
                                if !matches!(
                                    tokio::time::timeout(
                                        Duration::from_millis(150),
                                        ws_sink.send(Message::Text(text.into())),
                                    )
                                    .await,
                                    Ok(Ok(()))
                                ) {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = tokio::time::timeout(
                        Duration::from_millis(150),
                        ws_sink.send(Message::Close(None)),
                    )
                    .await;
                    break;
                }
                maybe_sig = rx.recv() => {
                    match maybe_sig {
                        Some(OutboundSignal::Text(text)) => {
                            let send_res = tokio::time::timeout(
                                write_timeout,
                                ws_sink.send(Message::Text(text.into())),
                            ).await;
                            if !matches!(send_res, Ok(Ok(()))) {
                                break;
                            }
                        }
                        None => {
                            let _ = tokio::time::timeout(
                                Duration::from_millis(500),
                                ws_sink.send(Message::Close(None)),
                            ).await;
                            break;
                        }
                    }
                }
                _ = ping_ticker.tick() => {
                    let ping_res = tokio::time::timeout(
                        write_timeout,
                        ws_sink.send(Message::Ping(Vec::new().into())),
                    ).await;
                    if !matches!(ping_res, Ok(Ok(()))) {
                        break;
                    }
                }
            }
        }
        // Always notify the reader loop immediately if the writer exits (e.g. write timeout or sink error).
        let _ = writer_close_tx.send(true);
    });

    // Reader loop with keep-alive liveness timeout, inbound rate/byte budgets, and out-of-band abort.
    let read_deadline = keepalive_interval + keepalive_timeout;
    let mut binding: Option<ConnBinding> = None;
    let mut in_window_start_ms = state.current_time_ms();
    let mut in_frames_in_window: usize = 0;
    let mut in_bytes_in_window: usize = 0;

    loop {
        let next_item = tokio::select! {
            biased;
            _ = wait_closed(&mut reader_close_rx) => {
                break;
            }
            item = tokio::time::timeout(read_deadline, ws_stream.next()) => item,
        };

        match next_item {
            Ok(Some(Ok(msg))) => match msg {
                Message::Text(text) => {
                    if text.len() > state.config.max_frame_bytes {
                        handle.close();
                        break;
                    }
                    let now = state.current_time_ms();
                    if now.saturating_sub(in_window_start_ms) >= 60_000 {
                        in_window_start_ms = now;
                        in_frames_in_window = 0;
                        in_bytes_in_window = 0;
                    }
                    in_frames_in_window = in_frames_in_window.saturating_add(1);
                    in_bytes_in_window = in_bytes_in_window.saturating_add(text.len());
                    if in_frames_in_window > state.config.max_inbound_frames_per_min
                        || in_bytes_in_window > state.config.max_inbound_bytes_per_min
                    {
                        handle.try_send_msg(&RelayToClient::Error {
                            code: "rate_limited".into(),
                            message: "Inbound rate or byte budget exceeded".into(),
                        });
                        handle.close();
                        break;
                    }

                    match serde_json::from_str::<ClientToRelay>(&text) {
                        Ok(parsed) => {
                            state
                                .handle_message(conn_id, client_ip, &handle, &mut binding, parsed)
                                .await;
                        }
                        Err(_) => {
                            handle.try_send_msg(&RelayToClient::Error {
                                code: "bad_frame".into(),
                                message: "Invalid protocol frame".into(),
                            });
                        }
                    }
                }
                Message::Ping(_) | Message::Pong(_) => {
                    // Liveness confirmed; loop resets timeout.
                }
                Message::Close(_) => break,
                Message::Binary(_) => {
                    handle.try_send_msg(&RelayToClient::Error {
                        code: "unsupported_frame".into(),
                        message: "Binary frames are not supported".into(),
                    });
                }
            },
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => {
                // Keep-alive liveness expired: declare socket dead.
                handle.close();
                break;
            }
        }
    }

    handle.close();
    let mut writer_task = writer_task;
    if tokio::time::timeout(Duration::from_millis(350), &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
    }
    state.handle_disconnect(conn_id, binding).await;
    state.release_ip(client_ip);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpCidr;

    #[test]
    fn ignores_xff_from_untrusted_peer_and_walks_trusted_proxy_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.2.3.4, 198.51.100.20, 10.0.0.5".parse().unwrap(),
        );

        // Default config has no trusted proxies -> spoofed XFF MUST be ignored.
        let default_cfg = RelayConfig::default();
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(extract_client_ip(&headers, peer, &default_cfg), peer);

        // When peer is inside trusted proxy CIDR (10.0.0.0/8), walk right-to-left skipping 10.0.0.5
        // and stop at the rightmost untrusted IP (198.51.100.20), ignoring attacker's spoofed 1.2.3.4!
        let proxy_cfg = RelayConfig {
            trusted_proxy_cidrs: vec![IpCidr::parse("10.0.0.0/8").unwrap()],
            ..Default::default()
        };
        let proxy_peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            extract_client_ip(&headers, proxy_peer, &proxy_cfg),
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
    }
}
