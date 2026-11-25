use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use core_crypto::protocol::ClientToRelay;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tracing::warn;

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

    // 2. Determine client IP (respecting X-Forwarded-For on Koyeb Edge if present) and enforce rate/conn limits.
    let client_ip = extract_client_ip(&headers, addr.ip());
    if !state.try_acquire_ip(client_ip) {
        warn!(ip = %client_ip, "rejected WebSocket handshake: IP rate or connection limit exceeded");
        return (StatusCode::TOO_MANY_REQUESTS, "Connection limit exceeded").into_response();
    }

    let max_frame = state.config.max_frame_bytes;
    ws.max_message_size(max_frame)
        .max_frame_size(max_frame)
        .on_upgrade(move |socket| handle_socket(socket, state, client_ip))
}

fn extract_client_ip(headers: &HeaderMap, peer_ip: IpAddr) -> IpAddr {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first) = xff.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return ip;
    }
    peer_ip
}

async fn handle_socket(socket: WebSocket, state: Arc<RelayState>, client_ip: IpAddr) {
    let conn_id = state.next_conn_id();
    let (mut ws_sink, mut ws_stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<OutboundSignal>(state.config.max_outbound_queue);
    let handle = OutboundHandle::new(tx, state.config.max_outbound_bytes_per_min);

    let keepalive_interval = Duration::from_secs(state.config.keepalive_interval_secs);
    let keepalive_timeout = Duration::from_secs(state.config.keepalive_timeout_secs);

    // Writer task: forwards outbound JSON frames and WebSocket-level keepalive Pings.
    let writer_task = tokio::spawn(async move {
        let mut ping_ticker = tokio::time::interval(keepalive_interval);
        ping_ticker.tick().await; // skip immediate tick
        loop {
            tokio::select! {
                maybe_sig = rx.recv() => {
                    match maybe_sig {
                        Some(OutboundSignal::Text(text)) => {
                            if ws_sink.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        Some(OutboundSignal::Close) | None => {
                            let _ = ws_sink.send(Message::Close(None)).await;
                            break;
                        }
                    }
                }
                _ = ping_ticker.tick() => {
                    if ws_sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Reader loop with keep-alive liveness timeout (separate from the 60s reconnect window).
    let read_deadline = keepalive_interval + keepalive_timeout;
    let mut binding: Option<ConnBinding> = None;

    loop {
        match tokio::time::timeout(read_deadline, ws_stream.next()).await {
            Ok(Some(Ok(msg))) => match msg {
                Message::Text(text) => {
                    if text.len() > state.config.max_frame_bytes {
                        handle.close();
                        break;
                    }
                    match serde_json::from_str::<ClientToRelay>(&text) {
                        Ok(parsed) => {
                            state
                                .handle_message(conn_id, &handle, &mut binding, parsed)
                                .await;
                        }
                        Err(_) => {
                            handle.try_send_msg(&core_crypto::protocol::RelayToClient::Error {
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
                    handle.try_send_msg(&core_crypto::protocol::RelayToClient::Error {
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

    writer_task.abort();
    state.handle_disconnect(conn_id, binding).await;
    state.release_ip(client_ip);
}
