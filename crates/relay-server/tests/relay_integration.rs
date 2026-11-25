use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use core_crypto::admin::{AdminCommandPayload, AdminSigningKey, compute_admin_fingerprint};
use core_crypto::mls::{MlsIncomingEvent, MlsSession};
use core_crypto::policy::RoomPolicy;
use core_crypto::protocol::{ChatAppPayload, ClientToRelay, RelayToClient};
use core_crypto::{random_token_b64url, sha256_hex};
use futures_util::{SinkExt, StreamExt};
use relay_server::build_router;
use relay_server::config::RelayConfig;
use relay_server::state::RelayState;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn spawn_test_relay(mut config: RelayConfig) -> (String, std::sync::Arc<RelayState>) {
    config.allowed_origin = "https://geistr.pages.dev".into();
    config.sweep_interval_ms = 50;
    config.wipe_delivery_grace_ms = 100;
    let state = RelayState::new(config);
    state.spawn_sweeper();
    let app = build_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("ws://{addr}/ws"), state)
}

#[allow(clippy::result_large_err)]
async fn connect_ws(
    url: &str,
    origin: &str,
) -> Result<WsStream, tokio_tungstenite::tungstenite::Error> {
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("Origin", origin.parse().unwrap());
    let (ws, _) = tokio_tungstenite::connect_async(req).await?;
    Ok(ws)
}

async fn send_msg(ws: &mut WsStream, msg: &ClientToRelay) {
    let text = serde_json::to_string(msg).unwrap();
    ws.send(Message::Text(text.into())).await.unwrap();
}

async fn recv_msg(ws: &mut WsStream) -> RelayToClient {
    let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("timed out waiting for relay frame")
        .expect("socket ended unexpectedly")
        .expect("ws read error");
    match frame {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("unexpected ws frame: {other:?}"),
    }
}

async fn create_initialized_room(
    url: &str,
) -> (
    WsStream,
    String,
    String,
    String,
    AdminSigningKey,
    MlsSession,
) {
    let mut admin_ws = connect_ws(url, "https://geistr.pages.dev").await.unwrap();
    let mut admin_key = AdminSigningKey::generate("pending").unwrap();
    let policy = RoomPolicy::default();

    send_msg(
        &mut admin_ws,
        &ClientToRelay::CreateRoom {
            admin_pubkey_b64: admin_key.verifying_key_b64(),
            initial_policy: policy,
        },
    )
    .await;

    let (room_id, admin_id, resume_token) = match recv_msg(&mut admin_ws).await {
        RelayToClient::RoomCreated {
            room_id,
            participant_id,
            resume_token,
            ..
        } => (room_id, participant_id, resume_token),
        other => panic!("expected RoomCreated, got {other:?}"),
    };

    admin_key.rebind_room(&room_id);
    let init_policy_cmd = admin_key
        .sign_command(
            0,
            AdminCommandPayload::SetPolicy {
                msg_ttl_secs: policy.msg_ttl_secs,
                room_ttl_secs: policy.room_ttl_secs,
            },
        )
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AdminCommand {
            signed_cmd: init_policy_cmd,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::PolicyUpdated { .. }
    ));

    let mut admin_mls =
        MlsSession::new(&room_id, &admin_id, true, Some(admin_key.fingerprint())).unwrap();
    admin_mls.create_group().unwrap();

    (
        admin_ws,
        room_id,
        admin_id,
        resume_token,
        admin_key,
        admin_mls,
    )
}

async fn register_invite(
    admin_ws: &mut WsStream,
    admin_key: &mut AdminSigningKey,
    epoch: u64,
) -> String {
    let token = random_token_b64url(24).unwrap();
    let token_hash_hex = sha256_hex(token.as_bytes());
    let cmd = admin_key
        .sign_command(
            epoch,
            AdminCommandPayload::RegisterInvite {
                token_hash_hex,
                invite_ttl_secs: 300,
            },
        )
        .unwrap();
    send_msg(admin_ws, &ClientToRelay::AdminCommand { signed_cmd: cmd }).await;
    assert!(matches!(
        recv_msg(admin_ws).await,
        RelayToClient::InviteRegistered { .. }
    ));
    token
}

async fn admit_guest(
    url: &str,
    room_id: &str,
    invite_token: &str,
    admin_fp: &str,
    admin_ws: &mut WsStream,
    admin_mls: &mut MlsSession,
) -> (WsStream, String, String, MlsSession) {
    let mut guest_ws = connect_ws(url, "https://geistr.pages.dev").await.unwrap();
    let provisional_id = random_token_b64url(6).unwrap();
    let mut guest_mls = MlsSession::new(room_id, &provisional_id, false, None).unwrap();
    let kp = guest_mls.generate_key_package().unwrap();

    send_msg(
        &mut guest_ws,
        &ClientToRelay::JoinRoom {
            room_id: room_id.into(),
            invite_token: invite_token.into(),
            key_package_b64: STANDARD.encode(&kp),
            client_join_nonce: random_token_b64url(12).unwrap(),
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut guest_ws).await,
        RelayToClient::JoinPending { .. }
    ));

    // Admin receives GuestJoinRequest and admits automatically.
    let (reservation_id, guest_id, kp_b64) = match recv_msg(admin_ws).await {
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => (reservation_id, guest_id, key_package_b64),
        other => panic!("expected GuestJoinRequest, got {other:?}"),
    };

    let kp_bytes = STANDARD.decode(&kp_b64).unwrap();
    let add_out = admin_mls.add_member(&kp_bytes).unwrap();

    send_msg(
        admin_ws,
        &ClientToRelay::CompleteJoin {
            reservation_id,
            guest_id: guest_id.clone(),
            commit_b64: STANDARD.encode(&add_out.commit_bytes),
            welcome_b64: STANDARD.encode(&add_out.welcome_bytes),
            new_epoch: add_out.new_epoch,
        },
    )
    .await;

    // Admin gets MemberStatus.
    assert!(matches!(
        recv_msg(admin_ws).await,
        RelayToClient::MemberStatus { .. }
    ));

    // Guest gets JoinAccepted and joins MLS group + verifies admin fingerprint.
    let (accepted_id, resume_token, welcome_b64, admin_pubkey_b64) =
        match recv_msg(&mut guest_ws).await {
            RelayToClient::JoinAccepted {
                participant_id,
                resume_token,
                welcome_b64,
                admin_pubkey_b64,
                ..
            } => (participant_id, resume_token, welcome_b64, admin_pubkey_b64),
            other => panic!("expected JoinAccepted, got {other:?}"),
        };
    assert_eq!(accepted_id, guest_id);
    let pk = core_crypto::admin::decode_pubkey_b64(&admin_pubkey_b64).unwrap();
    assert_eq!(compute_admin_fingerprint(&pk, room_id), admin_fp);

    let welcome_bytes = STANDARD.decode(&welcome_b64).unwrap();
    guest_mls
        .join_from_welcome(&welcome_bytes, admin_fp)
        .expect("guest must verify admin identity in MLS roster");

    (guest_ws, provisional_id, resume_token, guest_mls)
}

#[tokio::test]
async fn origin_header_is_strictly_enforced() {
    let (url, _) = spawn_test_relay(RelayConfig::default()).await;
    assert!(connect_ws(&url, "https://evil.example").await.is_err());
    assert!(connect_ws(&url, "https://geistr.pages.dev").await.is_ok());
}

#[tokio::test]
async fn parallel_joins_with_same_token_take_at_most_one_slot_and_fifth_person_rejected() {
    let (url, _) = spawn_test_relay(RelayConfig::default()).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    // Test 1: Two parallel joins with the EXACT same invite token -> at most 1 succeeds.
    let shared_token = register_invite(&mut admin_ws, &mut admin_key, 0).await;

    let mut g1 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let mut g2 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let kp1 = STANDARD.encode(
        MlsSession::new(&room_id, "g1", false, None)
            .unwrap()
            .generate_key_package()
            .unwrap(),
    );
    let kp2 = STANDARD.encode(
        MlsSession::new(&room_id, "g2", false, None)
            .unwrap()
            .generate_key_package()
            .unwrap(),
    );

    let j1 = ClientToRelay::JoinRoom {
        room_id: room_id.clone(),
        invite_token: shared_token.clone(),
        key_package_b64: kp1,
        client_join_nonce: "nonce-guest-1".into(),
    };
    let j2 = ClientToRelay::JoinRoom {
        room_id: room_id.clone(),
        invite_token: shared_token.clone(),
        key_package_b64: kp2,
        client_join_nonce: "nonce-guest-2".into(),
    };
    tokio::join!(send_msg(&mut g1, &j1), send_msg(&mut g2, &j2));

    let r1 = recv_msg(&mut g1).await;
    let r2 = recv_msg(&mut g2).await;
    let pending_count = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, RelayToClient::JoinPending { .. }))
        .count();
    let error_count = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, RelayToClient::Error { .. }))
        .count();
    assert_eq!(
        pending_count, 1,
        "exactly one parallel joiner may reserve the token"
    );
    assert_eq!(
        error_count, 1,
        "the second parallel joiner must be rejected"
    );

    // Admit the winning guest (seat 2 of 4).
    let (res_id, guest_id, kp_b64) = match recv_msg(&mut admin_ws).await {
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => (reservation_id, guest_id, key_package_b64),
        other => panic!("expected GuestJoinRequest, got {other:?}"),
    };
    let add = admin_mls
        .add_member(&STANDARD.decode(&kp_b64).unwrap())
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::CompleteJoin {
            reservation_id: res_id,
            guest_id,
            commit_b64: STANDARD.encode(&add.commit_bytes),
            welcome_b64: STANDARD.encode(&add.welcome_bytes),
            new_epoch: add.new_epoch,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus { .. }
    ));

    // Admit Guest 2 (seat 3 of 4) and Guest 3 (seat 4 of 4).
    let tok2 = register_invite(&mut admin_ws, &mut admin_key, admin_mls.current_epoch()).await;
    let (_g2_ws, _, _, _) = admit_guest(
        &url,
        &room_id,
        &tok2,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    let tok3 = register_invite(&mut admin_ws, &mut admin_key, admin_mls.current_epoch()).await;
    let (_g3_ws, _, _, _) = admit_guest(
        &url,
        &room_id,
        &tok3,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    // Test 2: A 5th person MUST be rejected even with a freshly issued invite token!
    let tok4 = register_invite(&mut admin_ws, &mut admin_key, admin_mls.current_epoch()).await;
    let mut g5 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let kp5 = STANDARD.encode(
        MlsSession::new(&room_id, "g5", false, None)
            .unwrap()
            .generate_key_package()
            .unwrap(),
    );
    send_msg(
        &mut g5,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token: tok4,
            key_package_b64: kp5,
            client_join_nonce: "nonce-guest-5".into(),
        },
    )
    .await;
    match recv_msg(&mut g5).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "room_full"),
        other => panic!("5th person must be rejected with room_full, got {other:?}"),
    }
}

#[tokio::test]
async fn full_e2e_mls_flow_removal_blocks_former_guest_and_panic_wipe() {
    let (url, state) = spawn_test_relay(RelayConfig::default()).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    // Admit Guest 1 and Guest 2.
    let tok1 = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    let (mut g1_ws, g1_mls_id, _, mut g1_mls) = admit_guest(
        &url,
        &room_id,
        &tok1,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    let tok2 = register_invite(&mut admin_ws, &mut admin_key, admin_mls.current_epoch()).await;
    let (mut g2_ws, _, _, mut g2_mls) = admit_guest(
        &url,
        &room_id,
        &tok2,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    // Guest 1 receives the Add Commit for Guest 2 so all 3 members share Epoch 2.
    match recv_msg(&mut g1_ws).await {
        RelayToClient::MlsCommit { commit_b64, .. } => {
            g1_mls
                .process_incoming(&STANDARD.decode(&commit_b64).unwrap())
                .unwrap();
        }
        other => panic!("expected MlsCommit for g1, got {other:?}"),
    }

    // Exchange encrypted message across all 3 participants.
    let payload = ChatAppPayload {
        message_id: "msg-1".into(),
        text: "Secret message in epoch 2".into(),
        sent_at_ms: 1_700_000_000_000,
    };
    let ct = admin_mls.encrypt_chat_message(&payload).unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::SendMlsMessage {
            epoch: admin_mls.current_epoch(),
            message_id: "msg-1".into(),
            ciphertext_b64: STANDARD.encode(&ct),
        },
    )
    .await;

    for (gws, gmls) in [(&mut g1_ws, &mut g1_mls), (&mut g2_ws, &mut g2_mls)] {
        let RelayToClient::MlsMessage { ciphertext_b64, .. } = recv_msg(gws).await else {
            panic!("expected MlsMessage");
        };
        let bytes = STANDARD.decode(&ciphertext_b64).unwrap();
        match gmls.process_incoming(&bytes).unwrap() {
            MlsIncomingEvent::ChatMessage { payload: p, .. } => assert_eq!(p.text, payload.text),
            _ => panic!("expected ChatMessage"),
        }
    }

    // Guest 1 leaves permanently -> messaging pauses until Admin commits MLS Remove!
    send_msg(&mut g1_ws, &ClientToRelay::LeaveRoom).await;

    let removed_relay_pid = match recv_msg(&mut admin_ws).await {
        RelayToClient::MemberRemovalRequired { participant_id, .. } => participant_id,
        other => panic!("expected MemberRemovalRequired, got {other:?}"),
    };
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            messaging_paused: true,
            ..
        }
    ));
    assert!(matches!(
        recv_msg(&mut g2_ws).await,
        RelayToClient::MemberStatus {
            messaging_paused: true,
            ..
        }
    ));

    // Trying to send while paused MUST be rejected by relay!
    send_msg(
        &mut admin_ws,
        &ClientToRelay::SendMlsMessage {
            epoch: admin_mls.current_epoch(),
            message_id: "blocked-msg".into(),
            ciphertext_b64: STANDARD.encode(&ct),
        },
    )
    .await;
    match recv_msg(&mut admin_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "messaging_paused"),
        other => panic!("expected messaging_paused error, got {other:?}"),
    }

    // Admin commits MLS Remove for Guest 1 -> Epoch 3 -> messaging unpauses!
    let (remove_commit, new_epoch) = admin_mls
        .remove_member_by_participant_id(&g1_mls_id)
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::SendMlsCommit {
            epoch: new_epoch,
            commit_b64: STANDARD.encode(&remove_commit),
            removed_participant_id: Some(removed_relay_pid),
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            messaging_paused: false,
            ..
        }
    ));

    // Guest 2 applies Remove Commit.
    match recv_msg(&mut g2_ws).await {
        RelayToClient::MlsCommit { commit_b64, .. } => {
            g2_mls
                .process_incoming(&STANDARD.decode(&commit_b64).unwrap())
                .unwrap();
        }
        other => panic!("expected MlsCommit for g2, got {other:?}"),
    }

    // Admin sends a post-removal message -> Guest 2 decrypts, former Guest 1 CANNOT decrypt!
    let post_payload = ChatAppPayload {
        message_id: "msg-post-remove".into(),
        text: "Confidential after removal".into(),
        sent_at_ms: 1_700_000_005_000,
    };
    let post_ct = admin_mls.encrypt_chat_message(&post_payload).unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::SendMlsMessage {
            epoch: admin_mls.current_epoch(),
            message_id: "msg-post-remove".into(),
            ciphertext_b64: STANDARD.encode(&post_ct),
        },
    )
    .await;

    let RelayToClient::MlsMessage { ciphertext_b64, .. } = recv_msg(&mut g2_ws).await else {
        panic!("expected post-remove MlsMessage for g2");
    };
    let post_bytes = STANDARD.decode(&ciphertext_b64).unwrap();
    assert!(matches!(
        g2_mls.process_incoming(&post_bytes).unwrap(),
        MlsIncomingEvent::ChatMessage { payload: p, .. } if p.text == post_payload.text
    ));
    // Former Guest 1 MUST fail to decrypt Epoch 3 ciphertext!
    assert!(g1_mls.process_incoming(&post_bytes).is_err());

    // Admin triggers Panic-Wipe -> receives confirmation, Guest 2 receives RoomWiped, room is destroyed.
    let wipe_cmd = admin_key
        .sign_command(admin_mls.current_epoch(), AdminCommandPayload::PanicWipe)
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AdminCommand {
            signed_cmd: wipe_cmd,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::PanicWipeConfirmed { .. }
    ));
    assert!(matches!(
        recv_msg(&mut g2_ws).await,
        RelayToClient::RoomWiped { .. }
    ));
    assert_eq!(state.active_room_count().await, 0);
}

#[tokio::test]
async fn last_socket_disconnect_immediately_destroys_room_and_invalidates_resume() {
    let (url, state) = spawn_test_relay(RelayConfig::default()).await;
    let (mut admin_ws, room_id, admin_id, resume_token, _, _) = create_initialized_room(&url).await;
    assert_eq!(state.active_room_count().await, 1);

    // Close the ONLY open WebSocket in the room -> room MUST terminate immediately (no 60s wait!).
    admin_ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(state.active_room_count().await, 0);

    // Attempting to resume must fail.
    let mut ws2 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut ws2,
        &ClientToRelay::ResumeSession {
            room_id,
            participant_id: admin_id,
            resume_token,
        },
    )
    .await;
    match recv_msg(&mut ws2).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "room_not_found"),
        other => panic!("expected room_not_found, got {other:?}"),
    }
}

#[tokio::test]
async fn guest_reconnect_within_grace_succeeds_and_expiry_triggers_removal() {
    let cfg = RelayConfig {
        reconnect_grace_secs: 1,
        ..Default::default()
    };
    let (url, _) = spawn_test_relay(cfg).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    let tok1 = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    let (mut g1_ws, _, g1_resume, _) = admit_guest(
        &url,
        &room_id,
        &tok1,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    // Fetch guest's relay participant_id from the member list by disconnecting and reading MemberStatus.
    g1_ws.close(None).await.unwrap();
    let g1_relay_id = match recv_msg(&mut admin_ws).await {
        RelayToClient::MemberStatus {
            participant_id,
            connected: false,
            ..
        } => participant_id,
        other => panic!("expected MemberStatus disconnected, got {other:?}"),
    };

    // Resume BEFORE 1s grace window expires -> succeeds!
    let mut g1_resumed = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut g1_resumed,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: g1_relay_id.clone(),
            resume_token: g1_resume,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut g1_resumed).await,
        RelayToClient::SessionResumed { .. }
    ));
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            connected: true,
            ..
        }
    ));

    // Now disconnect again and let the 1s grace window expire -> Admin receives MemberRemovalRequired!
    g1_resumed.close(None).await.unwrap();
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            connected: false,
            ..
        }
    ));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    match recv_msg(&mut admin_ws).await {
        RelayToClient::MemberRemovalRequired { participant_id, .. } => {
            assert_eq!(participant_id, g1_relay_id);
        }
        other => panic!("expected MemberRemovalRequired after grace expiry, got {other:?}"),
    }
}
