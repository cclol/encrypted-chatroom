use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use core_crypto::admin::{
    AdminCommandPayload, AdminCommandVerifier, AdminSigningKey, compute_admin_fingerprint,
};
use core_crypto::mls::{MlsIncomingEvent, MlsSession};
use core_crypto::policy::RoomPolicy;
use core_crypto::protocol::{ChatAppPayload, ClientToRelay, RelayToClient};
use core_crypto::{random_token_b64url, sha256_hex};
use futures_util::{SinkExt, StreamExt};
use relay_server::build_router;
use relay_server::config::RelayConfig;
use relay_server::state::{RelayState, now_ms};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn spawn_test_relay(mut config: RelayConfig) -> (String, Arc<RelayState>) {
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

async fn spawn_test_relay_with_clock(
    mut config: RelayConfig,
    initial_ms: u64,
    run_sweeper: bool,
) -> (String, Arc<RelayState>, Arc<AtomicU64>) {
    config.allowed_origin = "https://geistr.pages.dev".into();
    config.sweep_interval_ms = 50;
    config.wipe_delivery_grace_ms = 100;
    let clock = Arc::new(AtomicU64::new(initial_ms));
    let clock_clone = Arc::clone(&clock);
    let state =
        RelayState::new_with_clock(config, Arc::new(move || clock_clone.load(Ordering::SeqCst)));
    if run_sweeper {
        state.spawn_sweeper();
    }
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
    (format!("ws://{addr}/ws"), state, clock)
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

    let mut admin_mls = MlsSession::new_admin(&room_id, &admin_id, &admin_key).unwrap();
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
) -> (WsStream, String, String, String, MlsSession) {
    let mut guest_ws = connect_ws(url, "https://geistr.pages.dev").await.unwrap();
    let provisional_id = random_token_b64url(6).unwrap();
    let mut guest_mls = MlsSession::new_guest(room_id, &provisional_id).unwrap();
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

    // Admin receives GuestJoinRequest, stages Add Commit, waits for CommitAccepted, then applies & acks!
    let (reservation_id, guest_id, kp_b64) = match recv_msg(admin_ws).await {
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => (reservation_id, guest_id, key_package_b64),
        other => panic!("expected GuestJoinRequest, got {other:?}"),
    };

    let kp_bytes = STANDARD.decode(&kp_b64).unwrap();
    let staged = admin_mls.stage_add_member(&kp_bytes).unwrap();
    let commit_id = random_token_b64url(10).unwrap();

    send_msg(
        admin_ws,
        &ClientToRelay::CompleteJoin {
            reservation_id,
            guest_id: guest_id.clone(),
            commit_id: commit_id.clone(),
            expected_epoch: staged.expected_epoch,
            commit_b64: STANDARD.encode(&staged.commit_bytes),
            welcome_b64: STANDARD.encode(&staged.welcome_bytes),
            new_epoch: staged.new_epoch,
        },
    )
    .await;

    // Admin gets CommitAccepted, applies pending commit, and sends AckCommit.
    match recv_msg(admin_ws).await {
        RelayToClient::CommitAccepted {
            commit_id: cid,
            new_epoch,
            ..
        } => {
            assert_eq!(cid, commit_id);
            let (applied, _) = admin_mls.apply_pending_commit().unwrap();
            assert_eq!(applied, new_epoch);
            send_msg(
                admin_ws,
                &ClientToRelay::AckCommit {
                    commit_id: cid,
                    epoch: new_epoch,
                },
            )
            .await;
        }
        other => panic!("expected CommitAccepted, got {other:?}"),
    }

    // Guest gets JoinAccepted, verifies admin key + MLS binding + policy, and sends AckCommit.
    let (accepted_id, resume_token, welcome_b64, admin_pubkey_b64, cid, epoch, policy_cmd) =
        match recv_msg(&mut guest_ws).await {
            RelayToClient::JoinAccepted {
                participant_id,
                resume_token,
                welcome_b64,
                admin_pubkey_b64,
                commit_id,
                epoch,
                latest_policy_cmd,
                ..
            } => (
                participant_id,
                resume_token,
                welcome_b64,
                admin_pubkey_b64,
                commit_id,
                epoch,
                latest_policy_cmd,
            ),
            other => panic!("expected JoinAccepted, got {other:?}"),
        };
    assert_eq!(accepted_id, guest_id);
    let pk = core_crypto::admin::decode_pubkey_b64(&admin_pubkey_b64).unwrap();
    assert_eq!(compute_admin_fingerprint(&pk, room_id), admin_fp);

    let welcome_bytes = STANDARD.decode(&welcome_b64).unwrap();
    let joined_ep = guest_mls
        .join_from_welcome(&welcome_bytes, &pk, admin_fp)
        .expect("guest must verify cryptographic admin->MLS key binding");
    assert_eq!(joined_ep, epoch);

    let mut verifier = AdminCommandVerifier::new(room_id, pk).unwrap();
    verifier
        .verify_historical_policy_snapshot(&policy_cmd, epoch)
        .unwrap();

    send_msg(
        &mut guest_ws,
        &ClientToRelay::AckCommit {
            commit_id: cid,
            epoch,
        },
    )
    .await;

    (
        guest_ws,
        accepted_id,
        provisional_id,
        resume_token,
        guest_mls,
    )
}

#[tokio::test]
async fn origin_header_is_strictly_enforced() {
    let (url, _) = spawn_test_relay(RelayConfig {
        allowed_origin: "https://geistr.cc, https://www.geistr.cc, https://geistr.pages.dev".into(),
        ..RelayConfig::default()
    })
    .await;
    assert!(connect_ws(&url, "https://evil.example").await.is_err());
    assert!(
        connect_ws(&url, "https://www.geistr.cc.evil.example")
            .await
            .is_err()
    );
    assert!(connect_ws(&url, "https://geistr.cc").await.is_ok());
    assert!(connect_ws(&url, "https://www.geistr.cc").await.is_ok());
    assert!(connect_ws(&url, "https://geistr.pages.dev").await.is_ok());
}

#[tokio::test]
async fn parallel_joins_with_same_token_take_at_most_one_slot_and_fifth_person_rejected() {
    let (url, _) = spawn_test_relay(RelayConfig::default()).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    // Two parallel joins with the EXACT same invite token -> at most 1 succeeds.
    let shared_token = register_invite(&mut admin_ws, &mut admin_key, 0).await;

    let mut g1 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let mut g2 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let kp1 = STANDARD.encode(
        MlsSession::new_guest(&room_id, "g1")
            .unwrap()
            .generate_key_package()
            .unwrap(),
    );
    let kp2 = STANDARD.encode(
        MlsSession::new_guest(&room_id, "g2")
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
    assert_eq!(pending_count, 1);
    assert_eq!(error_count, 1);

    // Admit winning guest (seat 2 of 4).
    let (res_id, guest_id, kp_b64) = match recv_msg(&mut admin_ws).await {
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => (reservation_id, guest_id, key_package_b64),
        other => panic!("expected GuestJoinRequest, got {other:?}"),
    };
    let staged = admin_mls
        .stage_add_member(&STANDARD.decode(&kp_b64).unwrap())
        .unwrap();
    let cid = random_token_b64url(10).unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::CompleteJoin {
            reservation_id: res_id,
            guest_id,
            commit_id: cid.clone(),
            expected_epoch: staged.expected_epoch,
            commit_b64: STANDARD.encode(&staged.commit_bytes),
            welcome_b64: STANDARD.encode(&staged.welcome_bytes),
            new_epoch: staged.new_epoch,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::CommitAccepted { .. }
    ));
    admin_mls.apply_pending_commit().unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AckCommit {
            commit_id: cid,
            epoch: admin_mls.current_epoch(),
        },
    )
    .await;

    // Admit Guest 2 (seat 3) and Guest 3 (seat 4).
    let tok2 = register_invite(&mut admin_ws, &mut admin_key, admin_mls.current_epoch()).await;
    let (_g2_ws, _, _, _, _) = admit_guest(
        &url,
        &room_id,
        &tok2,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    let tok3 = register_invite(&mut admin_ws, &mut admin_key, admin_mls.current_epoch()).await;
    let (_g3_ws, _, _, _, _) = admit_guest(
        &url,
        &room_id,
        &tok3,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    // A 5th person MUST be rejected with room_full.
    let tok4 = register_invite(&mut admin_ws, &mut admin_key, admin_mls.current_epoch()).await;
    let mut g5 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let kp5 = STANDARD.encode(
        MlsSession::new_guest(&room_id, "g5")
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
async fn full_e2e_mls_flow_removal_requires_ack_before_unpause_and_blocks_former_guest() {
    let (url, state) = spawn_test_relay(RelayConfig::default()).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    // Admit Guest 1 and Guest 2.
    let tok1 = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    let (mut g1_ws, _g1_relay_id, g1_mls_id, _, mut g1_mls) = admit_guest(
        &url,
        &room_id,
        &tok1,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    let tok2 = register_invite(&mut admin_ws, &mut admin_key, admin_mls.current_epoch()).await;
    let (mut g2_ws, _, _, _, mut g2_mls) = admit_guest(
        &url,
        &room_id,
        &tok2,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    // Guest 1 receives Add Commit for Guest 2, applies, and sends AckCommit.
    match recv_msg(&mut g1_ws).await {
        RelayToClient::MlsCommit {
            commit_id,
            epoch,
            commit_b64,
            ..
        } => {
            g1_mls
                .process_incoming(&STANDARD.decode(&commit_b64).unwrap())
                .unwrap();
            send_msg(&mut g1_ws, &ClientToRelay::AckCommit { commit_id, epoch }).await;
        }
        other => panic!("expected MlsCommit for g1, got {other:?}"),
    }

    // Exchange encrypted message across all 3 participants in Epoch 2.
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

    // Guest 1 leaves permanently -> messaging pauses until Admin commits AND all remaining connected members ack!
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

    // Admin stages & sends MLS Remove Commit for Guest 1 -> Epoch 3.
    let staged_rm = admin_mls
        .stage_remove_member_by_participant_id(&g1_mls_id)
        .unwrap();
    let rm_cid = random_token_b64url(10).unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::SendMlsCommit {
            commit_id: rm_cid.clone(),
            expected_epoch: staged_rm.expected_epoch,
            epoch: staged_rm.new_epoch,
            commit_b64: STANDARD.encode(&staged_rm.commit_bytes),
            removed_participant_id: Some(removed_relay_pid),
        },
    )
    .await;

    // CommitAccepted STILL reports messaging_paused == true until connected members ack Epoch 3!
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::CommitAccepted {
            messaging_paused: true,
            new_epoch: 3,
            ..
        }
    ));
    admin_mls.apply_pending_commit().unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AckCommit {
            commit_id: rm_cid.clone(),
            epoch: 3,
        },
    )
    .await;

    // Even after Admin acked, Guest 2 hasn't acked Epoch 3 yet -> sending MUST STILL be paused!
    let post_payload = ChatAppPayload {
        message_id: "msg-post-remove".into(),
        text: "Confidential after removal".into(),
        sent_at_ms: 1_700_000_005_000,
    };
    let post_ct = admin_mls.encrypt_chat_message(&post_payload).unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::SendMlsMessage {
            epoch: 3,
            message_id: "blocked-before-g2-ack".into(),
            ciphertext_b64: STANDARD.encode(&post_ct),
        },
    )
    .await;
    match recv_msg(&mut admin_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "messaging_paused"),
        other => panic!("expected messaging_paused before g2 acks, got {other:?}"),
    }

    // Guest 2 receives Remove Commit, applies it, and sends AckCommit -> NOW messaging unpauses!
    match recv_msg(&mut g2_ws).await {
        RelayToClient::MlsCommit {
            commit_id,
            epoch,
            commit_b64,
            messaging_paused,
            ..
        } => {
            assert!(messaging_paused);
            assert_eq!(epoch, 3);
            g2_mls
                .process_incoming(&STANDARD.decode(&commit_b64).unwrap())
                .unwrap();
            send_msg(&mut g2_ws, &ClientToRelay::AckCommit { commit_id, epoch }).await;
        }
        other => panic!("expected MlsCommit for g2, got {other:?}"),
    }

    // Both Admin and Guest 2 receive unpause MemberStatus!
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            messaging_paused: false,
            ..
        }
    ));
    assert!(matches!(
        recv_msg(&mut g2_ws).await,
        RelayToClient::MemberStatus {
            messaging_paused: false,
            ..
        }
    ));

    // Stale-epoch send on epoch 2 MUST be rejected by relay!
    send_msg(
        &mut g2_ws,
        &ClientToRelay::SendMlsMessage {
            epoch: 2,
            message_id: "stale-epoch-msg".into(),
            ciphertext_b64: STANDARD.encode(&ct),
        },
    )
    .await;
    match recv_msg(&mut g2_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "epoch_mismatch"),
        other => panic!("expected epoch_mismatch on stale epoch, got {other:?}"),
    }

    // Admin sends valid Epoch 3 message -> Guest 2 decrypts, former Guest 1 CANNOT decrypt!
    send_msg(
        &mut admin_ws,
        &ClientToRelay::SendMlsMessage {
            epoch: 3,
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
async fn resume_on_stale_epoch_delivers_ordered_missed_commits_and_blocks_old_epoch_send() {
    let (url, _) = spawn_test_relay(RelayConfig::default()).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    // Admit Guest 1 (Epoch 1).
    let tok1 = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    let (mut g1_ws, g1_relay_id, _, g1_resume, mut g1_mls) = admit_guest(
        &url,
        &room_id,
        &tok1,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;
    assert_eq!(g1_mls.current_epoch(), 1);

    // Guest 1 temporarily disconnects.
    g1_ws.close(None).await.unwrap();
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            connected: false,
            ..
        }
    ));

    // While Guest 1 is offline, Guest 2 joins (Epoch 2) AND leaves + is removed (Epoch 3)!
    let tok2 = register_invite(&mut admin_ws, &mut admin_key, 1).await;
    let (mut g2_ws, g2_relay_id, g2_mls_id, _, mut g2_mls) = admit_guest(
        &url,
        &room_id,
        &tok2,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;
    send_msg(&mut g2_ws, &ClientToRelay::LeaveRoom).await;
    let _ = recv_msg(&mut admin_ws).await; // MemberRemovalRequired
    let _ = recv_msg(&mut admin_ws).await; // MemberStatus paused

    let staged_rm = admin_mls
        .stage_remove_member_by_participant_id(&g2_mls_id)
        .unwrap();
    let rm_cid = random_token_b64url(10).unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::SendMlsCommit {
            commit_id: rm_cid.clone(),
            expected_epoch: 2,
            epoch: 3,
            commit_b64: STANDARD.encode(&staged_rm.commit_bytes),
            removed_participant_id: Some(g2_relay_id),
        },
    )
    .await;
    let _ = recv_msg(&mut admin_ws).await; // CommitAccepted
    admin_mls.apply_pending_commit().unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AckCommit {
            commit_id: rm_cid,
            epoch: 3,
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

    // Now Guest 1 reconnects at stale Epoch 1!
    let mut g1_resumed = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut g1_resumed,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: g1_relay_id.clone(),
            resume_token: g1_resume,
            resume_attempt_id: "attempt-stale-1".into(),
            last_epoch: 1,
        },
    )
    .await;

    let (epoch, missed) = match recv_msg(&mut g1_resumed).await {
        RelayToClient::SessionResumed {
            epoch,
            missed_commits,
            ..
        } => (epoch, missed_commits),
        other => panic!("expected SessionResumed, got {other:?}"),
    };
    assert_eq!(epoch, 3);
    assert_eq!(missed.len(), 2);
    assert_eq!((missed[0].prev_epoch, missed[0].epoch), (1, 2));
    assert_eq!((missed[1].prev_epoch, missed[1].epoch), (2, 3));

    // Before applying & acking missed commits, Guest 1 CANNOT send messages!
    let old_ct = g1_mls
        .encrypt_chat_message(&ChatAppPayload {
            message_id: "old-m".into(),
            text: "stale".into(),
            sent_at_ms: 1000,
        })
        .unwrap();
    send_msg(
        &mut g1_resumed,
        &ClientToRelay::SendMlsMessage {
            epoch: 1,
            message_id: "old-m".into(),
            ciphertext_b64: STANDARD.encode(&old_ct),
        },
    )
    .await;
    match recv_msg(&mut g1_resumed).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "epoch_mismatch"),
        other => panic!("stale client must be blocked from sending, got {other:?}"),
    }

    // Apply both missed commits in order -> reaches Epoch 3, sends AckCommit, then messaging works
    // and removed Guest 2 CANNOT decrypt Guest 1's message!
    let mut last_cid = String::new();
    for mc in missed {
        g1_mls
            .process_incoming(&STANDARD.decode(&mc.commit_b64).unwrap())
            .unwrap();
        last_cid = mc.commit_id;
    }
    assert_eq!(g1_mls.current_epoch(), 3);
    send_msg(
        &mut g1_resumed,
        &ClientToRelay::AckCommit {
            commit_id: last_cid,
            epoch: 3,
        },
    )
    .await;
    // Drain MemberStatus on admin_ws: first paused when g1 resumed on stale epoch, then unpaused after g1 acked epoch 3!
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            connected: true,
            messaging_paused: true,
            ..
        }
    ));
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            messaging_paused: false,
            ..
        }
    ));

    let fresh_payload = ChatAppPayload {
        message_id: "fresh-ep3".into(),
        text: "After catching up to epoch 3".into(),
        sent_at_ms: 2000,
    };
    let fresh_ct = g1_mls.encrypt_chat_message(&fresh_payload).unwrap();
    send_msg(
        &mut g1_resumed,
        &ClientToRelay::SendMlsMessage {
            epoch: 3,
            message_id: "fresh-ep3".into(),
            ciphertext_b64: STANDARD.encode(&fresh_ct),
        },
    )
    .await;

    let RelayToClient::MlsMessage { ciphertext_b64, .. } = recv_msg(&mut admin_ws).await else {
        panic!("expected MlsMessage on admin");
    };
    let ct_bytes = STANDARD.decode(&ciphertext_b64).unwrap();
    assert!(matches!(
        admin_mls.process_incoming(&ct_bytes).unwrap(),
        MlsIncomingEvent::ChatMessage { payload: p, .. } if p.text == fresh_payload.text
    ));
    // Removed Guest 2 MUST NOT decrypt!
    assert!(g2_mls.process_incoming(&ct_bytes).is_err());
}

#[tokio::test]
async fn lost_join_accepted_retries_idempotently_with_same_nonce_and_rejects_expired_complete_join()
{
    let start_ms = now_ms();
    let cfg = RelayConfig {
        join_reservation_ttl_secs: 10,
        ..Default::default()
    };
    // Run without sweeper to verify synchronous deadline checks inside CompleteJoin!
    let (url, _, clock) = spawn_test_relay_with_clock(cfg, start_ms, false).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();
    let admin_pk = admin_key.verifying_key_bytes();

    // Case 1: Guest sends JoinRoom, drops socket before receiving JoinAccepted, Admin completes join,
    // Guest retries with the EXACT same invite token + nonce + KeyPackage -> receives JoinAccepted!
    let tok1 = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    let mut guest_mls = MlsSession::new_guest(&room_id, "guest-retry").unwrap();
    let kp_b64 = STANDARD.encode(guest_mls.generate_key_package().unwrap());
    let nonce = "retry-nonce-12345";

    let mut g_ws1 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut g_ws1,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token: tok1.clone(),
            key_package_b64: kp_b64.clone(),
            client_join_nonce: nonce.into(),
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut g_ws1).await,
        RelayToClient::JoinPending { .. }
    ));

    // Guest loses socket mid-flight BEFORE admin finishes!
    g_ws1.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Admin still receives GuestJoinRequest and completes join (reservation preserved across disconnect!).
    let (res_id, guest_id, req_kp) = match recv_msg(&mut admin_ws).await {
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => (reservation_id, guest_id, key_package_b64),
        other => panic!("expected GuestJoinRequest, got {other:?}"),
    };
    let staged = admin_mls
        .stage_add_member(&STANDARD.decode(&req_kp).unwrap())
        .unwrap();
    let cid = random_token_b64url(10).unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::CompleteJoin {
            reservation_id: res_id,
            guest_id: guest_id.clone(),
            commit_id: cid.clone(),
            expected_epoch: 0,
            commit_b64: STANDARD.encode(&staged.commit_bytes),
            welcome_b64: STANDARD.encode(&staged.welcome_bytes),
            new_epoch: 1,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::CommitAccepted { new_epoch: 1, .. }
    ));
    admin_mls.apply_pending_commit().unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AckCommit {
            commit_id: cid,
            epoch: 1,
        },
    )
    .await;

    // Parallel attacker with DIFFERENT nonce is rejected with invite_consumed!
    let mut attacker = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut attacker,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token: tok1.clone(),
            key_package_b64: kp_b64.clone(),
            client_join_nonce: "other-nonce-999".into(),
        },
    )
    .await;
    match recv_msg(&mut attacker).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "invite_consumed"),
        other => panic!("different nonce must be rejected, got {other:?}"),
    }

    // Real guest retries with EXACT same token + nonce + KeyPackage -> gets cached JoinAccepted!
    let mut g_ws2 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut g_ws2,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token: tok1,
            key_package_b64: kp_b64,
            client_join_nonce: nonce.into(),
        },
    )
    .await;
    match recv_msg(&mut g_ws2).await {
        RelayToClient::JoinAccepted {
            participant_id,
            welcome_b64,
            members,
            ..
        } => {
            assert_eq!(participant_id, guest_id);
            assert_eq!(members.len(), 2, "must occupy exactly 1 guest seat");
            guest_mls
                .join_from_welcome(
                    &STANDARD.decode(&welcome_b64).unwrap(),
                    &admin_pk,
                    &admin_fp,
                )
                .unwrap();
        }
        other => panic!("expected cached JoinAccepted on retry, got {other:?}"),
    }

    // Case 2: CompleteJoin AFTER reservation TTL expires (without any sweeper tick!) MUST be rejected!
    let tok2 = register_invite(&mut admin_ws, &mut admin_key, 1).await;
    let mut g2_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let kp2 = STANDARD.encode(
        MlsSession::new_guest(&room_id, "g2-exp")
            .unwrap()
            .generate_key_package()
            .unwrap(),
    );
    send_msg(
        &mut g2_ws,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token: tok2,
            key_package_b64: kp2,
            client_join_nonce: "nonce-exp-1".into(),
        },
    )
    .await;
    let _ = recv_msg(&mut g2_ws).await; // JoinPending
    let (exp_res_id, exp_gid, exp_kp) = match recv_msg(&mut admin_ws).await {
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => (reservation_id, guest_id, key_package_b64),
        other => panic!("expected GuestJoinRequest, got {other:?}"),
    };

    // Advance controlled clock past the 10s reservation TTL (sweeper is OFF!).
    clock.fetch_add(15_000, Ordering::SeqCst);

    let staged_late = admin_mls
        .stage_add_member(&STANDARD.decode(&exp_kp).unwrap())
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::CompleteJoin {
            reservation_id: exp_res_id,
            guest_id: exp_gid,
            commit_id: "late-commit".into(),
            expected_epoch: 1,
            commit_b64: STANDARD.encode(&staged_late.commit_bytes),
            welcome_b64: STANDARD.encode(&staged_late.welcome_bytes),
            new_epoch: 2,
        },
    )
    .await;
    match recv_msg(&mut admin_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "reservation_expired"),
        other => panic!("expired reservation CompleteJoin must fail, got {other:?}"),
    }
    admin_mls.clear_pending_commit();
}

#[tokio::test]
async fn resume_retry_is_idempotent_and_superseded_socket_cannot_submit_frames() {
    let (url, _) = spawn_test_relay(RelayConfig::default()).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    let tok1 = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    let (mut g1_old, g1_relay_id, _, g1_resume_tok, mut g1_mls) = admit_guest(
        &url,
        &room_id,
        &tok1,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    // 1. Overlapping socket resumes while g1_old is STILL open!
    let mut g1_new1 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut g1_new1,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: g1_relay_id.clone(),
            resume_token: g1_resume_tok.clone(),
            resume_attempt_id: "attempt-idemp-1".into(),
            last_epoch: 1,
        },
    )
    .await;
    let rotated_tok1 = match recv_msg(&mut g1_new1).await {
        RelayToClient::SessionResumed { resume_token, .. } => resume_token,
        other => panic!("expected SessionResumed, got {other:?}"),
    };
    let _ = recv_msg(&mut admin_ws).await; // MemberStatus

    // Old superseded socket tries to send a message -> MUST be rejected or closed, never forwarded!
    let ct = g1_mls
        .encrypt_chat_message(&ChatAppPayload {
            message_id: "from-old-sock".into(),
            text: "should not pass".into(),
            sent_at_ms: 1000,
        })
        .unwrap();
    let _ = send_msg(
        &mut g1_old,
        &ClientToRelay::SendMlsMessage {
            epoch: 1,
            message_id: "from-old-sock".into(),
            ciphertext_b64: STANDARD.encode(&ct),
        },
    )
    .await;
    // Admin must NOT receive the frame from the superseded socket.
    let admin_got = tokio::time::timeout(Duration::from_millis(200), admin_ws.next()).await;
    assert!(
        admin_got.is_err(),
        "admin must not receive message from superseded socket"
    );

    // 2. Suppose SessionResumed on g1_new1 was lost in flight (no AckResume sent).
    // Client retries with the SAME old resume_token AND SAME resume_attempt_id -> succeeds idempotently!
    let mut g1_new2 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut g1_new2,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: g1_relay_id.clone(),
            resume_token: g1_resume_tok.clone(),
            resume_attempt_id: "attempt-idemp-1".into(),
            last_epoch: 1,
        },
    )
    .await;
    let rotated_tok2 = match recv_msg(&mut g1_new2).await {
        RelayToClient::SessionResumed { resume_token, .. } => resume_token,
        other => panic!("expected idempotent SessionResumed, got {other:?}"),
    };
    assert_eq!(rotated_tok1, rotated_tok2);

    // Once client sends AckResume, the old token is permanently retired!
    send_msg(&mut g1_new2, &ClientToRelay::AckResume).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut g1_replay = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut g1_replay,
        &ClientToRelay::ResumeSession {
            room_id,
            participant_id: g1_relay_id,
            resume_token: g1_resume_tok,
            resume_attempt_id: "attempt-idemp-1".into(),
            last_epoch: 1,
        },
    )
    .await;
    match recv_msg(&mut g1_replay).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "invalid_resume_token"),
        other => panic!("retired resume token must fail, got {other:?}"),
    }
}

#[tokio::test]
async fn expired_room_cannot_be_resurrected_before_sweep_and_stale_admin_cmd_rejected() {
    let start_ms = now_ms();
    // Sweeper disabled so we prove hard expiry is enforced synchronously BEFORE any sweep!
    let (url, state, clock) =
        spawn_test_relay_with_clock(RelayConfig::default(), start_ms, false).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    // Advance room to Epoch 1 by admitting a guest.
    let tok1 = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    let (mut g1_ws, _, _, _, _) = admit_guest(
        &url,
        &room_id,
        &tok1,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    // 1. Live AdminCommand signed for stale epoch 0 while room is at epoch 1 MUST be rejected!
    let stale_policy_cmd = admin_key
        .sign_command(
            0,
            AdminCommandPayload::SetPolicy {
                msg_ttl_secs: 300,
                room_ttl_secs: 300,
            },
        )
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AdminCommand {
            signed_cmd: stale_policy_cmd,
        },
    )
    .await;
    match recv_msg(&mut admin_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "invalid_admin_command"),
        other => panic!("stale-epoch live admin command must fail, got {other:?}"),
    }

    // 2. VerifySession succeeds while active & synced!
    send_msg(
        &mut g1_ws,
        &ClientToRelay::VerifySession {
            check_id: "vis-1".into(),
            local_epoch: 1,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut g1_ws).await,
        RelayToClient::SessionVerified { epoch: 1, .. }
    ));

    // 3. Shorten room TTL to 5m (300s), then advance controlled clock by 301s WITHOUT running sweep!
    let shorten_cmd = admin_key
        .sign_command(
            1,
            AdminCommandPayload::SetPolicy {
                msg_ttl_secs: 300,
                room_ttl_secs: 300,
            },
        )
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AdminCommand {
            signed_cmd: shorten_cmd,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::PolicyUpdated { .. }
    ));

    // Advance past 5m hard deadline!
    clock.fetch_add(301_000, Ordering::SeqCst);

    // Admin tries to extend room TTL back to 1h (3600s) before sweeper runs -> MUST FAIL and close room!
    let resurrect_cmd = admin_key
        .sign_command(
            1,
            AdminCommandPayload::SetPolicy {
                msg_ttl_secs: 300,
                room_ttl_secs: 3600,
            },
        )
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AdminCommand {
            signed_cmd: resurrect_cmd,
        },
    )
    .await;
    match recv_msg(&mut admin_ws).await {
        RelayToClient::RoomClosed { .. } | RelayToClient::Error { .. } => {}
        other => panic!("expired room must close instead of resurrecting, got {other:?}"),
    }
    assert_eq!(state.active_room_count().await, 0);
}

#[tokio::test]
async fn solo_admin_disconnect_without_invite_survives_5min_and_starts_new_window_only_after_resume()
 {
    let cfg = RelayConfig {
        admin_reconnect_grace_secs: 300,
        reconnect_grace_secs: 60,
        ..Default::default()
    };
    let (url, state, clock) = spawn_test_relay_with_clock(cfg, 50_000_000, false).await;
    let (mut admin_ws, room_id, admin_id, resume_token, _, _) = create_initialized_room(&url).await;
    assert_eq!(state.active_room_count().await, 1);

    // Solo admin with NO invite disconnects unintentionally -> room is held for 5 minutes!
    admin_ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(state.active_room_count().await, 1);

    // After 120s (> 60s) and sweeper tick, room is still alive.
    clock.fetch_add(120_000, Ordering::SeqCst);
    state.sweep_once().await;
    assert_eq!(state.active_room_count().await, 1);

    // Failed resume attempt at t=200s must NOT extend the original t=300s deadline.
    clock.fetch_add(80_000, Ordering::SeqCst);
    let mut bad_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut bad_ws,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: admin_id.clone(),
            resume_token: "wrong-token".into(),
            resume_attempt_id: "bad-solo-1".into(),
            last_epoch: 0,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut bad_ws).await,
        RelayToClient::Error { code, .. } if code == "invalid_resume_token"
    ));

    // Valid resume at t=290s (< 300s) succeeds and rotates resume token!
    clock.fetch_add(90_000, Ordering::SeqCst);
    let mut ws2 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut ws2,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: admin_id.clone(),
            resume_token,
            resume_attempt_id: "solo-resume-1".into(),
            last_epoch: 0,
        },
    )
    .await;
    let rotated_token = match recv_msg(&mut ws2).await {
        RelayToClient::SessionResumed {
            resume_token,
            epoch,
            ..
        } => {
            assert_eq!(epoch, 0);
            resume_token
        }
        other => panic!("expected SessionResumed at t=290s, got {other:?}"),
    };

    // Second disconnect after successful resume starts a NEW 5-minute window (t=290s -> t=590s).
    ws2.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    clock.fetch_add(200_000, Ordering::SeqCst); // t=490s (> original 300s, < new 590s)
    state.sweep_once().await;
    assert_eq!(
        state.active_room_count().await,
        1,
        "new disconnect after verified resume must start a fresh 5-minute window"
    );

    // Past the new 5-minute window (t=591s) -> resume fails and room is destroyed!
    clock.fetch_add(101_000, Ordering::SeqCst);
    let mut ws3 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut ws3,
        &ClientToRelay::ResumeSession {
            room_id,
            participant_id: admin_id,
            resume_token: rotated_token,
            resume_attempt_id: "solo-resume-expired".into(),
            last_epoch: 0,
        },
    )
    .await;
    match recv_msg(&mut ws3).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "resume_expired"),
        other => panic!("expected resume_expired after 5-min grace, got {other:?}"),
    }
    assert_eq!(state.active_room_count().await, 0);
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
    let (mut g1_ws, g1_relay_id, _, g1_resume, _) = admit_guest(
        &url,
        &room_id,
        &tok1,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    g1_ws.close(None).await.unwrap();
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::MemberStatus {
            connected: false,
            ..
        }
    ));

    // Resume BEFORE 1s grace window expires -> succeeds!
    let mut g1_resumed = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut g1_resumed,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: g1_relay_id.clone(),
            resume_token: g1_resume,
            resume_attempt_id: "attempt-grace-1".into(),
            last_epoch: 1,
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

    // Disconnect again and let 1s grace window expire -> Admin receives MemberRemovalRequired!
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

#[tokio::test]
async fn slow_consumer_budget_overflow_terminates_only_slow_socket_while_others_continue() {
    // Outbound byte budget large enough for join handshake (~4 KiB) but small enough that
    // blasting chat messages overflows the slow guest's socket while admin stays alive.
    let cfg = RelayConfig {
        max_outbound_bytes_per_min: 10_240,
        ..Default::default()
    };
    let (url, _) = spawn_test_relay(cfg).await;
    let (mut admin_ws, room_id, _, _, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_fp = admin_key.fingerprint();

    let tok1 = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    let (_slow_g1, g1_relay_id, _, _, _) = admit_guest(
        &url,
        &room_id,
        &tok1,
        &admin_fp,
        &mut admin_ws,
        &mut admin_mls,
    )
    .await;

    // Blast messages from admin until slow_g1 overflows its outbound byte budget -> relay closes slow_g1
    // out-of-band and notifies admin that g1 disconnected, while admin's own socket stays alive!
    let mut saw_g1_disconnect = false;
    for i in 0..40 {
        let ct = admin_mls
            .encrypt_chat_message(&ChatAppPayload {
                message_id: format!("flood-{i}"),
                text: "x".repeat(1200),
                sent_at_ms: 1000 + i,
            })
            .unwrap();
        send_msg(
            &mut admin_ws,
            &ClientToRelay::SendMlsMessage {
                epoch: 1,
                message_id: format!("flood-{i}"),
                ciphertext_b64: STANDARD.encode(&ct),
            },
        )
        .await;
        if let Ok(Some(Ok(Message::Text(t)))) =
            tokio::time::timeout(Duration::from_millis(40), admin_ws.next()).await
            && let Ok(RelayToClient::MemberStatus {
                participant_id,
                connected: false,
                ..
            }) = serde_json::from_str::<RelayToClient>(&t)
            && participant_id == g1_relay_id
        {
            saw_g1_disconnect = true;
            break;
        }
    }
    assert!(
        saw_g1_disconnect,
        "slow/overflowing consumer must be aborted out-of-band so reader exits and triggers disconnect"
    );

    // Admin socket is still alive and responds to Ping!
    send_msg(&mut admin_ws, &ClientToRelay::Ping { ts_ms: 42 }).await;
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::Pong { ts_ms: 42 }
    ));
}

#[tokio::test]
async fn invite_hold_survives_admin_disconnect_beyond_60s_and_admits_waiting_guest_on_verified_resume()
 {
    let cfg = RelayConfig {
        invite_ttl_secs: 300,
        admin_reconnect_grace_secs: 300,
        reconnect_grace_secs: 60,
        join_reservation_ttl_secs: 60,
        ..Default::default()
    };
    let (url, state, clock) = spawn_test_relay_with_clock(cfg, 10_000_000, false).await;
    let (mut admin_ws, room_id, admin_id, admin_resume, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_pk = admin_key.verifying_key_bytes();
    let admin_fp = admin_key.fingerprint();

    // Admin registers an invite valid for 5 minutes, then disconnects (e.g. switches to Signal/WhatsApp).
    let invite_token = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    admin_ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        state.active_room_count().await,
        1,
        "room with valid unused invite must stay in Relay RAM after last socket drops"
    );

    // Advance clock 90 seconds (> 60s normal reconnect window!) and run sweeper.
    clock.fetch_add(90_000, Ordering::SeqCst);
    state.sweep_once().await;
    assert_eq!(
        state.active_room_count().await,
        1,
        "room must still be held after 90s while invite is valid"
    );

    // Guest opens the invite link while admin is offline -> receives JoinPending ("waiting for admin").
    let mut guest_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let mut guest_mls = MlsSession::new_guest(&room_id, "guest-wait").unwrap();
    let guest_kp = STANDARD.encode(guest_mls.generate_key_package().unwrap());
    send_msg(
        &mut guest_ws,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token,
            key_package_b64: guest_kp,
            client_join_nonce: "nonce-wait-1".into(),
        },
    )
    .await;
    match recv_msg(&mut guest_ws).await {
        RelayToClient::JoinPending { reason, .. } => {
            assert!(
                reason.to_ascii_lowercase().contains("waiting for admin"),
                "expected waiting-for-admin message, got: {reason}"
            );
        }
        other => panic!("expected JoinPending while admin offline, got {other:?}"),
    }

    // Admin returns at t=95s (> 60s!) and resumes with the matching invite-hold deadline.
    clock.fetch_add(5_000, Ordering::SeqCst);
    let mut admin_ws2 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut admin_ws2,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: admin_id,
            resume_token: admin_resume,
            resume_attempt_id: "admin-resume-after-95s".into(),
            last_epoch: 0,
        },
    )
    .await;
    match recv_msg(&mut admin_ws2).await {
        RelayToClient::SessionResumed { epoch, .. } => assert_eq!(epoch, 0),
        other => panic!("expected SessionResumed for admin, got {other:?}"),
    }

    // Relay immediately forwards the queued GuestJoinRequest to the resumed admin.
    let (res_id, guest_id, kp_b64) = match recv_msg(&mut admin_ws2).await {
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => (reservation_id, guest_id, key_package_b64),
        other => panic!("expected queued GuestJoinRequest on admin resume, got {other:?}"),
    };

    let staged = admin_mls
        .stage_add_member(&STANDARD.decode(&kp_b64).unwrap())
        .unwrap();
    send_msg(
        &mut admin_ws2,
        &ClientToRelay::CompleteJoin {
            reservation_id: res_id,
            guest_id,
            commit_id: "admit-after-hold".into(),
            expected_epoch: 0,
            commit_b64: STANDARD.encode(&staged.commit_bytes),
            welcome_b64: STANDARD.encode(&staged.welcome_bytes),
            new_epoch: 1,
        },
    )
    .await;

    match recv_msg(&mut admin_ws2).await {
        RelayToClient::CommitAccepted { new_epoch, .. } => assert_eq!(new_epoch, 1),
        other => panic!("expected CommitAccepted, got {other:?}"),
    }
    admin_mls.apply_pending_commit().unwrap();

    // Waiting guest receives JoinAccepted automatically and verifies MLS Welcome!
    match recv_msg(&mut guest_ws).await {
        RelayToClient::JoinAccepted {
            welcome_b64,
            epoch,
            members,
            ..
        } => {
            assert_eq!(epoch, 1);
            assert_eq!(members.len(), 2);
            let joined_ep = guest_mls
                .join_from_welcome(
                    &STANDARD.decode(&welcome_b64).unwrap(),
                    &admin_pk,
                    &admin_fp,
                )
                .unwrap();
            assert_eq!(joined_ep, 1);
        }
        other => panic!("expected JoinAccepted for waiting guest, got {other:?}"),
    }
}

#[tokio::test]
async fn expired_reservation_releases_slot_for_retry_without_extending_any_deadline() {
    let cfg = RelayConfig {
        invite_ttl_secs: 300,
        admin_reconnect_grace_secs: 300,
        reconnect_grace_secs: 60,
        join_reservation_ttl_secs: 20,
        ..Default::default()
    };
    let (url, state, clock) = spawn_test_relay_with_clock(cfg, 20_000_000, false).await;
    let (mut admin_ws, room_id, admin_id, admin_resume, mut admin_key, _) =
        create_initialized_room(&url).await;

    let invite_token = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    admin_ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(state.active_room_count().await, 1);

    // At t=10s, guest 1 reserves the invite (reservation expires at t=30s).
    clock.fetch_add(10_000, Ordering::SeqCst);
    let mut g1_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let kp1 = STANDARD.encode(
        MlsSession::new_guest(&room_id, "g1-retry")
            .unwrap()
            .generate_key_package()
            .unwrap(),
    );
    send_msg(
        &mut g1_ws,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token: invite_token.clone(),
            key_package_b64: kp1,
            client_join_nonce: "nonce-r1".into(),
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut g1_ws).await,
        RelayToClient::JoinPending { .. }
    ));

    // Advance to t=35s (reservation expired, invite still valid until t=300s).
    clock.fetch_add(25_000, Ordering::SeqCst);
    state.sweep_once().await;
    match recv_msg(&mut g1_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "join_timeout"),
        other => panic!("expected join_timeout for expired reservation, got {other:?}"),
    }
    assert_eq!(
        state.active_room_count().await,
        1,
        "room must remain held while invite is still valid and unused"
    );

    // At t=40s, guest retries with the EXACT SAME invite link -> slot was freed, retry succeeds!
    clock.fetch_add(5_000, Ordering::SeqCst);
    let mut g2_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let kp2 = STANDARD.encode(
        MlsSession::new_guest(&room_id, "g2-retry")
            .unwrap()
            .generate_key_package()
            .unwrap(),
    );
    send_msg(
        &mut g2_ws,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token: invite_token.clone(),
            key_package_b64: kp2.clone(),
            client_join_nonce: "nonce-r2".into(),
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut g2_ws).await,
        RelayToClient::JoinPending { .. }
    ));
    g2_ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Failed resume attempt at t=200s must NOT extend the original hold deadline (t=300s).
    clock.fetch_add(160_000, Ordering::SeqCst);
    let mut bad_resume_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut bad_resume_ws,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: admin_id.clone(),
            resume_token: "wrong-token".into(),
            resume_attempt_id: "bad-resume-1".into(),
            last_epoch: 0,
        },
    )
    .await;
    match recv_msg(&mut bad_resume_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "invalid_resume_token"),
        other => panic!("expected invalid_resume_token, got {other:?}"),
    }

    // Advance past original t=300s invite/hold deadline (t=301s, without sweeper!) -> MUST fail & close room!
    clock.fetch_add(101_000, Ordering::SeqCst);
    let mut late_admin_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut late_admin_ws,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: admin_id,
            resume_token: admin_resume,
            resume_attempt_id: "late-resume-after-301s".into(),
            last_epoch: 0,
        },
    )
    .await;
    match recv_msg(&mut late_admin_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "resume_expired"),
        other => panic!("expected resume_expired past hold deadline, got {other:?}"),
    }
    assert_eq!(state.active_room_count().await, 0);

    // Expired invite link must also be rejected.
    let mut late_guest_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut late_guest_ws,
        &ClientToRelay::JoinRoom {
            room_id,
            invite_token,
            key_package_b64: kp2,
            client_join_nonce: "nonce-r3".into(),
        },
    )
    .await;
    match recv_msg(&mut late_guest_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "room_not_found"),
        other => panic!("expected room_not_found after hold expiry, got {other:?}"),
    }
}

#[tokio::test]
async fn invite_hold_is_capped_at_room_expiry_and_panic_wipe_or_leave_ends_immediately() {
    // Subcase A: Invite hold capped at original 5-minute room TTL.
    let (url, state, clock) =
        spawn_test_relay_with_clock(RelayConfig::default(), 30_000_000, false).await;

    let mut admin_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let mut admin_key = AdminSigningKey::generate("pending").unwrap();
    let short_policy = RoomPolicy::new(300, 300).unwrap(); // 5m room TTL
    send_msg(
        &mut admin_ws,
        &ClientToRelay::CreateRoom {
            admin_pubkey_b64: admin_key.verifying_key_b64(),
            initial_policy: short_policy,
        },
    )
    .await;
    let (room_id, admin_id, admin_resume) = match recv_msg(&mut admin_ws).await {
        RelayToClient::RoomCreated {
            room_id,
            participant_id,
            resume_token,
            ..
        } => (room_id, participant_id, resume_token),
        other => panic!("expected RoomCreated, got {other:?}"),
    };
    admin_key.rebind_room(&room_id);
    let init_cmd = admin_key
        .sign_command(
            0,
            AdminCommandPayload::SetPolicy {
                msg_ttl_secs: 300,
                room_ttl_secs: 300,
            },
        )
        .unwrap();
    send_msg(
        &mut admin_ws,
        &ClientToRelay::AdminCommand {
            signed_cmd: init_cmd,
        },
    )
    .await;
    let _ = recv_msg(&mut admin_ws).await; // PolicyUpdated

    // At t=240s, register a 300s invite (capped at room expiry t=300s) and disconnect.
    clock.fetch_add(240_000, Ordering::SeqCst);
    let _inv = register_invite(&mut admin_ws, &mut admin_key, 0).await;
    admin_ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(state.active_room_count().await, 1);

    // At t=300s (room expiry), room MUST end even though only 60s elapsed since disconnect.
    clock.fetch_add(60_000, Ordering::SeqCst);
    let mut late_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut late_ws,
        &ClientToRelay::ResumeSession {
            room_id,
            participant_id: admin_id,
            resume_token: admin_resume,
            resume_attempt_id: "capped-room-expiry".into(),
            last_epoch: 0,
        },
    )
    .await;
    match recv_msg(&mut late_ws).await {
        RelayToClient::Error { code, .. } => assert_eq!(code, "room_expired"),
        other => panic!("expected room_expired, got {other:?}"),
    }
    assert_eq!(state.active_room_count().await, 0);

    // Subcase B: Panic-Wipe ends room immediately despite an open unused invite!
    let (mut admin_ws_b, room_id_b, _, _, mut admin_key_b, _) = create_initialized_room(&url).await;
    let _inv_b = register_invite(&mut admin_ws_b, &mut admin_key_b, 0).await;
    let wipe_cmd = admin_key_b
        .sign_command(0, AdminCommandPayload::PanicWipe)
        .unwrap();
    send_msg(
        &mut admin_ws_b,
        &ClientToRelay::AdminCommand {
            signed_cmd: wipe_cmd,
        },
    )
    .await;
    match recv_msg(&mut admin_ws_b).await {
        RelayToClient::PanicWipeConfirmed { room_id } => assert_eq!(room_id, room_id_b),
        other => panic!("expected PanicWipeConfirmed, got {other:?}"),
    }
    assert_eq!(
        state.active_room_count().await,
        0,
        "PanicWipe must destroy room immediately even when unused invite exists"
    );

    // Subcase C: Explicit LeaveRoom by admin ends room immediately despite an open unused invite!
    let (mut admin_ws_c, _, _, _, mut admin_key_c, _) = create_initialized_room(&url).await;
    let _inv_c = register_invite(&mut admin_ws_c, &mut admin_key_c, 0).await;
    send_msg(&mut admin_ws_c, &ClientToRelay::LeaveRoom).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        state.active_room_count().await,
        0,
        "explicit admin LeaveRoom must destroy room immediately even when unused invite exists"
    );
}

#[tokio::test]
async fn waiting_guest_before_admin_disconnect_still_uses_invite_hold_deadline() {
    let cfg = RelayConfig {
        invite_ttl_secs: 300,
        admin_reconnect_grace_secs: 300,
        reconnect_grace_secs: 60,
        join_reservation_ttl_secs: 120,
        ..Default::default()
    };
    let (url, state, clock) = spawn_test_relay_with_clock(cfg, 40_000_000, false).await;
    let (mut admin_ws, room_id, admin_id, admin_resume, mut admin_key, mut admin_mls) =
        create_initialized_room(&url).await;
    let admin_pk = admin_key.verifying_key_bytes();
    let admin_fp = admin_key.fingerprint();

    let invite_token = register_invite(&mut admin_ws, &mut admin_key, 0).await;

    // Guest opens the invite link BEFORE Safari drops the admin's WebSocket!
    let mut guest_ws = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    let mut guest_mls = MlsSession::new_guest(&room_id, "guest-early").unwrap();
    let guest_kp = STANDARD.encode(guest_mls.generate_key_package().unwrap());
    send_msg(
        &mut guest_ws,
        &ClientToRelay::JoinRoom {
            room_id: room_id.clone(),
            invite_token,
            key_package_b64: guest_kp,
            client_join_nonce: "nonce-early-1".into(),
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut guest_ws).await,
        RelayToClient::JoinPending { .. }
    ));
    // GuestJoinRequest was sent to admin's backgrounded socket, which never completes it before closing.
    assert!(matches!(
        recv_msg(&mut admin_ws).await,
        RelayToClient::GuestJoinRequest { .. }
    ));

    // Now admin's WebSocket drops while ONLY the waiting guest socket is still connected.
    admin_ws.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(state.active_room_count().await, 1);

    // Advance clock 90 seconds (> 60s normal reconnect window!) and run sweeper.
    // The waiting guest socket MUST NOT have forced the 60s normal window.
    clock.fetch_add(90_000, Ordering::SeqCst);
    state.sweep_once().await;
    assert_eq!(
        state.active_room_count().await,
        1,
        "room must survive >60s when only a waiting guest was connected at admin disconnect"
    );

    // Admin resumes at t=95s (> 60s!) -> receives SessionResumed AND re-forwarded GuestJoinRequest!
    clock.fetch_add(5_000, Ordering::SeqCst);
    let mut admin_ws2 = connect_ws(&url, "https://geistr.pages.dev").await.unwrap();
    send_msg(
        &mut admin_ws2,
        &ClientToRelay::ResumeSession {
            room_id: room_id.clone(),
            participant_id: admin_id,
            resume_token: admin_resume,
            resume_attempt_id: "admin-resume-with-early-guest".into(),
            last_epoch: 0,
        },
    )
    .await;
    match recv_msg(&mut admin_ws2).await {
        RelayToClient::SessionResumed { epoch, .. } => assert_eq!(epoch, 0),
        other => panic!("expected SessionResumed after >60s, got {other:?}"),
    }

    let (res_id, guest_id, kp_b64) = match recv_msg(&mut admin_ws2).await {
        RelayToClient::GuestJoinRequest {
            reservation_id,
            guest_id,
            key_package_b64,
        } => (reservation_id, guest_id, key_package_b64),
        other => panic!("expected re-forwarded GuestJoinRequest on admin resume, got {other:?}"),
    };

    let staged = admin_mls
        .stage_add_member(&STANDARD.decode(&kp_b64).unwrap())
        .unwrap();
    send_msg(
        &mut admin_ws2,
        &ClientToRelay::CompleteJoin {
            reservation_id: res_id,
            guest_id,
            commit_id: "admit-early-guest".into(),
            expected_epoch: 0,
            commit_b64: STANDARD.encode(&staged.commit_bytes),
            welcome_b64: STANDARD.encode(&staged.welcome_bytes),
            new_epoch: 1,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut admin_ws2).await,
        RelayToClient::CommitAccepted { new_epoch: 1, .. }
    ));
    admin_mls.apply_pending_commit().unwrap();

    match recv_msg(&mut guest_ws).await {
        RelayToClient::JoinAccepted {
            welcome_b64,
            epoch,
            members,
            ..
        } => {
            assert_eq!(epoch, 1);
            assert_eq!(members.len(), 2);
            let joined_ep = guest_mls
                .join_from_welcome(
                    &STANDARD.decode(&welcome_b64).unwrap(),
                    &admin_pk,
                    &admin_fp,
                )
                .unwrap();
            assert_eq!(joined_ep, 1);
        }
        other => panic!("expected JoinAccepted for early waiting guest, got {other:?}"),
    }
}
