use std::net::SocketAddr;

use relay_server::build_router;
use relay_server::config::RelayConfig;
use relay_server::state::RelayState;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config = RelayConfig::from_env();
    let addr: SocketAddr = format!("{}:{}", config.bind_addr, config.port)
        .parse()
        .expect("invalid BIND_ADDR/PORT");

    info!(
        addr = %addr,
        allowed_origin = %config.allowed_origin,
        allow_localhost_dev = config.allow_localhost_dev,
        invite_ttl_secs = config.invite_ttl_secs,
        keepalive_interval_secs = config.keepalive_interval_secs,
        max_concurrent_rooms = config.max_concurrent_rooms,
        "starting geistr zero-trace relay"
    );

    let state = RelayState::new(config);
    let _sweeper = state.spawn_sweeper();

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("relay server exited with error");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received; all ephemeral rooms terminating");
}
