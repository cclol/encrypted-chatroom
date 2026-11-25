pub mod config;
pub mod state;
pub mod ws;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::routing::get;
use serde_json::json;

use crate::state::RelayState;
use crate::ws::ws_handler;

pub fn build_router(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}
