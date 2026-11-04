//! Optional HTTP service (`--features server`).
//!
//! Exposes the same engine over `POST /scan` so a future always-on deployment
//! can call it without spawning a process per request. Off by default: the CLI
//! is the integration path today (apps/api/src/analysis/rust-engine.ts).
//!
//! Build & run:
//!   cargo run --features server --bin codegate-scan-server

use axum::{routing::get, routing::post, Json, Router};
use codegate_scan_engine::{analyze_inputs, Finding, Manifest};

async fn health() -> &'static str {
    "ok"
}

async fn scan(Json(manifest): Json<Manifest>) -> Json<Vec<Finding>> {
    Json(analyze_inputs(&manifest.files))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan));

    let addr = std::env::var("SCAN_ENGINE_ADDR").unwrap_or_else(|_| "127.0.0.1:7878".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind scan-engine server");
    eprintln!("codegate-scan-server listening on {addr}");
    axum::serve(listener, app).await.expect("serve");
}
