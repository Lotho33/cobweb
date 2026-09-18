//! `GET/PATCH /v1/blocklist`, `POST/PATCH/DELETE /v1/blocklist/sources`,
//! `POST /v1/blocklist/refresh` — runtime CRUD for `[blocklist]` sources
//! (`src/blocklist.rs`). Mirrors how `GET/DELETE /v1/jar` manages the cookie
//! jar: state cobweb owns and persists itself, driven entirely over HTTP
//! (typically by mycelium's dashboard) instead of `config.toml`. Gated by
//! the same `require_api_key` middleware as every other `/v1/*` route
//! (`src/api/mod.rs`) — no separate admin auth.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::blocklist::{BlocklistSourceView, BlocklistStatusView};
use crate::error::Result;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct AddSourceRequest {
    pub url: String,
}

pub async fn status(State(st): State<AppState>) -> Json<BlocklistStatusView> {
    Json(st.blocklist.status().await)
}

pub async fn set_enabled(
    State(st): State<AppState>,
    Json(req): Json<SetEnabledRequest>,
) -> Json<BlocklistStatusView> {
    Json(st.blocklist.set_enabled(req.enabled).await)
}

pub async fn add_source(
    State(st): State<AppState>,
    Json(req): Json<AddSourceRequest>,
) -> Result<Json<BlocklistSourceView>> {
    let view = st.blocklist.add_source(req.url, &st.fast).await?;
    Ok(Json(view))
}

pub async fn set_source_enabled(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SetEnabledRequest>,
) -> Result<Json<BlocklistSourceView>> {
    let view = st.blocklist.set_source_enabled(&id, req.enabled).await?;
    Ok(Json(view))
}

pub async fn remove_source(State(st): State<AppState>, Path(id): Path<String>) -> Json<Value> {
    let removed = st.blocklist.remove_source(&id).await;
    Json(json!({ "ok": true, "removed": removed }))
}

/// Force an immediate re-fetch of every enabled source (a dashboard
/// "refresh now" button) instead of waiting for the periodic loop.
pub async fn refresh(State(st): State<AppState>) -> Json<BlocklistStatusView> {
    st.blocklist.refresh(&st.fast).await;
    Json(st.blocklist.status().await)
}
