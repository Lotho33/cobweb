//! `GET/PATCH /v1/settings` — runtime CRUD for `RuntimeSettings`
//! (`src/settings.rs`): DNS servers + a handful of timeout/TTL knobs.
//! Mirrors `src/api/blocklist.rs`: state cobweb owns and persists itself,
//! driven entirely over HTTP (typically by mycelium's dashboard) instead of
//! `config.toml`. Gated by the same `require_api_key` middleware as every
//! other `/v1/*` route (`src/api/mod.rs`) — no separate admin auth.

use axum::extract::State;
use axum::Json;

use crate::error::Result;
use crate::settings::{SettingsPatch, SettingsView};
use crate::state::AppState;

pub async fn get(State(st): State<AppState>) -> Json<SettingsView> {
    Json(st.settings.view())
}

/// Applies the patch, then pushes the jar TTL/fail-streak and browser
/// idle-shutdown values into their live owners (`Jar`, `CdpEngine` via the
/// `BrowserEngine` trait) — `RuntimeSettings` itself only holds/persists
/// them; `Jar`/`CdpEngine` are the ones actually consulted on the jar/
/// browser hot paths, so a change needs to reach them explicitly. DNS and
/// the two plain-read knobs (`nav_timeout_ms`,
/// `flaresolverr_session_ttl_secs`) need no such push — every reader already
/// goes through `RuntimeSettings` live.
pub async fn patch(
    State(st): State<AppState>,
    Json(req): Json<SettingsPatch>,
) -> Result<Json<SettingsView>> {
    let view = st.settings.apply(req).await?;
    st.jar.set_default_ttl_secs(view.jar_default_ttl_secs);
    st.jar.set_fail_streak(view.jar_fail_streak);
    if let Some(b) = &st.browser {
        b.set_idle_shutdown_secs(view.idle_shutdown_secs);
    }
    Ok(Json(view))
}
