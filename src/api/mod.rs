//! axum `Router` assembly and shared HTTP concerns.

pub mod dto;
pub mod flaresolverr;
pub mod native;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde_json::json;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// The full router. `body_limit` caps request bodies (default 2 MiB).
///
/// Every route is gated behind `[server].api_key` (when configured) **except**
/// `GET /health` (used by liveness probes / reverse proxies before they can
/// know a key), the vendored noVNC static assets (plain JS/HTML, not secret,
/// and loaded by a browser navigating there directly — it can't attach a
/// custom header), and the VNC websocket upgrade (browsers can't set custom
/// headers on a WebSocket handshake either; it is instead gated by its own
/// per-session token — see `vnc::session::SessionManager`).
pub fn router(state: AppState) -> Router {
    let body_limit = 2 * 1024 * 1024;

    let protected = Router::new()
        // native cobweb-compatible + extensions
        .route("/v1/resolve", post(native::resolve))
        .route("/v1/navigate", post(native::navigate))
        .route("/v1/fetch", post(native::fetch))
        .route("/v1/eval", post(native::eval))
        .route("/v1/sniff", post(native::sniff))
        .route("/v1/session/start", post(native::session_start))
        .route("/v1/session/{id}/close", post(native::session_close))
        .route("/v1/session/current", get(native::session_current))
        .route("/v1/jar", get(native::jar_list))
        .route("/v1/jar/{domain}", delete(native::jar_delete))
        .route("/metrics", get(native::metrics))
        // FlareSolverr-compatible
        .route("/v1", post(flaresolverr::handle))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    let mut app = Router::new()
        .route("/health", get(native::health))
        .route("/v1/session/{id}/vnc-ws", get(native::vnc_ws))
        .merge(protected);

    // Vendored noVNC static assets (git submodule vendor/novnc, or /opt/novnc
    // in the image). 404s harmlessly if not present.
    #[cfg(feature = "vnc")]
    {
        if let Some(dir) = novnc_dir() {
            app = app.nest_service("/vnc", tower_http::services::ServeDir::new(dir));
        }
    }

    app.layer(RequestBodyLimitLayer::new(body_limit))
        .layer(TraceLayer::new_for_http())
        // Outermost: a panic in any handler (or inner layer) becomes a 500
        // instead of killing the connection task / tripping the runtime.
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

use crate::util::constant_time_eq;

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": "missing or invalid API key",
            "kind": "unauthorized",
        })),
    )
        .into_response()
}

async fn require_api_key(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let Some(key) = st.config.server.effective_api_key() else {
        // No key configured: unauthenticated by operator choice (main.rs warns
        // loudly at startup if this is paired with a non-loopback bind).
        return next.run(req).await;
    };

    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        });

    match provided {
        Some(p) if constant_time_eq(p, key) => next.run(req).await,
        _ => unauthorized(),
    }
}

#[cfg(feature = "vnc")]
fn novnc_dir() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    // HYPHA_NOVNC is the deprecated pre-rename name, still honoured.
    std::env::var_os("COBWEB_NOVNC")
        .or_else(|| std::env::var_os("HYPHA_NOVNC"))
        .map(PathBuf::from)
        .into_iter()
        .chain(
            ["vendor/novnc", "/opt/novnc"]
                .into_iter()
                .map(PathBuf::from),
        )
        .find(|p| p.join("vnc_lite.html").is_file() || p.join("vnc.html").is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_str_eq_semantics() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
