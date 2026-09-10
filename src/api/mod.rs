//! axum `Router` assembly and shared HTTP concerns.

pub mod dto;
pub mod flaresolverr;
pub mod native;

use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// The full router. `body_limit` caps request bodies (default 2 MiB).
pub fn router(state: AppState) -> Router {
    let body_limit = 2 * 1024 * 1024;

    let mut app = Router::new()
        .route("/health", get(native::health))
        // native cobweb-compatible + extensions
        .route("/v1/resolve", post(native::resolve))
        .route("/v1/navigate", post(native::navigate))
        .route("/v1/fetch", post(native::fetch))
        .route("/v1/eval", post(native::eval))
        .route("/v1/sniff", post(native::sniff))
        .route("/v1/session/start", post(native::session_start))
        .route("/v1/session/{id}/close", post(native::session_close))
        .route("/v1/session/current", get(native::session_current))
        .route("/v1/session/{id}/vnc-ws", get(native::vnc_ws))
        .route("/v1/jar", get(native::jar_list))
        .route("/v1/jar/{domain}", delete(native::jar_delete))
        .route("/metrics", get(native::metrics))
        // FlareSolverr-compatible
        .route("/v1", post(flaresolverr::handle));

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
