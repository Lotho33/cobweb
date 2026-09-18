//! axum `Router` assembly and shared HTTP concerns.

pub mod blocklist;
pub mod dto;
pub mod flaresolverr;
pub mod native;
pub mod settings;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
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
/// know a key).
pub fn router(state: AppState) -> Router {
    let body_limit = 2 * 1024 * 1024;

    let protected = Router::new()
        // native cobweb-compatible + extensions
        .route("/v1/resolve", post(native::resolve))
        .route("/v1/navigate", post(native::navigate))
        .route("/v1/fetch", post(native::fetch))
        .route("/v1/eval", post(native::eval))
        .route("/v1/sniff", post(native::sniff))
        .route("/v1/jar", get(native::jar_list))
        .route("/v1/jar/{domain}", delete(native::jar_delete))
        .route(
            "/v1/blocklist",
            get(blocklist::status).patch(blocklist::set_enabled),
        )
        .route("/v1/blocklist/refresh", post(blocklist::refresh))
        .route("/v1/blocklist/sources", post(blocklist::add_source))
        .route(
            "/v1/blocklist/sources/{id}",
            patch(blocklist::set_source_enabled).delete(blocklist::remove_source),
        )
        .route("/v1/settings", get(settings::get).patch(settings::patch))
        .route("/metrics", get(native::metrics))
        // FlareSolverr-compatible
        .route("/v1", post(flaresolverr::handle))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    let app = Router::new()
        .route("/health", get(native::health))
        .merge(protected);

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
