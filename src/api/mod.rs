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
        .merge(protected)
        .layer(middleware::from_fn_with_state(state.clone(), check_host));

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

/// Does `req` carry the configured API key? (`false` when none is set.)
pub(crate) fn request_has_valid_key(st: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let Some(key) = st.config.server.effective_api_key() else {
        return false;
    };
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .is_some_and(|p| constant_time_eq(p, key))
}

/// DNS-rebinding guard for the *unauthenticated* API. A web page the
/// operator has open can re-point its own domain at `127.0.0.1` (or the
/// sidecar's LAN IP) and then call cobweb same-origin — no CORS preflight,
/// full access to `/v1/eval`, the jar, etc. Such a request necessarily
/// carries the attacker's domain in `Host`, so while no `api_key` is set,
/// only Hosts that can't be an attacker-registered name are accepted: an IP
/// literal, `localhost`/`*.localhost`, a single-label name (Docker/Compose
/// service names) or an explicit `[server].allowed_hosts` entry. With an
/// `api_key` the rebinding page has no key, so this check is skipped.
async fn check_host(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if st.config.server.effective_api_key().is_some() {
        return next.run(req).await;
    }
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().host());
    match host {
        // No Host at all: not a browser (they always send one).
        None => next.run(req).await,
        Some(h) if host_allowed(h, &st.config.server.allowed_hosts) => next.run(req).await,
        Some(h) => {
            tracing::warn!(host = %h, "refusing request with an unexpected Host header (DNS rebinding guard; see [server].allowed_hosts)");
            (
                StatusCode::MISDIRECTED_REQUEST,
                axum::Json(json!({
                    "error": "unexpected Host header; add it to [server].allowed_hosts or set [server].api_key",
                    "kind": "bad_host",
                })),
            )
                .into_response()
        }
    }
}

/// See [`check_host`]. `host` is a raw `Host` header value (`name[:port]`,
/// `[v6]:port`).
fn host_allowed(host: &str, extra: &[String]) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        // [v6]:port
        return rest
            .split(']')
            .next()
            .is_some_and(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok());
    } else {
        host.rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
            .map_or(host, |(name, _)| name)
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    // Special-use names that can never be registered in public DNS, so a
    // rebinding attacker can't own them: `.localhost` (RFC 6761), `.local`
    // (mDNS, RFC 6762), `.home.arpa` (RFC 8375) and `.internal` (reserved by
    // ICANN for private use — e.g. Docker's `host.docker.internal`).
    const PRIVATE_SUFFIXES: [&str; 4] = [".localhost", ".local", ".home.arpa", ".internal"];
    if name.parse::<std::net::IpAddr>().is_ok()
        || name == "localhost"
        || PRIVATE_SUFFIXES.iter().any(|s| name.ends_with(s))
        || (!name.is_empty() && !name.contains('.'))
    {
        return true;
    }
    extra
        .iter()
        .any(|a| a.trim().trim_end_matches('.').eq_ignore_ascii_case(&name))
}

async fn require_api_key(State(st): State<AppState>, req: Request, next: Next) -> Response {
    // No key configured: unauthenticated by operator choice (main.rs warns
    // loudly at startup if this is paired with a non-loopback bind).
    if st.config.server.effective_api_key().is_none() || request_has_valid_key(&st, req.headers()) {
        next.run(req).await
    } else {
        unauthorized()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_allowed_accepts_only_non_rebindable_names() {
        let extra = vec!["cobweb.example.org".to_string()];
        for ok in [
            "127.0.0.1:8191",
            "10.0.0.5",
            "[::1]:8191",
            "localhost:8191",
            "a.localhost",
            "cobweb:8191",
            "COBWEB",
            "cobweb.example.org",
            "cobweb.lan.internal:8191",
            "host.docker.internal:8191",
            "nas.local",
            "box.home.arpa",
        ] {
            assert!(host_allowed(ok, &extra), "{ok} should pass");
        }
        for bad in [
            "evil.example.com",
            "evil.example.com:8191",
            "127.0.0.1.nip.io",
            "[evil]:1",
        ] {
            assert!(!host_allowed(bad, &extra), "{bad} should be refused");
        }
    }

    #[test]
    fn constant_time_eq_matches_str_eq_semantics() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
