//! One error type for the whole crate, plus its mapping to HTTP responses.
//!
//! Handlers return `Result<T>`; axum turns `CobwebError` into a JSON body
//! `{ "error": "...", "kind": "..." }` with an appropriate status code.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub type Result<T, E = CobwebError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum CobwebError {
    #[error("config error: {0}")]
    Config(String),

    /// Request named an egress that isn't configured.
    #[error("unknown egress `{0}`")]
    UnknownEgress(String),

    /// Named egress is configured but its proxy failed the health check.
    /// Fail-closed: we never silently fall back to `direct`.
    #[error("egress `{name}` is unavailable: {reason}")]
    EgressUnavailable { name: String, reason: String },

    /// The caller asked for `mode = "fast"` (or the browser is disabled) but the
    /// target needs a browser we won't launch.
    #[error("would need a browser: {0}")]
    NeedsBrowser(String),

    /// Landed on a challenge and there's no way to solve it in this mode
    /// (no browser, no FlareSolverr, no VNC). Carries the domain so the
    /// dashboard can offer a manual solve.
    #[error("challenge on `{domain}` needs a manual solve")]
    NeedsManualSolve { domain: String },

    /// Fast-path ran but found no stream URL.
    #[error("no stream URL found for {0}")]
    NotResolved(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    /// Target URL is refused by the SSRF guard (resolves to a private / loopback
    /// / link-local / metadata address). See `[server].allow_private_targets`.
    #[error("blocked target: {0}")]
    Blocked(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("upstream fetch failed: {0}")]
    Upstream(String),

    #[error("browser tier failed: {0}")]
    Browser(String),

    #[error("not implemented until a later milestone: {0}")]
    NotImplemented(&'static str),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl CobwebError {
    /// Short machine-readable tag, useful for metrics and client branching.
    pub fn kind(&self) -> &'static str {
        match self {
            CobwebError::Config(_) => "config",
            CobwebError::UnknownEgress(_) => "unknown_egress",
            CobwebError::EgressUnavailable { .. } => "egress_unavailable",
            CobwebError::NeedsBrowser(_) => "needs_browser",
            CobwebError::NeedsManualSolve { .. } => "needs_manual_solve",
            CobwebError::NotResolved(_) => "not_resolved",
            CobwebError::BadRequest(_) => "bad_request",
            CobwebError::Blocked(_) => "blocked",
            CobwebError::Conflict(_) => "conflict",
            CobwebError::Upstream(_) => "upstream",
            CobwebError::Browser(_) => "browser",
            CobwebError::NotImplemented(_) => "not_implemented",
            CobwebError::Io(_) => "io",
            CobwebError::Other(_) => "internal",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            CobwebError::BadRequest(_) => StatusCode::BAD_REQUEST,
            CobwebError::Blocked(_) => StatusCode::FORBIDDEN,
            CobwebError::Conflict(_) => StatusCode::CONFLICT,
            CobwebError::UnknownEgress(_) => StatusCode::BAD_REQUEST,
            CobwebError::EgressUnavailable { .. } => StatusCode::BAD_GATEWAY,
            CobwebError::Upstream(_) => StatusCode::BAD_GATEWAY,
            CobwebError::Browser(_) => StatusCode::BAD_GATEWAY,
            CobwebError::NeedsBrowser(_) => StatusCode::UNPROCESSABLE_ENTITY,
            // Not an error the caller can retry as-is, but not a server fault
            // either — the dashboard is expected to act on it.
            CobwebError::NeedsManualSolve { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            CobwebError::NotResolved(_) => StatusCode::UNPROCESSABLE_ENTITY,
            CobwebError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            CobwebError::Config(_) | CobwebError::Io(_) | CobwebError::Other(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl From<crate::browser::BrowserError> for CobwebError {
    fn from(e: crate::browser::BrowserError) -> Self {
        use crate::browser::BrowserError as B;
        match e {
            // Challenge carries no domain here; callers that can name the domain
            // (the pipeline) intercept it before converting.
            B::Challenge => CobwebError::Browser("landed on a challenge page".into()),
            B::Unavailable(m) => CobwebError::Browser(format!("engine unavailable: {m}")),
            B::Timeout(d) => CobwebError::Browser(format!("timed out after {d:?}")),
            B::NoMatch => CobwebError::NotResolved("no request matched the pattern".into()),
            B::Cdp(m) => CobwebError::Browser(format!("cdp: {m}")),
            B::Other(e) => CobwebError::Other(e),
        }
    }
}

impl IntoResponse for CobwebError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            tracing::error!(error = %self, kind = self.kind(), "request failed");
        } else {
            tracing::debug!(error = %self, kind = self.kind(), "request rejected");
        }
        let mut body = json!({ "error": self.to_string(), "kind": self.kind() });
        if let CobwebError::NeedsManualSolve { domain } = &self {
            body["domain"] = json!(domain);
            body["needs_manual_solve"] = json!(true);
        }
        (status, Json(body)).into_response()
    }
}
