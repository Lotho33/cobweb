//! Request/response bodies for the native API (DESIGN.md §6.1).
//!
//! Field names are locked to what mycelium's `browser_client.go` sends/expects
//! — `/v1/navigate` in particular must answer with exactly `{html, final_url}`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fastpath::StreamKind;
use crate::jar::Cookie;
use crate::pipeline::{Mode, ViaTier};

/// Accepts either `"*.m3u8"` or `["*.m3u8", "*.mpd"]` for `url_pattern`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

/// Bounds applied to every caller-supplied `timeout_ms`. Without an upper
/// bound, a request naming an absurd timeout (accidentally or not) holds one
/// of the browser tier's `max_contexts` semaphore permits for that long —
/// repeat it `max_contexts` times and every other browser-tier request queues
/// indefinitely behind it. `flaresolverr.rs`'s `request.get` already clamped
/// its own `maxTimeout` the same way; these are shared so every entry point
/// agrees.
pub const MIN_TIMEOUT_MS: u64 = 1_000;
pub const MAX_TIMEOUT_MS: u64 = 180_000;

pub fn clamp_timeout_ms(ms: u64) -> u64 {
    ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS)
}

/// `explicit` (the request's `timeout_ms`) if set, else `default_ms`
/// (`[browser].nav_timeout_ms` from config — previously parsed and stored but
/// never actually consulted; every call site hard-coded 30s instead).  Either
/// way the result is clamped to `[MIN_TIMEOUT_MS, MAX_TIMEOUT_MS]`.
fn ms_to_duration(explicit: Option<u64>, default_ms: u64) -> Duration {
    Duration::from_millis(clamp_timeout_ms(explicit.unwrap_or(default_ms)))
}

// ─── POST /v1/resolve ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ResolveRequest {
    pub url: String,
    #[serde(default)]
    pub egress: Option<String>,
    #[serde(default)]
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub url_pattern: Option<OneOrMany>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub block_resources: Option<bool>,
}

impl ResolveRequest {
    pub fn timeout(&self, default_ms: u64) -> Duration {
        ms_to_duration(self.timeout_ms, default_ms)
    }
}

// ─── POST /v1/navigate ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct NavigateRequest {
    pub url: String,
    /// Accepted for wire compatibility (DESIGN.md §6.1's documented
    /// `/v1/navigate` contract) but **ignored**: this handler only ever runs
    /// the fast-path fetch (M1), which has no notion of "wait for network
    /// idle" / "wait for a selector" — there is no browser here to wait on.
    /// `native::navigate` logs at `debug` when this is set to a non-default
    /// value so an operator relying on it notices, instead of it being
    /// silently swallowed.
    #[serde(default)]
    pub wait_for: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub egress: Option<String>,
    // Debug/test-bench knob (DESIGN.md "fast-path as segment downloader?"
    // experiment): /v1/navigate normally carries no extra headers, but a
    // cross-origin CDN fetch (a media segment referred by a different page)
    // gets rejected by anti-hotlink checks without one. Threaded straight
    // into the fast-path request's Referer — not persisted to the jar.
    #[serde(default)]
    pub referer: Option<String>,
    // Same test-bench knob, generalized: arbitrary extra headers (Origin,
    // Sec-Fetch-*, …) for probing which one a given anti-hotlink check
    // actually wants. `referer` above stays as sugar for the common case.
    #[serde(default)]
    pub extra_headers: Option<std::collections::HashMap<String, String>>,
}

impl NavigateRequest {
    pub fn timeout(&self, default_ms: u64) -> Duration {
        ms_to_duration(self.timeout_ms, default_ms)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NavigateResponse {
    pub html: String,
    pub final_url: String,
    // Upstream HTTP status, so a caller probing "does the fast-path fingerprint
    // get past this 403" (rather than actually wanting the page) can tell a
    // real reject from a same-shaped 200. Previously silently dropped —
    // navigate_fastpath always returned Ok even on a non-2xx upstream status.
    pub status: u16,
}

// ─── POST /v1/eval ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct EvalRequest {
    pub url: String,
    pub js: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub egress: Option<String>,
}

impl EvalRequest {
    pub fn timeout(&self, default_ms: u64) -> Duration {
        ms_to_duration(self.timeout_ms, default_ms)
    }
}

// ─── POST /v1/sniff ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SniffRequest {
    pub trigger_url: String,
    pub url_pattern: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub egress: Option<String>,
}

impl SniffRequest {
    pub fn timeout(&self, default_ms: u64) -> Duration {
        ms_to_duration(self.timeout_ms, default_ms)
    }
}

// ─── session ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SessionStartRequest {
    pub url: String,
    #[serde(default)]
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub egress: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionCloseRequest {
    /// Write the solved storage_state back to the jar. Absent field (or an
    /// empty request body) = true, for older callers that close with no body.
    #[serde(default = "default_true")]
    pub save_cookies: bool,
}

fn default_true() -> bool {
    true
}

// ─── typed responses (previously ad-hoc `json!({...})` in api/native.rs) ─────
//
// Handlers built these by hand with `serde_json::json!`, so the wire shape
// documented in DESIGN.md §6.1 was enforced only by the handler code
// matching the doc, not by the compiler — a refactor renaming a field like
// `stream_url` would silently change the JSON mycelium parses instead of
// failing to build. These structs give the same shapes a fixed, checked
// definition; `headers` stays a `Value` object (built by
// `native::headers_to_map`) rather than `Vec<(String, String)>` to keep the
// wire format (`{"name": "value"}`) unchanged.

#[derive(Debug, Clone, Serialize)]
pub struct ResolveResponse {
    pub stream_url: String,
    pub kind: StreamKind,
    pub headers: Value,
    pub cookies: Vec<Cookie>,
    pub via_tier: ViaTier,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SniffResponse {
    pub intercepted_url: String,
    pub headers: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvalResponse {
    pub result: String,
}

// ─── GET /health ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub ready: bool,
    /// Browser engine: `"none"` in M1.
    pub engine: String,
    pub fast_engine: String,
    pub contexts_in_use: usize,
    pub jar_domains: usize,
    pub egress_profiles: Vec<String>,
    pub uptime_secs: u64,
    pub version: String,
}
