//! Request/response bodies for the native API (DESIGN.md §6.1).
//!
//! Field names are locked to what mycelium's `browser_client.go` sends/expects
//! — `/v1/navigate` in particular must answer with exactly `{html, final_url}`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::pipeline::Mode;

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

fn ms_to_duration(ms: Option<u64>, default: Duration) -> Duration {
    ms.map(Duration::from_millis).unwrap_or(default)
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
    pub fn timeout(&self) -> Duration {
        ms_to_duration(self.timeout_ms, Duration::from_secs(30))
    }
}

// ─── POST /v1/navigate ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct NavigateRequest {
    pub url: String,
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
    pub fn timeout(&self) -> Duration {
        ms_to_duration(self.timeout_ms, Duration::from_secs(30))
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
    pub fn timeout(&self) -> Duration {
        ms_to_duration(self.timeout_ms, Duration::from_secs(30))
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
    pub fn timeout(&self) -> Duration {
        ms_to_duration(self.timeout_ms, Duration::from_secs(30))
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
