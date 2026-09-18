//! Native cobweb-compatible handlers (DESIGN.md §6.1).
//!
//! `/health`, `/v1/resolve`, `/v1/navigate`, `/v1/jar` since M1; `/v1/sniff`
//! and `/v1/eval` since M2 (need `browser_engine = "chromium"`, else `422`).

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;

use crate::api::dto::*;
use crate::error::{CobwebError, Result};
use crate::pipeline::{self, ResolveParams};
use crate::state::AppState;

fn parse_url(raw: &str) -> Result<Url> {
    Url::parse(raw).map_err(|_| CobwebError::BadRequest(format!("not a valid URL: {raw}")))
}

/// `Vec<(name, value)>` -> JSON object, last-wins on duplicates.
fn headers_to_map(headers: &[(String, String)]) -> Value {
    let mut m = serde_json::Map::new();
    for (k, v) in headers {
        m.insert(k.clone(), json!(v));
    }
    Value::Object(m)
}

// ─── GET /health ────────────────────────────────────────────────────────────

pub async fn health(State(st): State<AppState>) -> Json<HealthResponse> {
    let jar_domains = st.jar.count().await;
    let (engine, contexts_in_use) = match &st.browser {
        Some(b) => (b.name().to_string(), b.contexts_in_use()),
        None => ("none".to_string(), 0),
    };
    Json(HealthResponse {
        ready: true,
        engine,
        fast_engine: st.fast.engine().into(),
        contexts_in_use,
        jar_domains,
        egress_profiles: st.egress.names(),
        uptime_secs: st.uptime().as_secs(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

// ─── POST /v1/resolve ───────────────────────────────────────────────────────

pub async fn resolve(
    State(st): State<AppState>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ResolveResponse>> {
    let url = parse_url(&req.url)?;
    let timeout = req.timeout(st.settings.nav_timeout_ms());
    let ResolveRequest {
        egress,
        proxy_url,
        mode,
        url_pattern,
        block_resources,
        block_trackers,
        ..
    } = req;
    let params = ResolveParams {
        url,
        egress_name: egress,
        proxy_url,
        mode: mode.unwrap_or_default(),
        url_pattern: url_pattern
            .map(OneOrMany::into_vec)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(pipeline::default_patterns),
        timeout,
        block_resources: block_resources.unwrap_or(true),
        block_trackers: block_trackers.unwrap_or(true),
    };

    let outcome = pipeline::resolve(&st, params).await?;

    Ok(Json(ResolveResponse {
        stream_url: outcome.stream.stream_url,
        kind: outcome.stream.kind,
        headers: headers_to_map(&outcome.stream.headers),
        cookies: outcome.stream.cookies,
        via_tier: outcome.via_tier,
        domain: outcome.domain,
    }))
}

// ─── POST /v1/navigate (fast-path only in M1) ───────────────────────────────

pub async fn navigate(
    State(st): State<AppState>,
    Json(req): Json<NavigateRequest>,
) -> Result<Json<NavigateResponse>> {
    let url = parse_url(&req.url)?;
    let timeout = req.timeout(st.settings.nav_timeout_ms());
    if req
        .wait_for
        .as_deref()
        .is_some_and(|w| !w.trim().is_empty())
    {
        // See the field doc on `NavigateRequest::wait_for`: this handler is
        // fast-path only and has no browser to wait on, so the value is
        // accepted (wire compat) but has no effect — surfaced here instead of
        // silently dropped.
        tracing::debug!(
            wait_for = req.wait_for.as_deref().unwrap_or_default(),
            "navigate: wait_for is ignored (fast-path only, no browser wait to apply it to)"
        );
    }
    let NavigateRequest {
        egress,
        proxy_url,
        referer,
        extra_headers,
        ..
    } = req;
    let r =
        pipeline::navigate_fastpath(&st, url, egress, proxy_url, referer, extra_headers, timeout)
            .await?;
    // mycelium's browser_client.go only reads html/final_url — status is
    // additive, ignored by that decoder, used only by the test bench.
    Ok(Json(NavigateResponse {
        html: r.html,
        final_url: r.final_url,
        status: r.status,
    }))
}

// ─── POST /v1/fetch — impersonated streaming GET proxy ──────────────────────
//
// mycelium's HLS proxy calls this so every upstream fetch rides ONE TLS/HTTP2
// fingerprint (wreq/BoringSSL) instead of a second impersonation stack on the
// mycelium side. cobweb applies the egress + jar cookies and streams the body
// straight back — it does NOT buffer or sniff (unlike /v1/navigate). All the
// caching/dedup/retry logic stays in mycelium's proxy. Unauthenticated like
// the rest of the API: keep it on a private network (see [server].bind).

#[derive(Debug, Deserialize)]
pub struct FetchProxyRequest {
    pub url: String,
    #[serde(default)]
    pub egress: Option<String>,
    #[serde(default)]
    pub proxy_url: Option<String>,
    /// Request-shaping headers to forward upstream (allowlisted below).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Attach jar cookies for the URL's registrable domain when the caller
    /// didn't pass its own `Cookie`. Default true.
    #[serde(default = "default_true")]
    pub use_jar: bool,
}

fn default_true() -> bool {
    true
}

/// Headers the proxy may forward upstream. Hop-by-hop and routing/identity
/// headers (Host, Authorization, X-Forwarded-*, Content-Length, …) are dropped.
fn fetch_header_allowed(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    n.starts_with("sec-fetch-")
        || matches!(
            n.as_str(),
            "referer"
                | "origin"
                | "cookie"
                | "user-agent"
                | "accept"
                | "accept-language"
                | "range"
                | "if-range"
                | "if-none-match"
                | "if-modified-since"
                | "x-requested-with"
        )
}

pub async fn fetch(
    State(st): State<AppState>,
    Json(req): Json<FetchProxyRequest>,
) -> Result<Response> {
    let url = parse_url(&req.url)?;
    let egress = st
        .egress
        .resolve(req.egress.as_deref(), req.proxy_url.as_deref())?;
    crate::ssrf::guard_egress(&egress, st.config.server.allow_private_targets).await?;
    st.egress.ensure_available(&egress).await?;
    crate::ssrf::guard_url(
        &url,
        egress.is_direct(),
        st.config.server.allow_private_targets,
    )
    .await?;

    // No per-request total timeout: it would cut a healthy long download mid
    // stream. raw_client carries connect + read-inactivity guards, and the
    // caller's context cancellation still tears the request down. `timeout_ms`
    // is accepted for compat but not applied here.
    let client = st.fast.raw_client(&egress)?;
    let mut rb = client.get(url.as_str());

    let caller_sent_cookie = req.headers.keys().any(|k| k.eq_ignore_ascii_case("cookie"));
    for (k, v) in &req.headers {
        if fetch_header_allowed(k) {
            rb = rb.header(k.as_str(), v.as_str());
        } else {
            tracing::debug!(header = %k, "fetch: dropping disallowed header");
        }
    }

    if req.use_jar && !caller_sent_cookie {
        if let Ok(domain) = pipeline::registrable_domain(&url) {
            let now = chrono::Utc::now().timestamp() as f64;
            if let Some(j) = st.jar.get_fresh(&domain, &egress).await {
                if let Some(ch) = j
                    .storage_state
                    .cookie_header(url.host_str().unwrap_or(""), now)
                {
                    rb = rb.header("cookie", ch);
                }
            }
        }
    }

    let resp = rb
        .send()
        .await
        .map_err(|e| CobwebError::Upstream(format!("GET {url}: {e}")))?;

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let final_url = resp.uri().to_string();

    // Curated passthrough. Deliberately NOT content-length / content-encoding /
    // transfer-encoding: wreq transparently decompresses gzip/brotli, so the
    // upstream length no longer matches the bytes streamed on.
    let mut out = HeaderMap::new();
    for name in [
        "content-type",
        "content-range",
        "accept-ranges",
        "cache-control",
        "last-modified",
        "etag",
        "expires",
        "vary",
    ] {
        if let Some(v) = resp.headers().get(name) {
            // `name` is a &'static str literal (infallible) and `v` is already
            // a parsed HeaderValue — clone the Bytes, don't re-parse.
            out.insert(HeaderName::from_static(name), v.clone());
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&final_url) {
        out.insert(HeaderName::from_static("x-cobweb-final-url"), hv);
    }
    out.insert(
        HeaderName::from_static("access-control-allow-origin"),
        HeaderValue::from_static("*"),
    );

    let mut response = Response::new(Body::from_stream(resp.bytes_stream()));
    *response.status_mut() = status;
    *response.headers_mut() = out;
    Ok(response)
}

// ─── POST /v1/sniff ─────────────────────────────────────────────────────────

pub async fn sniff(
    State(st): State<AppState>,
    Json(req): Json<SniffRequest>,
) -> Result<Json<SniffResponse>> {
    let trigger = parse_url(&req.trigger_url)?;
    let timeout = req.timeout(st.settings.nav_timeout_ms());
    let pattern = pipeline::normalize_sniff_pattern(req.url_pattern.trim());
    let SniffRequest {
        egress, proxy_url, ..
    } = req;

    let r =
        pipeline::browser_sniff(&st, trigger, vec![pattern], egress, proxy_url, timeout).await?;

    // mycelium's browser_client.go wants {intercepted_url, headers}.
    Ok(Json(SniffResponse {
        intercepted_url: r.intercepted_url,
        headers: headers_to_map(&r.headers),
    }))
}

// ─── POST /v1/eval ─────────────────────────────────────────────────────────

pub async fn eval(
    State(st): State<AppState>,
    Json(req): Json<EvalRequest>,
) -> Result<Json<EvalResponse>> {
    let url = parse_url(&req.url)?;
    let timeout = req.timeout(st.settings.nav_timeout_ms());
    let EvalRequest {
        js,
        egress,
        proxy_url,
        ..
    } = req;
    let v = pipeline::browser_eval(&st, url, js, egress, proxy_url, timeout).await?;

    // mycelium expects {result: "<string>"}: hand back strings verbatim,
    // JSON-encode anything else.
    let result = match v {
        Value::String(s) => s,
        Value::Null => String::new(),
        other => other.to_string(),
    };
    Ok(Json(EvalResponse { result }))
}

// ─── GET /metrics ──────────────────────────────────────────────────────────

pub async fn metrics(State(st): State<AppState>) -> ([(&'static str, &'static str); 1], String) {
    let contexts = st
        .browser
        .as_ref()
        .map(|b| b.contexts_in_use())
        .unwrap_or(0);
    let jar_domains = st.jar.count().await;
    let body = st
        .metrics
        .render(contexts, jar_domains, st.uptime().as_secs());
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

// ─── GET /v1/jar , DELETE /v1/jar/{domain} ──────────────────────────────────

pub async fn jar_list(State(st): State<AppState>) -> Json<Vec<crate::jar::JarSummary>> {
    Json(st.jar.list().await)
}

#[derive(Debug, Deserialize)]
pub struct JarDeleteQuery {
    #[serde(default)]
    pub egress: Option<String>,
}

pub async fn jar_delete(
    State(st): State<AppState>,
    Path(domain): Path<String>,
    Query(q): Query<JarDeleteQuery>,
) -> Result<Json<Value>> {
    // `egress` here is the jar *key* (profile name, or `direct`, or
    // `proxy-<host>-<port>`); default to `direct` when omitted.
    let key = q.egress.unwrap_or_else(|| "direct".to_string());
    let removed = st.jar.delete(&domain, &key).await?;
    Ok(Json(json!({ "ok": true, "removed": removed })))
}
