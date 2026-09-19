//! The tiered `resolve()` orchestrator and the `Tier` trait (DESIGN.md §2, §8).
//!
//! Tier 2 (fast path) then Tier 3 (browser sniff, when `browser_engine =
//! "chromium"`), then optionally Tier 3b (an operator-configured external
//! FlareSolverr). If every tier fails on a challenge, `resolve()` returns
//! `CobwebError::NeedsManualSolve` — a terminal, structured outcome; cobweb
//! itself has no manual-solve capability of its own.

use std::borrow::Cow;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::browser::{BrowserEngine, BrowserError, ContextOptions, SniffHit};
use crate::error::{CobwebError, Result};
use crate::fastpath::{
    looks_like_cloudflare_challenge, sniff_stream_url, ttl_hint_from, FetchRequest, StreamKind,
};
use crate::jar::{Cookie, JarEntry, StorageState};
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Tier 2 only. Fails fast if a browser would be needed.
    Fast,
    /// Full automated pipeline (fast path, then browser sniff, then an
    /// optional external FlareSolverr).
    #[default]
    Auto,
    /// Skip Tier 2, straight to the browser.
    Browser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ViaTier {
    Fastpath,
    Browser,
    Flaresolverr,
    Manual,
    Ytdlp,
}

/// Normalised inputs for one `resolve()` call (API DTOs convert into this).
pub struct ResolveParams {
    pub url: Url,
    pub egress_name: Option<String>,
    pub proxy_url: Option<String>,
    pub mode: Mode,
    /// Glob(s) the stream URL must match. Default `*.m3u8`, `*.mpd`.
    pub url_pattern: Vec<String>,
    pub timeout: Duration,
    pub block_resources: bool,
    pub block_trackers: bool,
}

impl ResolveParams {
    pub fn new(url: Url) -> Self {
        Self {
            url,
            egress_name: None,
            proxy_url: None,
            mode: Mode::Auto,
            url_pattern: default_patterns(),
            timeout: Duration::from_secs(30),
            block_resources: true,
            block_trackers: true,
        }
    }
}

/// The default stream-URL globs. `resolve()` runs on every request and the vast
/// majority pass exactly these, so the compiled set is cached (see
/// [`globset_for`]) instead of rebuilt per call.
const DEFAULT_PATTERN_STRS: [&str; 2] = ["*.m3u8", "*.mpd"];

pub fn default_patterns() -> Vec<String> {
    DEFAULT_PATTERN_STRS.iter().map(|s| s.to_string()).collect()
}

static DEFAULT_GLOBSET: LazyLock<GlobSet> =
    LazyLock::new(|| build_globset(&default_patterns()).expect("default patterns compile"));

/// Borrow the process-wide cached set when `patterns` is exactly the default,
/// otherwise compile a fresh one for this call.
fn globset_for(patterns: &[String]) -> Result<Cow<'static, GlobSet>> {
    if patterns.iter().map(String::as_str).eq(DEFAULT_PATTERN_STRS) {
        Ok(Cow::Borrowed(&*DEFAULT_GLOBSET))
    } else {
        Ok(Cow::Owned(build_globset(patterns)?))
    }
}

/// A resolved stream plus the context needed to fetch it elsewhere.
#[derive(Debug, Clone, Serialize)]
pub struct StreamResult {
    pub stream_url: String,
    pub kind: StreamKind,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<Cookie>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolveOutcome {
    #[serde(flatten)]
    pub stream: StreamResult,
    pub via_tier: ViaTier,
    pub domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalateReason {
    Challenge,
    NeedsJs,
    NotFound,
}

pub enum TierOutcome {
    Resolved(StreamResult),
    Escalate(EscalateReason),
    Failed(CobwebError),
}

/// Per-call context threaded through the tiers.
pub struct ResolveCtx<'a> {
    pub url: &'a Url,
    pub registrable_domain: &'a str,
    pub egress: &'a crate::egress::Egress,
    pub mode: Mode,
    pub url_pattern: &'a GlobSet,
    pub timeout: Duration,
    pub block_resources: bool,
    pub block_trackers: bool,
    /// Fresh jar entry seeding this call, if any.
    pub jar: Option<&'a JarEntry>,
    /// Optional JS to run after load during a browser sniff (`/v1/sniff` only).
    pub interact_js: Option<&'a str>,
}

#[async_trait]
pub trait Tier: Send + Sync {
    fn name(&self) -> &'static str;
    async fn try_resolve(&self, ctx: &ResolveCtx<'_>) -> TierOutcome;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 2 — fast path
// ─────────────────────────────────────────────────────────────────────────────

pub struct FastPathTier {
    client: Arc<dyn crate::fastpath::FastClient>,
}

impl FastPathTier {
    pub fn new(client: Arc<dyn crate::fastpath::FastClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Tier for FastPathTier {
    fn name(&self) -> &'static str {
        "fastpath"
    }

    async fn try_resolve(&self, ctx: &ResolveCtx<'_>) -> TierOutcome {
        let now = chrono::Utc::now().timestamp() as f64;
        let cookie_header = ctx.jar.and_then(|j| {
            j.storage_state
                .cookie_header(ctx.url.host_str().unwrap_or(""), now)
        });
        let ua = ctx
            .jar
            .map(|j| j.user_agent.as_str())
            .filter(|s| !s.is_empty());
        let al = ctx
            .jar
            .map(|j| j.accept_language.as_str())
            .filter(|s| !s.is_empty());

        let req = FetchRequest {
            url: ctx.url,
            egress: ctx.egress,
            user_agent: ua,
            accept_language: al,
            cookie_header: cookie_header.as_deref(),
            extra_headers: &[],
            timeout: ctx.timeout,
        };

        let mut resp = match self.client.fetch(req).await {
            Ok(r) => r,
            Err(e) => return TierOutcome::Failed(e),
        };

        if looks_like_cloudflare_challenge(resp.status, &resp.body, resp.header("server")) {
            tracing::info!(
                url = %crate::util::redact_url_query(ctx.url),
                status = resp.status,
                "fast path hit a Cloudflare challenge"
            );
            return TierOutcome::Escalate(EscalateReason::Challenge);
        }
        if resp.status == 403 || resp.status == 429 {
            return TierOutcome::Escalate(EscalateReason::Challenge);
        }

        match sniff_stream_url(&resp.body, &resp.final_url) {
            Some(hit) if pattern_ok(ctx.url_pattern, &hit.url) => {
                // Cookies to hand back: jar cookies (if any) plus anything the
                // response just set.
                let mut state = ctx.jar.map(|j| j.storage_state.clone()).unwrap_or_default();
                state.merge_from(std::mem::take(&mut resp.set_cookies));

                TierOutcome::Resolved(StreamResult {
                    stream_url: hit.url.to_string(),
                    kind: hit.kind,
                    headers: replay_headers(ctx, &state),
                    cookies: state.cookies,
                })
            }
            Some(_) => TierOutcome::Escalate(EscalateReason::NotFound),
            None => TierOutcome::Escalate(EscalateReason::NeedsJs),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier 3 — browser sniff
// ─────────────────────────────────────────────────────────────────────────────

pub struct BrowserSniffTier {
    engine: Arc<dyn BrowserEngine>,
}

impl BrowserSniffTier {
    pub fn new(engine: Arc<dyn BrowserEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl Tier for BrowserSniffTier {
    fn name(&self) -> &'static str {
        "browser"
    }

    async fn try_resolve(&self, ctx: &ResolveCtx<'_>) -> TierOutcome {
        if let Err(e) = self.engine.ensure_ready().await {
            return TierOutcome::Failed(CobwebError::Browser(format!("engine not ready: {e}")));
        }

        let opts = ContextOptions {
            egress: ctx.egress.clone(),
            seed: ctx.jar.map(|j| j.storage_state.clone()),
            user_agent: ctx
                .jar
                .map(|j| j.user_agent.clone())
                .filter(|s| !s.is_empty()),
            accept_language: ctx
                .jar
                .map(|j| j.accept_language.clone())
                .filter(|s| !s.is_empty()),
            block_resources: ctx.block_resources,
            block_trackers: ctx.block_trackers,
        };

        let mut cx = match self.engine.acquire(opts).await {
            Ok(c) => c,
            Err(e) => return TierOutcome::Failed(e.into()),
        };

        let outcome = match cx.sniff(ctx.url, ctx.url_pattern, ctx.timeout, ctx.interact_js).await {
            Ok(hit) => {
                let state = cx.storage_state().await.unwrap_or_default();
                let kind = StreamKind::from_url(&hit.url).unwrap_or(StreamKind::Hls);
                let headers = browser_replay_headers(&hit, &state);
                TierOutcome::Resolved(StreamResult {
                    stream_url: hit.url.to_string(),
                    kind,
                    headers,
                    cookies: state.cookies,
                })
            }
            Err(BrowserError::Challenge) => TierOutcome::Escalate(EscalateReason::Challenge),
            Err(BrowserError::NoMatch | BrowserError::Timeout(_)) => {
                TierOutcome::Escalate(EscalateReason::NotFound)
            }
            Err(e) => TierOutcome::Failed(e.into()),
        };

        cx.close().await;
        outcome
    }
}

/// Replay set for a browser-sniffed stream: the request headers Chromium
/// actually sent (safelisted), plus a fresh `Cookie` from the final storage.
fn browser_replay_headers(hit: &SniffHit, state: &StorageState) -> Vec<(String, String)> {
    const KEEP: &[&str] = &[
        "user-agent",
        "accept",
        "accept-language",
        "referer",
        "origin",
        "authorization",
        // Chromium adds these via requestWillBeSentExtraInfo; a Cloudflare-fronted
        // CDN checks them for coherence with the TLS/UA fingerprint and 403s a
        // request that carries only UA + Referer.
        "cookie",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
    ];
    let mut h: Vec<(String, String)> = hit
        .request_headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .filter(|(k, _)| KEEP.contains(&k.as_str()) || k.starts_with("x-"))
        .collect();

    if !h.iter().any(|(k, _)| k == "referer") {
        h.push(("referer".to_string(), hit.final_url.to_string()));
    }

    let now = chrono::Utc::now().timestamp() as f64;
    if let Some(ch) = state.cookie_header(hit.url.host_str().unwrap_or(""), now) {
        h.retain(|(k, _)| k != "cookie");
        h.push(("cookie".to_string(), ch));
    }
    h
}

/// Headers a caller should replay when fetching the stream URL.
fn replay_headers(ctx: &ResolveCtx<'_>, state: &StorageState) -> Vec<(String, String)> {
    let mut h = Vec::new();
    if let Some(j) = ctx.jar {
        if !j.user_agent.is_empty() {
            h.push(("user-agent".to_string(), j.user_agent.clone()));
        }
        if !j.accept_language.is_empty() {
            h.push(("accept-language".to_string(), j.accept_language.clone()));
        }
    }
    h.push(("referer".to_string(), ctx.url.to_string()));
    let now = chrono::Utc::now().timestamp() as f64;
    if let Some(ch) = state.cookie_header(ctx.url.host_str().unwrap_or(""), now) {
        h.push(("cookie".to_string(), ch));
    }
    h
}

fn pattern_ok(set: &GlobSet, u: &Url) -> bool {
    if set.is_empty() {
        return true;
    }
    // Match against the path (no query) and the last path segment, so `*.m3u8`
    // matches `https://h/a/b/master.m3u8?token=…`.
    let path = u.path();
    let file = path.rsplit('/').next().unwrap_or(path);
    set.is_match(path) || set.is_match(file) || set.is_match(u.as_str())
}

pub fn build_globset(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let g = Glob::new(p)
            .map_err(|e| CobwebError::BadRequest(format!("bad url_pattern `{p}`: {e}")))?;
        b.add(g);
    }
    b.build()
        .map_err(|e| CobwebError::BadRequest(format!("bad url_pattern set: {e}")))
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Registrable domain (`example.com` from `cdn.example.com`), or the bare host for
/// IP literals / unknown suffixes.
pub fn registrable_domain(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| CobwebError::BadRequest(format!("URL has no host: {url}")))?;
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }
    Ok(psl::domain_str(host).unwrap_or(host).to_ascii_lowercase())
}

/// Run the pipeline (DESIGN.md §2) and record the outcome for `/metrics`.
pub async fn resolve(state: &AppState, params: ResolveParams) -> Result<ResolveOutcome> {
    let r = resolve_inner(state, params).await;
    match &r {
        Ok(o) => state.metrics.resolve_ok(&o.domain, o.via_tier),
        Err(CobwebError::NeedsManualSolve { domain }) => state.metrics.resolve_needs_manual(domain),
        Err(_) => state.metrics.resolve_error("unknown"),
    }
    r
}

async fn resolve_inner(state: &AppState, params: ResolveParams) -> Result<ResolveOutcome> {
    let domain = registrable_domain(&params.url)?;
    let egress = state
        .egress
        .resolve(params.egress_name.as_deref(), params.proxy_url.as_deref())?;
    // Vet a caller-supplied `proxy_url` *before* `ensure_available`'s
    // TCP-connect probe, which would otherwise double as a blind port-scan
    // oracle against an internal host named in the request.
    crate::ssrf::guard_egress(&egress, state.config.server.allow_private_targets).await?;
    state.egress.ensure_available(&egress).await?;

    // yt-dlp path: for configured hosts, shell out instead of running the tiers.
    // Runs before the SSRF guard — `[ytdlp].hosts` is an explicit operator
    // allowlist and yt-dlp does its own fetching.
    #[cfg(feature = "ytdlp")]
    if let Some(yt) = &state.ytdlp {
        if yt.handles(&params.url) {
            let seed = state.jar.get_fresh(&domain, &egress).await;
            let urls = yt
                .resolve(
                    &params.url,
                    seed.as_ref().map(|j| &j.storage_state),
                    egress.proxy.as_ref(),
                    params.timeout,
                )
                .await?;
            let stream_url = urls.into_iter().next().unwrap_or_default();
            let kind = Url::parse(&stream_url)
                .ok()
                .and_then(|u| StreamKind::from_url(&u))
                .unwrap_or(StreamKind::Progressive);
            return Ok(ResolveOutcome {
                stream: StreamResult {
                    stream_url,
                    kind,
                    headers: Vec::new(),
                    cookies: seed.map(|j| j.storage_state.cookies).unwrap_or_default(),
                },
                via_tier: ViaTier::Ytdlp,
                domain,
            });
        }
    }

    crate::ssrf::guard_url(
        &params.url,
        egress.is_direct(),
        state.config.server.allow_private_targets,
    )
    .await?;

    let jar_entry = state.jar.get_fresh(&domain, &egress).await;
    let globset = globset_for(&params.url_pattern)?;

    let ctx = ResolveCtx {
        url: &params.url,
        registrable_domain: &domain,
        egress: &egress,
        mode: params.mode,
        url_pattern: globset.as_ref(),
        timeout: params.timeout,
        block_resources: params.block_resources,
        block_trackers: params.block_trackers,
        jar: jar_entry.as_ref(),
        interact_js: None,
    };

    let mut last_reason = EscalateReason::NeedsJs;

    // Tier 2 — fast path
    if params.mode != Mode::Browser {
        match state.fast_tier.try_resolve(&ctx).await {
            TierOutcome::Resolved(stream) => {
                persist_success(state, &domain, &egress, ctx.jar, &stream).await;
                return Ok(ResolveOutcome {
                    stream,
                    via_tier: ViaTier::Fastpath,
                    domain,
                });
            }
            TierOutcome::Failed(e) => return Err(e),
            TierOutcome::Escalate(reason) => {
                if reason == EscalateReason::Challenge {
                    state.jar.note_failure(&domain, &egress).await;
                    state.metrics.challenge_hit();
                }
                last_reason = reason;
            }
        }
    }

    // Tier 3 — browser sniff
    if params.mode != Mode::Fast {
        if let Some(browser_tier) = &state.browser_tier {
            match browser_tier.try_resolve(&ctx).await {
                TierOutcome::Resolved(stream) => {
                    persist_success(state, &domain, &egress, ctx.jar, &stream).await;
                    return Ok(ResolveOutcome {
                        stream,
                        via_tier: ViaTier::Browser,
                        domain,
                    });
                }
                TierOutcome::Failed(e) => return Err(e),
                TierOutcome::Escalate(reason) => {
                    if reason == EscalateReason::Challenge {
                        state.jar.note_failure(&domain, &egress).await;
                        state.metrics.challenge_hit();
                    }
                    last_reason = reason;
                }
            }
        }
    }

    // Tier 3b — delegate an unsolved challenge to an external FlareSolverr, then
    // retry the browser tier once with the cookies it brought back.
    #[cfg(feature = "flaresolverr")]
    if last_reason == EscalateReason::Challenge && params.mode != Mode::Fast {
        if let Some(outcome) =
            try_flaresolverr(state, &domain, &egress, &params, globset.as_ref()).await
        {
            match outcome {
                TierOutcome::Resolved(stream) => {
                    let fresh = state.jar.get_fresh(&domain, &egress).await;
                    persist_success(state, &domain, &egress, fresh.as_ref(), &stream).await;
                    return Ok(ResolveOutcome {
                        stream,
                        via_tier: ViaTier::Flaresolverr,
                        domain,
                    });
                }
                TierOutcome::Failed(e) => return Err(e),
                TierOutcome::Escalate(reason) => last_reason = reason,
            }
        }
    }

    // Every automated tier is exhausted — terminal, see finish_unresolved.
    finish_unresolved(
        &domain,
        params.mode,
        last_reason,
        state.browser_tier.is_some(),
    )
}

#[cfg(feature = "flaresolverr")]
async fn try_flaresolverr(
    state: &AppState,
    domain: &str,
    egress: &crate::egress::Egress,
    params: &ResolveParams,
    globset: &GlobSet,
) -> Option<TierOutcome> {
    let fs = state.flaresolverr.as_ref()?;
    let browser_tier = state.browser_tier.as_ref()?;

    let sol = match fs
        .solve(&params.url, egress.proxy.as_ref(), params.timeout)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "tier 3b: flaresolverr delegate failed");
            return None;
        }
    };
    tracing::info!(
        cookies = sol.cookies.len(),
        "tier 3b: flaresolverr returned; merging into jar and retrying the browser"
    );

    let ttl = state.jar.default_ttl().as_secs();
    let mut entry = state
        .jar
        .load(domain, egress)
        .await
        .unwrap_or_else(|| JarEntry::new(domain.to_string(), egress.jar_key(), ttl));
    entry.storage_state.merge_from(sol.cookies);
    if !sol.user_agent.is_empty() {
        entry.user_agent = sol.user_agent;
    }
    if let Some(secs) = ttl_hint_from(&entry.storage_state.cookies, "cf_clearance") {
        entry.ttl_hint_secs = secs;
    }
    let _ = state.jar.note_success(entry).await;

    let fresh = state.jar.get_fresh(domain, egress).await;
    let ctx = ResolveCtx {
        url: &params.url,
        registrable_domain: domain,
        egress,
        mode: params.mode,
        url_pattern: globset,
        timeout: params.timeout,
        block_resources: params.block_resources,
        block_trackers: params.block_trackers,
        jar: fresh.as_ref(),
        interact_js: None,
    };
    Some(browser_tier.try_resolve(&ctx).await)
}

/// Turn the last escalation reason into the right error once every tier we have
/// has been tried.
fn finish_unresolved(
    domain: &str,
    mode: Mode,
    reason: EscalateReason,
    browser_ran: bool,
) -> Result<ResolveOutcome> {
    match (mode, reason) {
        (Mode::Fast, _) => Err(CobwebError::NotResolved(format!(
            "{domain}: fast mode and no stream on the fast path"
        ))),
        (_, EscalateReason::Challenge) => Err(CobwebError::NeedsManualSolve {
            domain: domain.to_string(),
        }),
        // The browser tier ran and still found nothing.
        _ if browser_ran => Err(CobwebError::NotResolved(format!(
            "{domain}: no matching stream URL after the browser sniff"
        ))),
        (_, EscalateReason::NeedsJs) => Err(CobwebError::NeedsBrowser(format!(
            "{domain}: needs a browser (tier 3) — set browser_engine = \"chromium\""
        ))),
        (_, EscalateReason::NotFound) => Err(CobwebError::NotResolved(format!(
            "{domain}: no matching stream URL"
        ))),
    }
}

async fn persist_success(
    state: &AppState,
    domain: &str,
    egress: &crate::egress::Egress,
    seed: Option<&JarEntry>,
    stream: &StreamResult,
) {
    let ttl_default = state.jar.default_ttl().as_secs();
    let mut entry = match seed {
        Some(j) => j.clone(),
        None => JarEntry::new(domain, egress.jar_key(), ttl_default),
    };
    entry.storage_state.cookies = stream.cookies.clone();
    if let Some(secs) = ttl_hint_from(&stream.cookies, "cf_clearance") {
        entry.ttl_hint_secs = secs;
    }
    // Carry forward UA/lang from replay headers if the jar had none.
    for (k, v) in &stream.headers {
        match k.as_str() {
            "user-agent" if entry.user_agent.is_empty() => entry.user_agent = v.clone(),
            "accept-language" if entry.accept_language.is_empty() => {
                entry.accept_language = v.clone()
            }
            _ => {}
        }
    }
    if let Err(e) = state.jar.note_success(entry).await {
        tracing::warn!(domain, error = %e, "failed to persist jar after fast-path success");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// /v1/navigate — fast-path only (M1)
// ─────────────────────────────────────────────────────────────────────────────

pub struct NavigateResult {
    pub html: String,
    pub final_url: String,
    pub status: u16,
}

/// Allowlist for caller-supplied `extra_headers` on `/v1/navigate`. This is a
/// test-bench knob probing anti-hotlink checks — it must not become a lever for
/// SSRF/routing tricks (`Host`, `Authorization`, `X-Forwarded-For`, `Cookie`,
/// …), so only request-shaping headers a browser would legitimately send are
/// forwarded; everything else is dropped with a warning.
fn navigate_header_allowed(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    n.starts_with("sec-fetch-")
        || matches!(
            n.as_str(),
            "referer"
                | "origin"
                | "accept"
                | "accept-language"
                | "accept-encoding"
                | "range"
                | "x-requested-with"
                | "upgrade-insecure-requests"
        )
}

pub async fn navigate_fastpath(
    state: &AppState,
    url: Url,
    egress_name: Option<String>,
    proxy_url: Option<String>,
    referer: Option<String>,
    extra_headers_in: Option<std::collections::HashMap<String, String>>,
    timeout: Duration,
) -> Result<NavigateResult> {
    let domain = registrable_domain(&url)?;
    let egress = state
        .egress
        .resolve(egress_name.as_deref(), proxy_url.as_deref())?;
    crate::ssrf::guard_egress(&egress, state.config.server.allow_private_targets).await?;
    state.egress.ensure_available(&egress).await?;
    crate::ssrf::guard_url(
        &url,
        egress.is_direct(),
        state.config.server.allow_private_targets,
    )
    .await?;
    let jar = state.jar.get_fresh(&domain, &egress).await;

    let now = chrono::Utc::now().timestamp() as f64;
    let cookie_header = jar.as_ref().and_then(|j| {
        j.storage_state
            .cookie_header(url.host_str().unwrap_or(""), now)
    });
    let ua = jar
        .as_ref()
        .map(|j| j.user_agent.as_str())
        .filter(|s| !s.is_empty());
    let al = jar
        .as_ref()
        .map(|j| j.accept_language.as_str())
        .filter(|s| !s.is_empty());

    let mut extra_headers: Vec<(String, String)> = referer
        .map(|r| vec![("referer".to_string(), r)])
        .unwrap_or_default();
    if let Some(h) = extra_headers_in {
        for (k, v) in h {
            if navigate_header_allowed(&k) {
                extra_headers.push((k, v));
            } else {
                tracing::warn!(header = %k, "navigate: dropping disallowed extra header");
            }
        }
    }

    let resp = state
        .fast
        .fetch(FetchRequest {
            url: &url,
            egress: &egress,
            user_agent: ua,
            accept_language: al,
            cookie_header: cookie_header.as_deref(),
            extra_headers: &extra_headers,
            timeout,
        })
        .await?;

    Ok(NavigateResult {
        html: resp.body,
        final_url: resp.final_url.to_string(),
        status: resp.status,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// /v1/sniff and /v1/eval — thin wrappers over the browser tier
// ─────────────────────────────────────────────────────────────────────────────

pub struct SniffResult {
    pub intercepted_url: String,
    pub headers: Vec<(String, String)>,
}

/// A bare substring pattern (`"m3u8"`) becomes `*m3u8*`; anything already
/// containing glob metacharacters is left alone.
pub fn normalize_sniff_pattern(p: &str) -> String {
    if p.contains(['*', '?', '[', '{']) {
        p.to_string()
    } else {
        format!("*{p}*")
    }
}

pub async fn browser_sniff(
    state: &AppState,
    trigger: Url,
    url_pattern: Vec<String>,
    egress_name: Option<String>,
    proxy_url: Option<String>,
    timeout: Duration,
    interact_js: Option<String>,
) -> Result<SniffResult> {
    let tier = state.browser_tier.as_ref().ok_or_else(|| {
        CobwebError::NeedsBrowser(
            "browser engine disabled — set browser_engine = \"chromium\"".into(),
        )
    })?;

    let domain = registrable_domain(&trigger)?;
    let egress = state
        .egress
        .resolve(egress_name.as_deref(), proxy_url.as_deref())?;
    crate::ssrf::guard_egress(&egress, state.config.server.allow_private_targets).await?;
    state.egress.ensure_available(&egress).await?;
    crate::ssrf::guard_url(
        &trigger,
        egress.is_direct(),
        state.config.server.allow_private_targets,
    )
    .await?;
    let jar_entry = state.jar.get_fresh(&domain, &egress).await;
    let globset = globset_for(&url_pattern)?;

    let ctx = ResolveCtx {
        url: &trigger,
        registrable_domain: &domain,
        egress: &egress,
        mode: Mode::Browser,
        url_pattern: globset.as_ref(),
        timeout,
        block_resources: true,
        block_trackers: true,
        jar: jar_entry.as_ref(),
        interact_js: interact_js.as_deref(),
    };

    match tier.try_resolve(&ctx).await {
        TierOutcome::Resolved(stream) => {
            persist_success(state, &domain, &egress, ctx.jar, &stream).await;
            Ok(SniffResult {
                intercepted_url: stream.stream_url,
                headers: stream.headers,
            })
        }
        TierOutcome::Escalate(EscalateReason::Challenge) => {
            state.jar.note_failure(&domain, &egress).await;
            Err(CobwebError::NeedsManualSolve { domain })
        }
        TierOutcome::Escalate(_) => Err(CobwebError::NotResolved(format!(
            "{domain}: no request matched {url_pattern:?} within the timeout"
        ))),
        TierOutcome::Failed(e) => Err(e),
    }
}

pub async fn browser_eval(
    state: &AppState,
    url: Url,
    js: String,
    egress_name: Option<String>,
    proxy_url: Option<String>,
    timeout: Duration,
) -> Result<serde_json::Value> {
    let engine = state.browser.as_ref().ok_or_else(|| {
        CobwebError::NeedsBrowser(
            "browser engine disabled — set browser_engine = \"chromium\"".into(),
        )
    })?;
    engine
        .ensure_ready()
        .await
        .map_err(|e| CobwebError::Browser(format!("engine not ready: {e}")))?;

    let domain = registrable_domain(&url)?;
    let egress = state
        .egress
        .resolve(egress_name.as_deref(), proxy_url.as_deref())?;
    crate::ssrf::guard_egress(&egress, state.config.server.allow_private_targets).await?;
    state.egress.ensure_available(&egress).await?;
    crate::ssrf::guard_url(
        &url,
        egress.is_direct(),
        state.config.server.allow_private_targets,
    )
    .await?;
    let jar_entry = state.jar.get_fresh(&domain, &egress).await;

    let opts = ContextOptions {
        egress: (*egress).clone(),
        seed: jar_entry.as_ref().map(|j| j.storage_state.clone()),
        user_agent: jar_entry
            .as_ref()
            .map(|j| j.user_agent.clone())
            .filter(|s| !s.is_empty()),
        accept_language: jar_entry
            .as_ref()
            .map(|j| j.accept_language.clone())
            .filter(|s| !s.is_empty()),
        block_resources: false,
        block_trackers: false,
    };

    let mut cx = engine.acquire(opts).await?;
    let out = cx.eval(&url, &js, timeout).await;

    // Persist any cookies the eval navigation picked up.
    if let Ok(state_after) = cx.storage_state().await {
        let ttl = state.jar.default_ttl().as_secs();
        let mut entry = jar_entry
            .clone()
            .unwrap_or_else(|| JarEntry::new(domain.clone(), egress.jar_key(), ttl));
        entry.storage_state.merge_from(state_after.cookies);
        let _ = state.jar.note_success(entry).await;
    }
    cx.close().await;

    out.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domain_collapses_subdomains() {
        let u = Url::parse("https://cdn.example.com/hls/master.m3u8").unwrap();
        assert_eq!(registrable_domain(&u).unwrap(), "example.com");
    }

    #[test]
    fn registrable_domain_handles_multi_level_suffix() {
        let u = Url::parse("https://www.example.net/anime/1").unwrap();
        assert_eq!(registrable_domain(&u).unwrap(), "example.net");
    }

    #[test]
    fn registrable_domain_keeps_ip_literal() {
        let u = Url::parse("http://192.168.1.10:8080/x").unwrap();
        assert_eq!(registrable_domain(&u).unwrap(), "192.168.1.10");
    }

    #[test]
    fn globset_matches_manifest_with_query() {
        let set = build_globset(&default_patterns()).unwrap();
        let u = Url::parse("https://h/a/b/master.m3u8?token=xyz").unwrap();
        assert!(pattern_ok(&set, &u));
        let u2 = Url::parse("https://h/a/b/index.html").unwrap();
        assert!(!pattern_ok(&set, &u2));
    }
}
