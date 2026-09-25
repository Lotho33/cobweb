//! [`BrowserEngine`] over the hand-rolled [`CdpClient`] (DESIGN.md §3).
//!
//! One Chromium, launched lazily. Each `acquire()` gets its own
//! `Target.createBrowserContext` (separate cookie jar) + one page in it.
//! JS runs in a `Page.createIsolatedWorld` — **`Runtime.enable` is never sent**.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use globset::GlobSet;
use serde_json::{json, Value};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use url::Url;

use super::cdp::CdpClient;
use super::chromium::Chromium;
use super::engine::*;
use crate::blocklist::Blocklist;
use crate::config::BrowserConfig;
use crate::fastpath::looks_like_cloudflare_challenge;
use crate::jar::{Cookie, StorageState};

const STEALTH_JS: &str = r#"
Object.defineProperty(navigator, 'webdriver', { get: () => false });
window.chrome = window.chrome || { runtime: {} };
"#;

const BLOCKED_URLS: &[&str] = &[
    // static media we never need for a sniff
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.otf",
    "*.eot",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.svg",
    "*.ico",
    "*.bmp",
    // video/audio segments: once the manifest URL is sniffed we return, so the
    // player never has to fetch the media — blocking it saves a lot of renderer
    // RAM and bandwidth. The manifests themselves (*.m3u8 / *.mpd) are never
    // listed here. `?*` variants catch tokenised segment URLs.
    "*.ts",
    "*.ts?*",
    "*.m4s",
    "*.m4s?*",
    "*.mp4",
    "*.mp4?*",
    "*.m4v",
    "*.m4v?*",
    "*.webm",
    "*.webm?*",
    "*.aac",
    "*.aac?*",
    "*.mp3",
    "*.mp3?*",
    // ad / analytics / popunder hosts seen in embed-provider traces — blocking
    // them cuts renderer work, memory, and stray popups.
    "*doubleclick.net*",
    "*googlesyndication.com*",
    "*google-analytics.com*",
    "*googletagmanager.com*",
    "*adservice.google.com*",
    "*histats.com*",
    "*popads.net*",
    "*propellerads.com*",
    "*onclickalgo.com*",
    "*rtmark.net*",
    "*spbgc.com*",
    "*bef77.com*",
    "*poptm.com*",
    "*adsterra.com*",
    "*hilltopads.net*",
];

type SharedLaunched = Arc<Mutex<Option<Launched>>>;

/// Params for `Network.enable`. The CDP default keeps up to 10 MB per resource
/// and 100 MB total of response bodies buffered browser-side so `getResponseBody`
/// can serve them; a sniff only ever reads a handful of sub-3 MB bodies.
fn network_enable_params() -> Value {
    json!({
        "maxResourceBufferSize": 2 * 1024 * 1024,
        "maxTotalBufferSize": 8 * 1024 * 1024,
    })
}

pub struct CdpEngine {
    cfg: BrowserConfig,
    max_contexts: usize,
    /// Seconds; 0 disables the reaper. Live-tunable via `PATCH /v1/settings`
    /// (`set_idle_shutdown_secs`) — `Arc` so it can be cloned into the
    /// reaper's spawned task and updated from outside it.
    idle_after_secs: Arc<AtomicU64>,
    launched: SharedLaunched,
    in_use: Arc<AtomicUsize>,
    last_used: Arc<StdMutex<Instant>>,
    sem: Arc<Semaphore>,
    reaper_started: AtomicBool,
    /// `[server].allow_private_targets` — threaded into each context's Fetch-domain
    /// SSRF guard (see `spawn_fetch_guard`), matching the top-level `ssrf::guard_url`.
    allow_private_targets: bool,
    /// Tracker/ad domain patterns from `[blocklist]` — merged with
    /// `BLOCKED_URLS` when a context's `block_trackers` is set.
    blocklist: Arc<Blocklist>,
}

struct Launched {
    chromium: Chromium,
    client: Arc<CdpClient>,
    /// Chromium's own UA with `HeadlessChrome` rewritten to `Chrome` — the
    /// default we pin per context so replayed requests don't shout "bot".
    default_ua: String,
}

impl CdpEngine {
    pub fn new(
        cfg: BrowserConfig,
        max_contexts: usize,
        idle_shutdown_secs: u64,
        allow_private_targets: bool,
        blocklist: Arc<Blocklist>,
    ) -> Self {
        Self {
            cfg,
            max_contexts: max_contexts.max(1),
            idle_after_secs: Arc::new(AtomicU64::new(idle_shutdown_secs)),
            launched: Arc::new(Mutex::new(None)),
            in_use: Arc::new(AtomicUsize::new(0)),
            last_used: Arc::new(StdMutex::new(Instant::now())),
            sem: Arc::new(Semaphore::new(max_contexts.max(1))),
            reaper_started: AtomicBool::new(false),
            allow_private_targets,
            blocklist,
        }
    }

    fn touch(&self) {
        *self.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    /// Pushed from `PATCH /v1/settings` (`src/api/settings.rs`) via the
    /// `BrowserEngine` trait. In prewarm mode the reaper never spawns in the
    /// first place (`start_reaper`'s zero-check sees `idle_shutdown_secs = 0`
    /// on Chromium's first — and, for a prewarmed engine, only — launch), so
    /// this has no visible effect there; that's intended, matching prewarm's
    /// existing "never idle-shut-down" contract.
    pub fn set_idle_shutdown_secs(&self, secs: u64) {
        self.idle_after_secs.store(secs, Ordering::SeqCst);
    }

    async fn launched(&self) -> BrowserResult<(Arc<CdpClient>, String)> {
        let mut g = self.launched.lock().await;
        if g.is_none() {
            let chromium = Chromium::launch(&self.cfg, self.max_contexts).await?;
            let client = CdpClient::connect(&chromium.ws_url).await?;
            let default_ua = chromium.user_agent.clone();
            tracing::info!(ua = %default_ua, "Chromium + CDP ready");
            *g = Some(Launched {
                chromium,
                client,
                default_ua,
            });
            self.start_reaper(); // only clones an Arc — safe to call holding `g`
        }
        let l = g.as_ref().unwrap();
        Ok((l.client.clone(), l.default_ua.clone()))
    }

    /// Spawn (once) the task that tears down Chromium after
    /// `idle_after_secs` with no contexts in use. `idle_after_secs == 0` (at
    /// the moment of this first, lazy call — prewarm forces this) disables it
    /// entirely; otherwise the threshold is re-read from the atomic on every
    /// tick, so a later `PATCH /v1/settings` takes effect live.
    fn start_reaper(&self) {
        if self.idle_after_secs.load(Ordering::SeqCst) == 0
            || self.reaper_started.swap(true, Ordering::SeqCst)
        {
            return;
        }
        let launched = self.launched.clone();
        let in_use = self.in_use.clone();
        let last_used = self.last_used.clone();
        let idle_after_secs = self.idle_after_secs.clone();
        tokio::spawn(async move {
            // Flat poll interval instead of deriving it from the (now
            // live-changeable) threshold — 15s was already the effective cap
            // in the old formula for any realistic threshold.
            let tick = Duration::from_secs(15);
            loop {
                tokio::time::sleep(tick).await;
                let idle_after = Duration::from_secs(idle_after_secs.load(Ordering::SeqCst));
                if idle_after.is_zero() || in_use.load(Ordering::SeqCst) > 0 {
                    continue;
                }
                if last_used
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .elapsed()
                    < idle_after
                {
                    continue;
                }
                let taken = {
                    let mut g = launched.lock().await;
                    // re-check under the lock to avoid killing a starting request
                    let idle_after = Duration::from_secs(idle_after_secs.load(Ordering::SeqCst));
                    if idle_after.is_zero()
                        || in_use.load(Ordering::SeqCst) > 0
                        || last_used
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .elapsed()
                            < idle_after
                    {
                        None
                    } else {
                        g.take()
                    }
                };
                if let Some(l) = taken {
                    tracing::info!("browser idle: tearing down Chromium");
                    l.chromium.kill().await;
                }
            }
        });
    }
}

#[async_trait]
impl BrowserEngine for CdpEngine {
    fn name(&self) -> &'static str {
        "cdp"
    }

    fn set_idle_shutdown_secs(&self, secs: u64) {
        CdpEngine::set_idle_shutdown_secs(self, secs);
    }

    async fn ensure_ready(&self) -> BrowserResult<()> {
        self.launched().await.map(|_| ())
    }

    async fn acquire(&self, opts: ContextOptions) -> BrowserResult<Box<dyn BrowserContext>> {
        self.touch();
        let (client, default_ua) = self.launched().await?;
        let permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| BrowserError::Unavailable("engine is shutting down".into()))?;

        // Per-context proxy: the shared Chromium is launched without one, so a
        // per-request egress (a named profile or a raw proxy_url) is applied
        // here on the browser context. Without this the CDP tier silently
        // egressed direct and `opts.egress` was carried but dropped.
        //
        // No `proxyBypassList` / `<-loopback>` here on purpose: when a proxy is
        // set, loopback and private targets must ride it too, not slip out
        // direct (SSRF hardening — the entry-point `ssrf::guard_url` already
        // rejects a private *target*; this stops a redirect/subresource from
        // reaching one via the box's own network).
        let mut ctx_params = json!({ "disposeOnDetach": true });
        if let Some(proxy) = opts.egress.proxy.as_ref() {
            ctx_params["proxyServer"] = json!(proxy.as_str().trim_end_matches('/'));
        }
        let bc = client
            .call("Target.createBrowserContext", ctx_params, None)
            .await?;
        let browser_context_id = bc
            .get("browserContextId")
            .and_then(Value::as_str)
            .map(str::to_string);

        let mut create_params = json!({ "url": "about:blank" });
        if let Some(bc) = &browser_context_id {
            create_params["browserContextId"] = json!(bc);
        }
        let tgt = client
            .call("Target.createTarget", create_params, None)
            .await?;
        let target_id = tgt
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| BrowserError::Cdp("createTarget: no targetId".into()))?
            .to_string();

        let att = client
            .call(
                "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": true }),
                None,
            )
            .await?;
        let session_id = att
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| BrowserError::Cdp("attachToTarget: no sessionId".into()))?
            .to_string();

        self.in_use.fetch_add(1, Ordering::SeqCst);

        let mut sessions = std::collections::HashSet::new();
        sessions.insert(session_id.clone());

        let mut cx = CdpContext {
            client,
            session_id,
            target_id,
            browser_context_id,
            frame_id: None,
            block_resources: false,
            block_trackers: false,
            blocklist: self.blocklist.clone(),
            default_ua,
            ua: String::new(),
            in_use: self.in_use.clone(),
            last_used: self.last_used.clone(),
            _permit: permit,
            sessions: Arc::new(StdMutex::new(sessions)),
            is_direct: opts.egress.is_direct(),
            fetch_guard: None,
        };
        cx.setup(&opts, self.allow_private_targets).await?;
        Ok(Box::new(cx))
    }

    fn contexts_in_use(&self) -> usize {
        self.in_use.load(Ordering::SeqCst)
    }

    async fn shutdown(&self) {
        if let Some(l) = self.launched.lock().await.take() {
            l.chromium.kill().await;
        }
    }
}

impl Drop for CdpEngine {
    fn drop(&mut self) {
        // Last-resort: a panicking test / abrupt exit must not orphan Chromium.
        if let Ok(mut g) = self.launched.try_lock() {
            if let Some(l) = g.take() {
                l.chromium.kill_sync();
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

struct CdpContext {
    client: Arc<CdpClient>,
    session_id: String,
    target_id: String,
    browser_context_id: Option<String>,
    frame_id: Option<String>,
    block_resources: bool,
    /// Mirrors `block_resources` but for `[blocklist]`'s tracker/ad domains —
    /// independently flaggable (`ContextOptions::block_trackers`).
    block_trackers: bool,
    /// Shared handle to the live `[blocklist]` snapshot (`CdpEngine::blocklist`).
    blocklist: Arc<Blocklist>,
    /// The launch-flag UA (already clean) — the baseline every frame uses.
    default_ua: String,
    /// A jar-pinned UA that differs from `default_ua`, applied via CDP override
    /// to the page and every auto-attached subframe. Empty = use `default_ua`.
    ua: String,
    in_use: Arc<AtomicUsize>,
    last_used: Arc<StdMutex<Instant>>,
    _permit: OwnedSemaphorePermit,
    /// Every CDP session id this context is responsible for — the main page
    /// plus any auto-attached sub-frame — shared with the Fetch-domain SSRF
    /// guard task so it knows which `Fetch.requestPaused` events are ours.
    sessions: Arc<StdMutex<std::collections::HashSet<String>>>,
    /// Whether this context's egress is `direct` (no proxy) — mirrors
    /// `ssrf::guard_url`'s own rule: a proxied egress resolves *at the proxy*,
    /// so only the literal-IP check applies there; a direct egress also gets
    /// the DNS-resolved check.
    is_direct: bool,
    /// The background task applying the Fetch-domain SSRF guard (see
    /// `spawn_fetch_guard`) to every request this context's sessions make.
    /// Aborted on `close()`/`Drop` — it would otherwise outlive the context,
    /// one leaked task per acquired context.
    fetch_guard: Option<tokio::task::JoinHandle<()>>,
}

impl CdpContext {
    fn sid(&self) -> Option<&str> {
        Some(&self.session_id)
    }

    /// The union of `BLOCKED_URLS` (media/asset extensions + the small
    /// built-in ad-domain set, gated on `block_resources`) and the live
    /// `[blocklist]` tracker/ad patterns (gated on `block_trackers`). CDP has
    /// no "append" for `Network.setBlockedURLs` — a second call replaces the
    /// first — so every call site needs the merged list, issued once.
    fn blocked_urls(&self) -> Vec<String> {
        let mut urls = Vec::new();
        if self.block_resources {
            urls.extend(BLOCKED_URLS.iter().map(|s| s.to_string()));
        }
        if self.block_trackers {
            urls.extend(self.blocklist.snapshot().iter().cloned());
        }
        urls
    }

    async fn call(&self, method: &str, params: Value) -> BrowserResult<Value> {
        self.client.call(method, params, self.sid()).await
    }

    async fn setup(&mut self, opts: &ContextOptions, allow_private: bool) -> BrowserResult<()> {
        self.block_resources = opts.block_resources;
        self.block_trackers = opts.block_trackers;

        // Domain init. Dispatched in this order (the CDP transport writes frames
        // in poll order and Chromium processes a session's queue in order, so
        // `Page.enable` / `Network.enable` still land first) but the round-trips
        // overlap instead of stacking.
        //
        // `Fetch.enable` here is the SSRF guard for everything that happens
        // *inside* this browser context after the entry-point `ssrf::guard_url`
        // has vetted the initial navigation URL: any subresource, redirect, or
        // `fetch()`/`XHR` a page's own JS makes (including the payload a
        // caller passes to `/v1/eval`) goes through Chromium's own network
        // stack and previously bypassed cobweb's SSRF check entirely. Every
        // request is paused (`Fetch.requestPaused`) until `spawn_fetch_guard`'s
        // background task below vets it and calls `Fetch.continueRequest` /
        // `Fetch.failRequest`.
        let (_, _, _, _, tree) = tokio::try_join!(
            self.call("Page.enable", json!({})),
            self.call("Network.enable", network_enable_params()),
            self.call(
                "Fetch.enable",
                json!({ "patterns": [{ "urlPattern": "*", "requestStage": "Request" }] }),
            ),
            self.call("Page.setLifecycleEventsEnabled", json!({ "enabled": true })),
            self.call("Page.getFrameTree", json!({})),
        )?;
        self.frame_id = tree
            .pointer("/frameTree/frame/id")
            .and_then(Value::as_str)
            .map(str::to_string);

        self.fetch_guard = Some(spawn_fetch_guard(
            self.client.clone(),
            self.sessions.clone(),
            allow_private,
            self.is_direct,
        ));

        // Chromium's `--user-agent` / `--accept-lang` launch flags already pin a
        // clean desktop-Chrome UA on every frame. Only add a CDP override when
        // the jar pins a *different* UA for this domain (kept in sync with the
        // later fast-path calls).
        self.ua = match &opts.user_agent {
            Some(u) if !u.is_empty() && *u != self.default_ua => u.clone(),
            _ => String::new(),
        };

        // Everything below only needs the domains enabled above and is mutually
        // independent — run it concurrently too.
        let script_fut = async {
            self.call(
                "Page.addScriptToEvaluateOnNewDocument",
                json!({ "source": STEALTH_JS }),
            )
            .await
            .map(|_| ())
        };
        let block_fut = async {
            let urls = self.blocked_urls();
            if !urls.is_empty() {
                self.call("Network.setBlockedURLs", json!({ "urls": urls }))
                    .await
                    .map(|_| ())
            } else {
                Ok(())
            }
        };
        let ua_fut = async {
            if !self.ua.is_empty() {
                self.apply_ua(self.sid()).await; // best-effort, logs on failure
            }
            Ok::<(), BrowserError>(())
        };
        let cookie_fut = async {
            if let Some(seed) = &opts.seed {
                let cookies: Vec<Value> = seed.cookies.iter().map(cookie_to_cdp).collect();
                if !cookies.is_empty() {
                    // best-effort; a malformed cookie shouldn't abort the whole sniff
                    if let Err(e) = self
                        .call("Network.setCookies", json!({ "cookies": cookies }))
                        .await
                    {
                        tracing::warn!(error = %e, "seeding cookies failed");
                    }
                }
            }
            Ok::<(), BrowserError>(())
        };
        tokio::try_join!(script_fut, block_fut, ua_fut, cookie_fut)?;
        Ok(())
    }

    /// Fresh isolated world + `Runtime.evaluate` — no `Runtime.enable`.
    async fn iso_eval(&self, expr: &str, timeout: Duration) -> BrowserResult<Value> {
        let frame_id = self
            .frame_id
            .clone()
            .ok_or_else(|| BrowserError::Cdp("no frame id".into()))?;
        let world = self
            .call(
                "Page.createIsolatedWorld",
                json!({ "frameId": frame_id, "worldName": "cobweb", "grantUniveralAccess": true }),
            )
            .await?;
        let ctx_id = world
            .get("executionContextId")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                BrowserError::Cdp("createIsolatedWorld: no executionContextId".into())
            })?;

        let res = self
            .client
            .call_timeout(
                "Runtime.evaluate",
                json!({
                    "expression": expr,
                    "contextId": ctx_id,
                    "returnByValue": true,
                    "awaitPromise": true,
                }),
                self.sid(),
                timeout,
            )
            .await?;

        if let Some(exc) = res.get("exceptionDetails") {
            return Err(BrowserError::Cdp(format!("eval threw: {exc}")));
        }
        Ok(res.pointer("/result/value").cloned().unwrap_or(Value::Null))
    }

    async fn current_html(&self) -> String {
        self.iso_eval("document.documentElement.outerHTML", Duration::from_secs(5))
            .await
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    }

    /// First 64 KiB of the DOM — enough for the Cloudflare markers (title +
    /// early scripts) without serialising a multi-MB document into a CDP reply.
    /// Used only for the challenge check on the sniff give-up path.
    async fn current_html_head(&self) -> String {
        self.iso_eval(
            "document.documentElement.outerHTML.slice(0, 65536)",
            Duration::from_secs(5),
        )
        .await
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
    }

    async fn current_url(&self, fallback: &Url) -> Url {
        self.iso_eval("location.href", Duration::from_secs(3))
            .await
            .ok()
            .and_then(|v| v.as_str().and_then(|s| Url::parse(s).ok()))
            .unwrap_or_else(|| fallback.clone())
    }

    /// Drive `Page.navigate` and wait for `wait`. A timeout here is *not* an
    /// error — we return whatever the page is.
    async fn goto(&self, url: &Url, wait: &WaitFor, timeout: Duration) -> BrowserResult<()> {
        let mut ev = self.client.subscribe();
        let nav = self
            .call("Page.navigate", json!({ "url": url.as_str() }))
            .await?;
        if let Some(err) = nav.get("errorText").and_then(Value::as_str) {
            if !err.is_empty() {
                return Err(BrowserError::Cdp(format!("navigate: {err}")));
            }
        }

        let target = match wait {
            WaitFor::Load => "load",
            WaitFor::DomContentLoaded => "DOMContentLoaded",
            WaitFor::NetworkIdle => "networkIdle",
            WaitFor::Selector(_) => "DOMContentLoaded",
        };

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                tracing::debug!(%url, ?wait, "goto: wait condition not seen before timeout");
                return Ok(());
            }
            match tokio::time::timeout(remaining, ev.recv()).await {
                Ok(Ok(e)) => {
                    if e.session_id.as_deref() == Some(&self.session_id)
                        && e.method == "Page.lifecycleEvent"
                        && e.params.get("name").and_then(Value::as_str) == Some(target)
                    {
                        break;
                    }
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(_)) | Err(_) => return Ok(()),
            }
        }

        if let WaitFor::Selector(sel) = wait {
            let js = format!("document.querySelector({}) != null", json!(sel));
            let sel_deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < sel_deadline {
                if matches!(
                    self.iso_eval(&js, Duration::from_secs(3)).await,
                    Ok(Value::Bool(true))
                ) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        Ok(())
    }

    async fn hit(
        &self,
        trigger: &Url,
        url: Url,
        request_headers: Vec<(String, String)>,
    ) -> SniffHit {
        SniffHit {
            url,
            request_headers,
            final_url: self.current_url(trigger).await,
        }
    }

    /// `Network.setUserAgentOverride` for a session (page or subframe). Only
    /// called when the jar pins a UA that differs from the launch flag; no
    /// `acceptLanguage` here — `--accept-lang` handles that without q mangling.
    async fn apply_ua(&self, sid: Option<&str>) {
        let _ = self
            .client
            .call(
                "Network.setUserAgentOverride",
                json!({ "userAgent": self.ua }),
                sid,
            )
            .await;
    }

    /// Bring a freshly auto-attached child target (sub-frame) up to the same
    /// instrumentation as the main page — including the UA and the Fetch-domain
    /// SSRF guard — then let it run. The child session id is registered in the
    /// shared `sessions` set *before* any of these calls so `spawn_fetch_guard`
    /// (already running, watching the whole broadcast stream) recognises its
    /// `Fetch.requestPaused` events as soon as they can possibly arrive.
    async fn adopt_child(&self, child_sid: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(child_sid.to_string());
        let s = Some(child_sid);
        let _ = self
            .client
            .call("Network.enable", network_enable_params(), s)
            .await;
        let _ = self.client.call("Page.enable", json!({}), s).await;
        let _ = self
            .client
            .call(
                "Fetch.enable",
                json!({ "patterns": [{ "urlPattern": "*", "requestStage": "Request" }] }),
                s,
            )
            .await;
        if !self.ua.is_empty() {
            self.apply_ua(s).await;
        }
        let _ = self
            .client
            .call(
                "Page.addScriptToEvaluateOnNewDocument",
                json!({ "source": STEALTH_JS }),
                s,
            )
            .await;
        let urls = self.blocked_urls();
        if !urls.is_empty() {
            let _ = self
                .client
                .call("Network.setBlockedURLs", json!({ "urls": urls }), s)
                .await;
        }
        let _ = self
            .client
            .call(
                "Target.setAutoAttach",
                json!({ "autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true }),
                s,
            )
            .await;
        // Was paused by waitForDebuggerOnStart — resume (does NOT enable Runtime events).
        let _ = self
            .client
            .call("Runtime.runIfWaitingForDebugger", json!({}), s)
            .await;
    }
}

#[async_trait]
impl BrowserContext for CdpContext {
    async fn navigate(
        &mut self,
        url: &Url,
        wait: WaitFor,
        timeout: Duration,
    ) -> BrowserResult<PageLoad> {
        self.goto(url, &wait, timeout).await?;
        let html = self.current_html().await;
        let final_url = self.current_url(url).await;
        let challenge = looks_like_cloudflare_challenge(200, &html, None);
        Ok(PageLoad {
            html,
            final_url,
            challenge,
        })
    }

    async fn sniff(
        &mut self,
        trigger: &Url,
        pattern: &GlobSet,
        timeout: Duration,
        interact_js: Option<&str>,
    ) -> BrowserResult<SniffHit> {
        let mut ev = self.client.subscribe();

        // Cross-origin embed players (an outer page whose real player lives on
        // another origin) run in their own out-of-process target. Auto-attach
        // (paused) so we can instrument each
        // one before it runs and see its *.m3u8 request. Only done for sniff —
        // navigate/eval don't want paused subframes blocking `load`.
        self.call(
            "Target.setAutoAttach",
            json!({ "autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true }),
        )
        .await?;

        let nav = self
            .call("Page.navigate", json!({ "url": trigger.as_str() }))
            .await?;
        if let Some(err) = nav.get("errorText").and_then(Value::as_str) {
            if !err.is_empty() {
                return Err(BrowserError::Cdp(format!("navigate: {err}")));
            }
        }

        // Per-request state, so a mime-type / body match on the *response* can
        // still hand back the URL + replay headers.
        #[derive(Default)]
        struct Req {
            url: Option<Url>,
            headers: Vec<(String, String)>,
            /// From `Network.requestWillBeSentExtraInfo`: the real Cookie /
            /// sec-ch-ua / sec-fetch-* headers Chromium adds after the initial
            /// `requestWillBeSent` (which only carries UA + Referer). Folded
            /// onto `headers` when the hit is built.
            extra_headers: Vec<(String, String)>,
            rtype: String,
            status: i64,
            mime: String,
        }
        let mut reqs: std::collections::HashMap<String, Req> = std::collections::HashMap::new();
        let mut body_reads = 0usize;
        const MAX_BODY_READS: usize = 24;
        const MAX_BODY_BYTES: f64 = 3.0 * 1024.0 * 1024.0;
        // An ad-heavy embed page fires hundreds of requests over the timeout;
        // only a manifest-plausible request is worth a `Req` (with its header
        // vecs). Static sub-resources are skipped and the map is hard-capped.
        const MAX_TRACKED_REQS: usize = 512;

        let deadline = Instant::now() + timeout;
        let mut doc_403 = false;

        // A URL-pattern match on `requestWillBeSent` is held for a short grace
        // period so that request's `requestWillBeSentExtraInfo` — carrying the
        // real Cookie / sec-ch-ua / sec-fetch-* headers — can land and be merged
        // in. Without it the replay set is just UA + Referer and a
        // Cloudflare-fronted CDN 403s it.
        let mut pending: Option<(String, Url)> = None;
        let mut pending_until = deadline;
        // `requestWillBeSentExtraInfo` normally lands within tens of ms of the
        // match; the loop exits as soon as it does. This is just the ceiling for
        // the case where it never comes (then we replay UA + Referer only).
        const PENDING_GRACE: Duration = Duration::from_millis(400);

        // Early challenge probe. Without this, a page parked on a Cloudflare
        // interstitial (no *.m3u8 request ever fires) is only recognised on the
        // give-up path — after the full `timeout` — by which point the caller's
        // own deadline has usually already elided the `Challenge` signal into a
        // bare "deadline exceeded". Probing the DOM periodically lets us:
        //   * give a *managed* Turnstile a few seconds to clear itself in this
        //     real headed browser (common after the egress IP changes — e.g.
        //     WARP rotating — which invalidates the previous cf_clearance), and
        //   * bail out with `Challenge` fast when it needs a human, so the
        //     caller can prompt a manual solve instead of just timing out.
        const PROBE_EVERY: Duration = Duration::from_millis(2500);
        const CHALLENGE_SELF_SOLVE_GRACE: Duration = Duration::from_secs(15);
        let mut next_probe = Instant::now() + Duration::from_secs(3);
        let mut challenge_since: Option<Instant> = None;

        // Optional page interaction (e.g. clicking a play button that only
        // appears after the page's own XHRs finish). Retried every
        // INTERACT_EVERY until the script returns a truthy value.
        const INTERACT_EVERY: Duration = Duration::from_millis(1500);
        let mut interact_done = interact_js.is_none();
        let mut next_interact = Instant::now() + Duration::from_secs(2);

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());

            if !interact_done
                && pending.is_none()
                && Instant::now() >= next_interact
                && !remaining.is_zero()
            {
                next_interact = Instant::now() + INTERACT_EVERY;
                if let Some(js) = interact_js {
                    match self.iso_eval(js, Duration::from_secs(5)).await {
                        Ok(v) => {
                            let truthy = match &v {
                                Value::Null | Value::Bool(false) => false,
                                Value::String(s) => !s.is_empty(),
                                Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
                                _ => true,
                            };
                            if truthy {
                                tracing::debug!(result = %v, "sniff: interact_js done");
                                interact_done = true;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "sniff: interact_js failed, will retry")
                        }
                    }
                }
            }

            if Instant::now() >= next_probe && !remaining.is_zero() {
                next_probe = Instant::now() + PROBE_EVERY;
                let head = self.current_html_head().await;
                if looks_like_cloudflare_challenge(200, &head, None) {
                    match challenge_since {
                        None => {
                            challenge_since = Some(Instant::now());
                            tracing::info!(
                                "sniff: Cloudflare interstitial detected, giving the browser {}s to clear it",
                                CHALLENGE_SELF_SOLVE_GRACE.as_secs()
                            );
                        }
                        Some(t) if t.elapsed() >= CHALLENGE_SELF_SOLVE_GRACE => {
                            tracing::info!(
                                "sniff: interstitial still up after grace — needs a manual solve"
                            );
                            return Err(BrowserError::Challenge);
                        }
                        Some(_) => {}
                    }
                } else if challenge_since.take().is_some() {
                    tracing::info!("sniff: interstitial cleared on its own, continuing");
                }
            }

            // Return a held match once its extra-info is in, the grace expires,
            // or the overall deadline is up.
            if let Some((pid, purl)) = &pending {
                let have_extra = reqs
                    .get(pid)
                    .map(|r| !r.extra_headers.is_empty())
                    .unwrap_or(false);
                if have_extra || Instant::now() >= pending_until || remaining.is_zero() {
                    let (base, extra) = reqs
                        .get(pid)
                        .map(|r| (r.headers.clone(), r.extra_headers.clone()))
                        .unwrap_or_default();
                    let purl = purl.clone();
                    tracing::debug!(%purl, extra_info = have_extra, "sniff matched (url pattern)");
                    return Ok(self
                        .hit(trigger, purl, merge_header_lists(base, extra))
                        .await);
                }
            }

            if remaining.is_zero() {
                break;
            }

            let mut wait = match &pending {
                Some(_) => pending_until
                    .saturating_duration_since(Instant::now())
                    .min(remaining),
                None => remaining,
            }
            // Never sleep past the next challenge probe, even with no events.
            .min(next_probe.saturating_duration_since(Instant::now()));
            if !interact_done {
                wait = wait.min(next_interact.saturating_duration_since(Instant::now()));
            }
            let e = match tokio::time::timeout(wait, ev.recv()).await {
                Ok(Ok(e)) => e,
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                    tracing::warn!(dropped = n, "sniff event stream lagged");
                    continue;
                }
                // A bare timeout is a probe tick as long as there's time left.
                Err(_) if pending.is_some() || !remaining.is_zero() => continue,
                _ => break,
            };

            // A sub-target attached. Adopt sub-frames; kill popup/new-tab pages
            // (streaming sites open ad popunders — they burn RAM and never close).
            if e.method == "Target.attachedToTarget" {
                let ttype = e
                    .params
                    .pointer("/targetInfo/type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if ttype == "page" || ttype == "tab" {
                    if let Some(tid) = e
                        .params
                        .pointer("/targetInfo/targetId")
                        .and_then(Value::as_str)
                    {
                        tracing::debug!(tid, "sniff: closing popup target");
                        // Short timeout: this must not compete with the sniff's
                        // own deadline for the default 30s — a popup close is
                        // fire-and-forget from the caller's point of view, and
                        // the event loop below stops consuming the broadcast
                        // channel while this is pending.
                        let _ = self
                            .client
                            .call_timeout(
                                "Target.closeTarget",
                                json!({ "targetId": tid }),
                                None,
                                Duration::from_secs(2),
                            )
                            .await;
                    }
                } else if let Some(child) = e.params.get("sessionId").and_then(Value::as_str) {
                    self.adopt_child(child).await;
                }
                continue;
            }

            // Accept events from any of our sessions (or session-less events).
            if let Some(sid) = &e.session_id {
                if !self
                    .sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(sid)
                {
                    continue;
                }
            }

            let req_id = e
                .params
                .get("requestId")
                .and_then(Value::as_str)
                .map(str::to_string);

            match e.method.as_str() {
                "Network.requestWillBeSent" => {
                    let Some(url_s) = e.params.pointer("/request/url").and_then(Value::as_str)
                    else {
                        continue;
                    };
                    tracing::trace!(url = %url_s, "sniff saw request");
                    let Ok(url) = Url::parse(url_s) else { continue };
                    let rtype = e.params.get("type").and_then(Value::as_str).unwrap_or("");
                    let hit = glob_hit(pattern, &url);
                    let trackable = req_id.is_some()
                        && req_type_trackable(rtype)
                        && (reqs.contains_key(req_id.as_deref().unwrap_or_default())
                            || reqs.len() < MAX_TRACKED_REQS);
                    // An ad-heavy embed page fires hundreds of requests over the
                    // timeout; the overwhelming majority are `Image`/`Font`/
                    // `Script`/etc, filtered out by `trackable` above. Building
                    // the header map (one alloc + clone per header) is wasted
                    // work for those — only pay for it on an actual match or a
                    // request worth tracking.
                    if !hit && !trackable {
                        continue;
                    }
                    let headers = header_map(e.params.pointer("/request/headers"));

                    if hit {
                        // Hold the match briefly so its requestWillBeSentExtraInfo
                        // (real Cookie / sec-ch-ua / sec-fetch-*) can be merged in.
                        if pending.is_none() {
                            if let Some(id) = &req_id {
                                let r = reqs.entry(id.clone()).or_default();
                                r.rtype = rtype.into();
                                r.url = Some(url.clone());
                                r.headers = headers;
                                pending = Some((id.clone(), url));
                                pending_until = Instant::now() + PENDING_GRACE;
                                continue;
                            }
                        }
                        tracing::debug!(%url, "sniff matched (url pattern)");
                        return Ok(self.hit(trigger, url, headers).await);
                    }
                    if let Some(id) = req_id {
                        let r = reqs.entry(id).or_default();
                        r.rtype = rtype.into();
                        r.url = Some(url);
                        r.headers = headers;
                    }
                }

                "Network.requestWillBeSentExtraInfo" => {
                    if let Some(id) = req_id {
                        if reqs.contains_key(&id) || reqs.len() < MAX_TRACKED_REQS {
                            let hdrs = header_map(e.params.pointer("/headers"));
                            if !hdrs.is_empty() {
                                reqs.entry(id).or_default().extra_headers = hdrs;
                            }
                        }
                    }
                }

                "Network.responseReceived" => {
                    let mime = e
                        .params
                        .pointer("/response/mimeType")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let url_s = e
                        .params
                        .pointer("/response/url")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let rtype = e.params.get("type").and_then(Value::as_str).unwrap_or("");
                    let status = e
                        .params
                        .pointer("/response/status")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    if rtype == "Document" && (status == 403 || status == 503) {
                        doc_403 = true;
                    }

                    if let Some(id) = &req_id {
                        if reqs.contains_key(id) || reqs.len() < MAX_TRACKED_REQS {
                            let r = reqs.entry(id.clone()).or_default();
                            r.status = status;
                            r.mime = mime.clone();
                            if !rtype.is_empty() {
                                r.rtype = rtype.into();
                            }
                            if r.url.is_none() {
                                r.url = Url::parse(url_s).ok();
                            }
                        }
                    }

                    // (2) manifest content-type — some CDNs: /playlist/<id>?… (no ext)
                    if is_manifest_mime(&mime) {
                        let taken = req_id.as_ref().and_then(|i| reqs.remove(i));
                        let (url, headers) = match taken {
                            Some(r) => (
                                r.url.unwrap_or_else(|| trigger.clone()),
                                merge_header_lists(r.headers, r.extra_headers),
                            ),
                            None => (
                                Url::parse(url_s).unwrap_or_else(|_| trigger.clone()),
                                Vec::new(),
                            ),
                        };
                        tracing::debug!(%url, %mime, "sniff matched (mime type)");
                        return Ok(self.hit(trigger, url, headers).await);
                    }

                    // (1b) glob match only visible at response time (redirects)
                    if let Ok(url) = Url::parse(url_s) {
                        if glob_hit(pattern, &url) {
                            let headers = req_id
                                .as_ref()
                                .and_then(|i| reqs.remove(i))
                                .map(|r| merge_header_lists(r.headers, r.extra_headers))
                                .unwrap_or_default();
                            tracing::debug!(%url, "sniff matched (url pattern, response)");
                            return Ok(self.hit(trigger, url, headers).await);
                        }
                    }
                }

                // (3) body sniff — after the body is complete. Gated so we only
                //     ever read a handful of small XHR/fetch/document bodies.
                "Network.loadingFinished" => {
                    let Some(id) = req_id else { continue };
                    let enc_len = e
                        .params
                        .get("encodedDataLength")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0);
                    let (rtype, status, mime) = match reqs.get(&id) {
                        Some(r) => (r.rtype.clone(), r.status, r.mime.clone()),
                        None => continue,
                    };
                    let worth = body_worth_type(&rtype)
                        && (200..300).contains(&status)
                        && enc_len > 0.0
                        && enc_len < MAX_BODY_BYTES
                        && !is_manifest_mime(&mime)
                        && body_reads < MAX_BODY_READS;
                    if !worth {
                        continue;
                    }
                    body_reads += 1;

                    let got = self
                        .client
                        .call(
                            "Network.getResponseBody",
                            json!({ "requestId": id }),
                            e.session_id.as_deref(),
                        )
                        .await;
                    let Ok(got) = got else { continue };
                    let raw = got.get("body").and_then(Value::as_str).unwrap_or("");
                    // `body_is_manifest` only inspects the document head
                    // (`#EXTM3U` / `<MPD…urn:mpeg:dash`), so decode/copy just the
                    // prefix — not a body that can be MB (× MAX_BODY_READS).
                    let text = if got.get("base64Encoded").and_then(Value::as_bool) == Some(true) {
                        use base64::Engine;
                        let n = raw.len().min(24 * 1024) / 4 * 4; // whole base64 quanta
                        base64::engine::general_purpose::STANDARD
                            .decode(&raw[..n])
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                            .unwrap_or_default()
                    } else {
                        raw.get(..16 * 1024).unwrap_or(raw).to_string()
                    };

                    if body_is_manifest(&text) {
                        if let Some(r) = reqs.remove(&id) {
                            let url = r.url.unwrap_or_else(|| trigger.clone());
                            tracing::debug!(%url, "sniff matched (body)");
                            let headers = merge_header_lists(r.headers, r.extra_headers);
                            return Ok(self.hit(trigger, url, headers).await);
                        }
                    }
                }
                _ => {}
            }
        }

        // Nothing matched — challenge or just a dud?
        let html = self.current_html_head().await;
        let session_count = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        tracing::debug!(sessions = session_count, "sniff gave up with no match");
        if doc_403 || looks_like_cloudflare_challenge(200, &html, None) {
            Err(BrowserError::Challenge)
        } else {
            Err(BrowserError::NoMatch)
        }
    }

    async fn eval(&mut self, url: &Url, js: &str, timeout: Duration) -> BrowserResult<Value> {
        self.goto(url, &WaitFor::Load, timeout).await?;
        self.iso_eval(js, timeout).await
    }

    fn user_agent(&self) -> String {
        if self.ua.is_empty() {
            self.default_ua.clone()
        } else {
            self.ua.clone()
        }
    }

    async fn storage_state(&mut self) -> BrowserResult<StorageState> {
        let mut params = json!({});
        if let Some(bc) = &self.browser_context_id {
            params["browserContextId"] = json!(bc);
        }
        // `browserContextId` is only valid on the browser target (no sessionId).
        let got = self.client.call("Storage.getCookies", params, None).await?;
        let cookies = got
            .get("cookies")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(cdp_to_cookie).collect())
            .unwrap_or_default();
        Ok(StorageState::from_cookies(cookies))
    }

    async fn close(self: Box<Self>) {
        let _ = self
            .client
            .call(
                "Target.closeTarget",
                json!({ "targetId": self.target_id }),
                None,
            )
            .await;
        if let Some(bc) = &self.browser_context_id {
            let _ = self
                .client
                .call(
                    "Target.disposeBrowserContext",
                    json!({ "browserContextId": bc }),
                    None,
                )
                .await;
        }
        // `in_use` / `last_used` bookkeeping happens in `Drop` so it stays
        // correct even if `close()` is never reached (a panic unwinds past it).
    }
}

impl Drop for CdpContext {
    fn drop(&mut self) {
        // The Fetch-domain SSRF guard task (see `spawn_fetch_guard`) is
        // per-context: without this it would outlive the context it was
        // guarding, one leaked task per acquired context (a real per-request
        // leak, unlike the engine-wide idle reaper). `close()` runs before
        // `Drop` in the normal path (it consumes `self: Box<Self>`, whose
        // fields still drop at the end of that call), so this covers both the
        // explicit-close and the panic-safety-net path below.
        if let Some(h) = self.fetch_guard.take() {
            h.abort();
        }
        // Safety net for the panic path: `close()` normally closes the target
        // gracefully; if we got here without it, fire-and-forget the teardown so
        // Chromium doesn't keep the renderer, and — crucially — release the
        // `in_use` slot so the idle reaper isn't wedged at a phantom count.
        self.client.notify(
            "Target.closeTarget",
            json!({ "targetId": self.target_id }),
            None,
        );
        if let Some(bc) = &self.browser_context_id {
            self.client.notify(
                "Target.disposeBrowserContext",
                json!({ "browserContextId": bc }),
                None,
            );
        }
        self.in_use.fetch_sub(1, Ordering::SeqCst);
        if let Ok(mut t) = self.last_used.lock() {
            *t = Instant::now();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fetch-domain SSRF guard
// ─────────────────────────────────────────────────────────────────────────────

/// How the SSRF guard should dispose of one intercepted `Fetch.requestPaused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchDecision {
    Allow,
    Block(&'static str),
}

/// Vet one request URL the browser is about to make, mirroring
/// `ssrf::guard_url`'s own rules (same literal-IP-always, DNS-only-when-direct
/// split) but as a fast, dependency-light, independently-unit-testable
/// function: it can't call `ssrf::guard_url` directly because that takes a
/// `&Url` + does its own thing with schemes cobweb's top-level entry points
/// never see (`data:`, `blob:`, `chrome-extension:`, …) which are legitimate
/// here and must not be blocked or even looked at.
async fn fetch_guard_decision(url_s: &str, is_direct: bool, allow_private: bool) -> FetchDecision {
    let Ok(url) = Url::parse(url_s) else {
        // An unparsable "URL" can't be an SSRF vector via cobweb's own network
        // stack either way — let Chromium's own handling deal with it.
        return FetchDecision::Allow;
    };
    match url.scheme() {
        "http" | "https" => {}
        // data:/blob:/chrome-extension:/about:/... never hit the network as an
        // arbitrary host the way http(s) does.
        _ => return FetchDecision::Allow,
    }
    let Some(host) = url.host_str().map(str::to_string) else {
        return FetchDecision::Allow;
    };
    let lower = host.to_ascii_lowercase();
    if !allow_private && (lower == "localhost" || lower.ends_with(".localhost")) {
        return FetchDecision::Block("localhost");
    }
    if let Ok(ip) = crate::ssrf::strip_brackets(&host).parse::<std::net::IpAddr>() {
        return match crate::ssrf::block_reason(ip, allow_private) {
            Some(r) => FetchDecision::Block(r),
            None => FetchDecision::Allow,
        };
    }
    if !is_direct {
        // Proxied egress: the proxy resolves and owns the exit, same rule as
        // `ssrf::guard_url`'s direct-egress split.
        return FetchDecision::Allow;
    }
    let port = url.port_or_known_default().unwrap_or(0);
    // Bound to a variable rather than used directly as the tail expression:
    // the borrow `host.as_str()` needs to outlive the temporary
    // `lookup_host(...).await` produces, and rustc's temporary-drop-order
    // rules for a tail expression otherwise drop `host` first.
    let decision = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addrs) => {
            let mut decision = FetchDecision::Allow;
            for sa in addrs {
                if let Some(r) = crate::ssrf::block_reason(sa.ip(), allow_private) {
                    decision = FetchDecision::Block(r);
                    break;
                }
            }
            decision
        }
        // Can't resolve => can't reach it either; not itself a reason to block.
        Err(_) => FetchDecision::Allow,
    };
    decision
}

/// A hard ceiling on `fetch_guard_decision` so a slow/wedged DNS resolution
/// never leaves a `Fetch.requestPaused` — and therefore the request itself —
/// hanging indefinitely: fail *open* (allow) on our own timeout rather than
/// turn a resolver hiccup into a stuck page load. This does not weaken the
/// guard for the common case (a literal IP or an already-cached name resolves
/// well under this).
const FETCH_GUARD_TIMEOUT: Duration = Duration::from_secs(3);

/// Spawn the background task that answers every `Fetch.requestPaused` event
/// belonging to `sessions` (the context's main session plus any adopted
/// sub-frame) for as long as the returned handle isn't aborted. This is what
/// actually closes the SSRF gap `ssrf::guard_url` leaves open once a browser
/// context exists: that guard only ever vets the *entry-point* navigation
/// URL, never a subresource, a redirect, or a `fetch()`/`XHR` a page's own JS
/// (including `/v1/eval`'s payload) makes afterwards — all of which go
/// through Chromium's own network stack.
///
/// Deliberately fails open (allows the request) on any internal error/timeout
/// rather than leaving it paused forever: a bug here should degrade back to
/// the pre-existing (unguarded) behaviour for that one request, never hang
/// the page load.
fn spawn_fetch_guard(
    client: Arc<CdpClient>,
    sessions: Arc<StdMutex<std::collections::HashSet<String>>>,
    allow_private: bool,
    is_direct: bool,
) -> tokio::task::JoinHandle<()> {
    let mut ev = client.subscribe();
    tokio::spawn(async move {
        loop {
            let e = match ev.recv().await {
                Ok(e) => e,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break, // CDP connection gone
            };
            if e.method != "Fetch.requestPaused" {
                continue;
            }
            let Some(sid) = e.session_id.clone() else {
                continue;
            };
            if !sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&sid)
            {
                continue;
            }
            let Some(request_id) = e
                .params
                .get("requestId")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };
            let url_s = e
                .params
                .pointer("/request/url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();

            // One task per intercepted request so a slow DNS lookup for one
            // request never delays the continue/fail decision for another
            // concurrent one — `Fetch.enable` pauses every request, so this
            // is directly on the page's load-latency critical path.
            let client = client.clone();
            tokio::spawn(async move {
                let decision = tokio::time::timeout(
                    FETCH_GUARD_TIMEOUT,
                    fetch_guard_decision(&url_s, is_direct, allow_private),
                )
                .await
                .unwrap_or(FetchDecision::Allow);
                match decision {
                    FetchDecision::Block(reason) => {
                        tracing::warn!(
                            url = %url_s,
                            reason,
                            "browser: blocking a request to a private/internal address"
                        );
                        let _ = client
                            .call_timeout(
                                "Fetch.failRequest",
                                json!({ "requestId": request_id, "errorReason": "BlockedByClient" }),
                                Some(&sid),
                                Duration::from_secs(5),
                            )
                            .await;
                    }
                    FetchDecision::Allow => {
                        let _ = client
                            .call_timeout(
                                "Fetch.continueRequest",
                                json!({ "requestId": request_id }),
                                Some(&sid),
                                Duration::from_secs(5),
                            )
                            .await;
                    }
                }
            });
        }
    })
}

/// Does `url` match the caller's glob set (path, full URL, or last segment)?
fn glob_hit(pattern: &GlobSet, url: &Url) -> bool {
    if pattern.is_empty() {
        return false;
    }
    pattern.is_match(url.path())
        || pattern.is_match(url.as_str())
        || url
            .path_segments()
            .and_then(|mut s| s.next_back())
            .map(|f| pattern.is_match(f))
            .unwrap_or(false)
}

/// HLS / DASH manifest content types (some CDNs serve the playlist from
/// `/playlist/<id>?…` with no extension, so URL globbing alone misses it).
fn is_manifest_mime(mime: &str) -> bool {
    let m = mime
        .split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .to_ascii_lowercase();
    matches!(
        m.as_str(),
        "application/vnd.apple.mpegurl"
            | "application/x-mpegurl"
            | "application/mpegurl"
            | "audio/mpegurl"
            | "audio/x-mpegurl"
            | "application/dash+xml"
            | "video/vnd.mpeg.dash.mpd"
    )
}

/// Resource types that could plausibly be — or redirect to — a stream manifest.
/// Static sub-resources never are, so the per-sniff request map skips them.
fn req_type_trackable(t: &str) -> bool {
    !matches!(
        t,
        "Image" | "Font" | "Stylesheet" | "Script" | "Ping" | "CSPViolationReport"
    )
}

/// Resource types whose body is cheap and plausibly a manifest.
fn body_worth_type(t: &str) -> bool {
    matches!(
        t,
        "XHR" | "Fetch" | "Document" | "Other" | "Manifest" | "Prefetch" | "TextTrack"
    )
}

/// Does a decoded response body look like an HLS or DASH manifest?
fn body_is_manifest(s: &str) -> bool {
    let head = s.trim_start();
    head.starts_with("#EXTM3U") || (head.contains("<MPD") && head.contains("urn:mpeg:dash"))
}

/// `base` with `overlay` folded on top: an overlay entry replaces a `base`
/// entry whose name matches case-insensitively, otherwise it is appended. Used
/// to merge `requestWillBeSentExtraInfo` headers (real Cookie / sec-ch-ua /
/// sec-fetch-*) onto the sparse `requestWillBeSent` set.
fn merge_header_lists(
    mut base: Vec<(String, String)>,
    overlay: Vec<(String, String)>,
) -> Vec<(String, String)> {
    for (k, v) in overlay {
        match base.iter_mut().find(|(bk, _)| bk.eq_ignore_ascii_case(&k)) {
            Some(slot) => slot.1 = v,
            None => base.push((k, v)),
        }
    }
    base
}

/// CDP headers object -> `Vec<(name, value)>`.
fn header_map(v: Option<&Value>) -> Vec<(String, String)> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn cookie_to_cdp(c: &Cookie) -> Value {
    let mut v = json!({
        "name": c.name,
        "value": c.value,
        "domain": c.domain,
        "path": c.path,
        "secure": c.secure,
        "httpOnly": c.http_only,
    });
    if c.expires >= 0.0 {
        v["expires"] = json!(c.expires);
    }
    if let Some(ss) = &c.same_site {
        v["sameSite"] = json!(ss);
    }
    v
}

fn cdp_to_cookie(v: &Value) -> Option<Cookie> {
    Some(Cookie {
        name: v.get("name")?.as_str()?.to_string(),
        value: v.get("value")?.as_str()?.to_string(),
        domain: v
            .get("domain")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        path: v
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string(),
        expires: v.get("expires").and_then(Value::as_f64).unwrap_or(-1.0),
        http_only: v.get("httpOnly").and_then(Value::as_bool).unwrap_or(false),
        secure: v.get("secure").and_then(Value::as_bool).unwrap_or(false),
        same_site: v
            .get("sameSite")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::{fetch_guard_decision, merge_header_lists, FetchDecision};

    fn pair(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    // `fetch_guard_decision` is the pure decision logic behind the Fetch-domain
    // SSRF guard (C1: cobweb's own network stack re-checking every request a
    // browser context makes, not just the entry-point navigation URL). It's
    // deliberately factored out so it's testable without a real Chromium.
    #[tokio::test]
    async fn fetch_guard_blocks_literal_private_and_metadata_addresses() {
        for url in [
            "http://127.0.0.1:8096/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5:6379",
            "http://[::1]/",
        ] {
            assert!(
                matches!(
                    fetch_guard_decision(url, true, false).await,
                    FetchDecision::Block(_)
                ),
                "{url} should be blocked"
            );
        }
    }

    #[tokio::test]
    async fn fetch_guard_blocks_literal_private_even_on_a_proxied_egress() {
        // Mirrors ssrf::guard_url: the literal-IP check is unconditional
        // regardless of is_direct.
        assert!(matches!(
            fetch_guard_decision("http://127.0.0.1/", false, false).await,
            FetchDecision::Block(_)
        ));
    }

    #[tokio::test]
    async fn fetch_guard_allows_public_addresses() {
        assert_eq!(
            fetch_guard_decision("https://1.1.1.1/", true, false).await,
            FetchDecision::Allow
        );
        assert_eq!(
            fetch_guard_decision("https://example.com/", true, false).await,
            FetchDecision::Allow
        );
    }

    #[tokio::test]
    async fn fetch_guard_allows_non_http_schemes_untouched() {
        for url in [
            "data:text/plain,hi",
            "blob:https://example.com/abc",
            "about:blank",
        ] {
            assert_eq!(
                fetch_guard_decision(url, true, false).await,
                FetchDecision::Allow
            );
        }
    }

    #[tokio::test]
    async fn fetch_guard_respects_allow_private_targets() {
        assert_eq!(
            fetch_guard_decision("http://10.0.0.5/", true, true).await,
            FetchDecision::Allow
        );
        // ...but never the always-bogus ranges, same as ssrf::block_reason.
        assert!(matches!(
            fetch_guard_decision("http://169.254.169.254/", true, true).await,
            FetchDecision::Block(_)
        ));
    }

    #[test]
    fn overlay_replaces_case_insensitively_and_appends_new() {
        // base = the sparse requestWillBeSent set; overlay = requestWillBeSentExtraInfo.
        let base = vec![
            pair("User-Agent", "chrome"),
            pair("Referer", "https://example.org/embed/1"),
        ];
        let overlay = vec![
            pair("referer", "https://example.org/embed/1"), // dup, different case
            pair("cookie", "__cf_bm=abc"),
            pair("sec-fetch-site", "same-origin"),
        ];
        let merged = merge_header_lists(base, overlay);

        // referer not duplicated
        assert_eq!(
            merged
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("referer"))
                .count(),
            1
        );
        // cookie + sec-fetch-site folded in
        assert!(merged
            .iter()
            .any(|(k, v)| k == "cookie" && v == "__cf_bm=abc"));
        assert!(merged
            .iter()
            .any(|(k, v)| k == "sec-fetch-site" && v == "same-origin"));
        // UA untouched
        assert!(merged
            .iter()
            .any(|(k, v)| k == "User-Agent" && v == "chrome"));
    }
}
