//! The browser engine seam (DESIGN.md §3 "CDP client strategy", §8).
//!
//! `resolve()` and `/v1/sniff` depend only on these traits. The default (and
//! only shipping) impl is the hand-rolled CDP client (`browser/cdp.rs`, M2b)
//! which **never sends `Runtime.enable`**; `MockEngine` backs the tests. A
//! `chromiumoxide`-backed fallback was evaluated during design (DESIGN.md §3)
//! but never implemented — this trait is the seam a future one would slot
//! into, not a promise that one already exists.

use std::time::Duration;

use async_trait::async_trait;
use globset::GlobSet;
use url::Url;

use crate::egress::Egress;
use crate::jar::StorageState;

#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    /// Engine could not start (no Chromium binary, Xvfb failed, …).
    #[error("browser engine unavailable: {0}")]
    Unavailable(String),
    /// Navigation or sniff exceeded its deadline with no result.
    #[error("browser timed out after {0:?}")]
    Timeout(Duration),
    /// Landed on a Cloudflare / managed-challenge interstitial.
    #[error("landed on a challenge page")]
    Challenge,
    /// Navigation finished but nothing matched `url_pattern`.
    #[error("no request matched the pattern")]
    NoMatch,
    /// Anything from the CDP transport itself.
    #[error("cdp: {0}")]
    Cdp(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type BrowserResult<T> = Result<T, BrowserError>;

/// How long `navigate` should wait before returning the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitFor {
    /// `Page.loadEventFired`.
    Load,
    /// `Page.domContentEventFired`.
    DomContentLoaded,
    /// ~500 ms with no in-flight requests.
    NetworkIdle,
    /// A CSS selector appears in the DOM.
    Selector(String),
}

/// What a context is seeded with on acquire.
#[derive(Debug, Clone)]
pub struct ContextOptions {
    pub egress: Egress,
    pub seed: Option<StorageState>,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    /// Block image/font/media/stylesheet requests (cheaper sniffs).
    pub block_resources: bool,
}

/// A loaded page (post-JS DOM).
#[derive(Debug, Clone)]
pub struct PageLoad {
    pub html: String,
    pub final_url: Url,
    pub challenge: bool,
}

/// A network hit that matched `url_pattern` during a sniff.
#[derive(Debug, Clone)]
pub struct SniffHit {
    pub url: Url,
    /// Request headers Chromium sent for the matched request — replay these to
    /// fetch the stream (auth, referer, cookie, UA).
    pub request_headers: Vec<(String, String)>,
    pub final_url: Url,
}

#[async_trait]
pub trait BrowserEngine: Send + Sync {
    /// Name for `/health` (`"cdp"`, `"mock"`).
    fn name(&self) -> &'static str;

    /// Lazily launch (first call) or no-op. Cheap after the first success.
    async fn ensure_ready(&self) -> BrowserResult<()>;

    /// Acquire an isolated context; blocks on the context semaphore.
    async fn acquire(&self, opts: ContextOptions) -> BrowserResult<Box<dyn BrowserContext>>;

    /// For `/health`.
    fn contexts_in_use(&self) -> usize;

    /// The X display Chromium is running on (e.g. `":100"`), so x11vnc can
    /// attach to the same one for a manual solve. `None` when headless / not up.
    async fn display(&self) -> Option<String>;

    /// Tear down Chromium + Xvfb (idle shutdown / process exit).
    async fn shutdown(&self);
}

#[async_trait]
pub trait BrowserContext: Send {
    /// Navigate and return the page once `wait` is satisfied.
    async fn navigate(
        &mut self,
        url: &Url,
        wait: WaitFor,
        timeout: Duration,
    ) -> BrowserResult<PageLoad>;

    /// Navigate to `trigger`, then resolve when a request/response URL matches
    /// `pattern`. `Err(Challenge)` if it lands on a challenge first.
    /// **Must not enable the `Runtime` domain.**
    async fn sniff(
        &mut self,
        trigger: &Url,
        pattern: &GlobSet,
        timeout: Duration,
    ) -> BrowserResult<SniffHit>;

    /// Run `js` in a fresh `Page.createIsolatedWorld`; returns the JSON result.
    async fn eval(
        &mut self,
        url: &Url,
        js: &str,
        timeout: Duration,
    ) -> BrowserResult<serde_json::Value>;

    /// Cookies + storage for jar writeback.
    async fn storage_state(&mut self) -> BrowserResult<StorageState>;

    /// The effective User-Agent this context is sending (for FlareSolverr's
    /// `solution.userAgent`). Empty if unknown.
    fn user_agent(&self) -> String;

    /// Release the context (jar writeback is the caller's job via
    /// `storage_state` before this).
    async fn close(self: Box<Self>);
}
