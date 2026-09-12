//! An in-memory [`BrowserEngine`] for tests — no Chromium, no CDP.
//!
//! Scriptable: pick what `sniff` / `navigate` / `eval` return, and whether
//! `ensure_ready` succeeds.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use globset::GlobSet;
use url::Url;

use super::engine::*;
use crate::jar::{Cookie, StorageState};

#[derive(Debug, Clone)]
pub enum SniffScript {
    /// A network hit matched.
    Hit {
        url: String,
        headers: Vec<(String, String)>,
    },
    /// Landed on a challenge page.
    Challenge,
    /// Navigation finished, nothing matched.
    NoMatch,
    /// Never resolved.
    Timeout,
}

#[derive(Clone)]
pub struct MockEngine {
    ready: bool,
    /// Consumed one per `acquire`; the last entry repeats.
    scripts: Arc<Mutex<Vec<SniffScript>>>,
    /// Cookies the context reports via `storage_state` (jar-writeback assertions).
    storage_cookies: Vec<Cookie>,
    nav_html: String,
    eval_result: serde_json::Value,
    acquired: Arc<AtomicUsize>,
}

impl Default for MockEngine {
    fn default() -> Self {
        Self {
            ready: true,
            scripts: Arc::new(Mutex::new(vec![SniffScript::NoMatch])),
            storage_cookies: vec![Cookie::new("cf_clearance", "mock", ".example.test")],
            nav_html: "<html><body>mock</body></html>".into(),
            eval_result: serde_json::Value::Null,
            acquired: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl MockEngine {
    pub fn with_sniff(script: SniffScript) -> Self {
        Self::with_sniffs(vec![script])
    }

    /// One script per `acquire` call; the final one repeats.
    pub fn with_sniffs(scripts: Vec<SniffScript>) -> Self {
        Self {
            scripts: Arc::new(Mutex::new(if scripts.is_empty() {
                vec![SniffScript::NoMatch]
            } else {
                scripts
            })),
            ..Self::default()
        }
    }

    fn next_script(&self) -> SniffScript {
        let mut q = self.scripts.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() > 1 {
            q.remove(0)
        } else {
            q.first().cloned().unwrap_or(SniffScript::NoMatch)
        }
    }

    pub fn unavailable() -> Self {
        Self {
            ready: false,
            ..Self::default()
        }
    }

    pub fn nav_html(mut self, html: impl Into<String>) -> Self {
        self.nav_html = html.into();
        self
    }

    pub fn eval_result(mut self, v: serde_json::Value) -> Self {
        self.eval_result = v;
        self
    }

    /// How many contexts have been acquired (all mock contexts are "released"
    /// immediately, so this doubles as a "did tier 3 run?" probe).
    pub fn acquired(&self) -> usize {
        self.acquired.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl BrowserEngine for MockEngine {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn ensure_ready(&self) -> BrowserResult<()> {
        if self.ready {
            Ok(())
        } else {
            Err(BrowserError::Unavailable(
                "mock engine set to unavailable".into(),
            ))
        }
    }

    async fn acquire(&self, opts: ContextOptions) -> BrowserResult<Box<dyn BrowserContext>> {
        self.acquired.fetch_add(1, Ordering::SeqCst);
        // Reflect the seed like a real context would, then layer our own cookies.
        let mut cookies = opts.seed.map(|s| s.cookies).unwrap_or_default();
        for c in &self.storage_cookies {
            cookies.push(c.clone());
        }
        Ok(Box::new(MockContext {
            sniff: self.next_script(),
            storage_cookies: cookies,
            nav_html: self.nav_html.clone(),
            eval_result: self.eval_result.clone(),
        }))
    }

    fn contexts_in_use(&self) -> usize {
        0
    }

    async fn display(&self) -> Option<String> {
        None
    }

    async fn shutdown(&self) {}
}

struct MockContext {
    sniff: SniffScript,
    storage_cookies: Vec<Cookie>,
    nav_html: String,
    eval_result: serde_json::Value,
}

#[async_trait]
impl BrowserContext for MockContext {
    async fn navigate(
        &mut self,
        url: &Url,
        _wait: WaitFor,
        _timeout: Duration,
    ) -> BrowserResult<PageLoad> {
        let challenge = matches!(self.sniff, SniffScript::Challenge);
        Ok(PageLoad {
            html: self.nav_html.clone(),
            final_url: url.clone(),
            challenge,
        })
    }

    async fn sniff(
        &mut self,
        trigger: &Url,
        _pattern: &GlobSet,
        timeout: Duration,
    ) -> BrowserResult<SniffHit> {
        match &self.sniff {
            SniffScript::Hit { url, headers } => {
                let u = Url::parse(url)
                    .or_else(|_| trigger.join(url))
                    .map_err(|e| BrowserError::Other(anyhow::anyhow!("mock bad url: {e}")))?;
                Ok(SniffHit {
                    url: u,
                    request_headers: headers.clone(),
                    final_url: trigger.clone(),
                })
            }
            SniffScript::Challenge => Err(BrowserError::Challenge),
            SniffScript::NoMatch => Err(BrowserError::NoMatch),
            SniffScript::Timeout => Err(BrowserError::Timeout(timeout)),
        }
    }

    async fn eval(
        &mut self,
        _url: &Url,
        _js: &str,
        _timeout: Duration,
    ) -> BrowserResult<serde_json::Value> {
        Ok(self.eval_result.clone())
    }

    fn user_agent(&self) -> String {
        "Mozilla/5.0 (mock) Chrome/147".to_string()
    }

    async fn storage_state(&mut self) -> BrowserResult<StorageState> {
        Ok(StorageState::from_cookies(self.storage_cookies.clone()))
    }

    async fn close(self: Box<Self>) {}
}
