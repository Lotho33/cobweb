//! One manual VNC solve at a time (DESIGN.md §3): open a live browser context
//! on the shared Chromium, point it at the challenge URL, expose it over
//! x11vnc; on close, write the solved `storage_state` back to the jar.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A manual session left open (admin closed the tab without calling `close`)
/// otherwise wedges the single slot forever. After this long, `start` reclaims it.
const SESSION_MAX_AGE: Duration = Duration::from_secs(20 * 60);

use tokio::sync::Mutex;
use url::Url;

use super::x11vnc::X11Vnc;
use crate::browser::{BrowserContext, BrowserEngine, ContextOptions, WaitFor};
use crate::egress::EgressRegistry;
use crate::error::{CobwebError, Result};
use crate::jar::{JarEntry, SharedJar};
use crate::pipeline::registrable_domain;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub target_url: String,
}

struct ActiveSession {
    id: String,
    target_url: String,
    started: Instant,
    ctx: Box<dyn BrowserContext>,
    vnc: X11Vnc,
    /// Jar coordinates to write the solved state back to.
    jar_domain: String,
    jar_egress: String,
    seed: Option<JarEntry>,
}

pub struct SessionManager {
    engine: Arc<dyn BrowserEngine>,
    jar: SharedJar,
    egress: Arc<EgressRegistry>,
    allow_private_targets: bool,
    inner: Mutex<Option<ActiveSession>>,
}

impl SessionManager {
    pub fn new(
        engine: Arc<dyn BrowserEngine>,
        jar: SharedJar,
        egress: Arc<EgressRegistry>,
        allow_private_targets: bool,
    ) -> Self {
        Self {
            engine,
            jar,
            egress,
            allow_private_targets,
            inner: Mutex::new(None),
        }
    }

    pub async fn start(
        &self,
        url_str: &str,
        egress_name: Option<&str>,
        proxy_url: Option<&str>,
    ) -> Result<SessionInfo> {
        let mut guard = self.inner.lock().await;
        if let Some(s) = guard.as_ref() {
            if s.started.elapsed() < SESSION_MAX_AGE {
                return Err(CobwebError::Conflict(format!(
                    "a manual session is already open ({})",
                    s.id
                )));
            }
            // Stale: the previous solver never called close. Reclaim the slot —
            // best-effort teardown, no jar writeback (we don't know if it solved).
            tracing::warn!(id = %s.id, "reclaiming a stale manual session");
            let stale = guard.take().unwrap();
            stale.ctx.close().await;
            stale.vnc.kill().await;
        }

        let url = Url::parse(url_str)
            .map_err(|_| CobwebError::BadRequest(format!("not a valid URL: {url_str}")))?;
        let domain = registrable_domain(&url)?;

        self.engine
            .ensure_ready()
            .await
            .map_err(|e| CobwebError::Browser(format!("browser not ready: {e}")))?;
        let display = self.engine.display().await.ok_or_else(|| {
            CobwebError::Browser(
                "no X display (headless) — a VNC solve needs browser.xvfb = true".into(),
            )
        })?;

        let egress = self.egress.resolve(egress_name, proxy_url)?;
        self.egress.ensure_available(&egress).await?;
        crate::ssrf::guard_url(&url, egress.is_direct(), self.allow_private_targets).await?;

        // Load the jar entry even if stale — the admin is here to re-solve it.
        let seed = self.jar.load(&domain, &egress).await;

        let opts = ContextOptions {
            egress: (*egress).clone(),
            seed: seed.as_ref().map(|j| j.storage_state.clone()),
            user_agent: seed
                .as_ref()
                .map(|j| j.user_agent.clone())
                .filter(|s| !s.is_empty()),
            accept_language: seed
                .as_ref()
                .map(|j| j.accept_language.clone())
                .filter(|s| !s.is_empty()),
            block_resources: false, // the admin needs to see the real page
        };

        let mut ctx = self
            .engine
            .acquire(opts)
            .await
            .map_err(|e| CobwebError::Browser(format!("acquire context: {e}")))?;
        ctx.navigate(&url, WaitFor::Load, Duration::from_secs(45))
            .await
            .map_err(|e| CobwebError::Browser(format!("navigate: {e}")))?;

        let vnc = X11Vnc::spawn(&display).await?;

        let id = format!(
            "s{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let info = SessionInfo {
            id: id.clone(),
            target_url: url.to_string(),
        };

        *guard = Some(ActiveSession {
            id,
            target_url: url.to_string(),
            started: Instant::now(),
            ctx,
            vnc,
            jar_domain: domain,
            jar_egress: egress.jar_key(),
            seed,
        });
        tracing::info!(url = %url, "manual session started");
        Ok(info)
    }

    /// Tear the session down. When `save_cookies` is true (the default from the
    /// API), the solved `storage_state` is written back to the jar for reuse by
    /// automated calls; when false, the session is discarded — for a
    /// look-around on a tab that doesn't need authorizing, whose cookies would
    /// only pollute the jar.
    pub async fn close(&self, id: &str, save_cookies: bool) -> Result<()> {
        let mut session = {
            let mut guard = self.inner.lock().await;
            let matches = guard.as_ref().map(|s| s.id == id).unwrap_or(false);
            if !matches {
                let msg = if guard.is_some() {
                    "session id does not match the open one"
                } else {
                    "no manual session is open"
                };
                return Err(CobwebError::BadRequest(msg.into()));
            }
            guard.take().unwrap()
        };

        if save_cookies {
            let state = session.ctx.storage_state().await.unwrap_or_default();
            let ttl = self.jar.default_ttl().as_secs();
            let mut entry = session.seed.unwrap_or_else(|| {
                JarEntry::new(session.jar_domain.clone(), session.jar_egress.clone(), ttl)
            });
            entry.domain = session.jar_domain;
            entry.egress = session.jar_egress;
            entry.storage_state = state;
            if let Err(e) = self.jar.note_success(entry).await {
                tracing::warn!(error = %e, "manual session: jar writeback failed");
            }
        }

        session.ctx.close().await;
        session.vnc.kill().await;
        tracing::info!(id, save_cookies, "manual session closed");
        Ok(())
    }

    pub async fn current(&self) -> SessionInfo {
        match self.inner.lock().await.as_ref() {
            Some(s) => SessionInfo {
                id: s.id.clone(),
                target_url: s.target_url.clone(),
            },
            None => SessionInfo {
                id: String::new(),
                target_url: String::new(),
            },
        }
    }

    /// RFB port for the websocket bridge, if `id` is the open session.
    pub async fn rfb_port(&self, id: &str) -> Option<u16> {
        self.inner
            .lock()
            .await
            .as_ref()
            .filter(|s| s.id == id)
            .map(|s| s.vnc.port)
    }
}
