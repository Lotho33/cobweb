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

/// Returned only by [`SessionManager::start`] — **never** by
/// [`SessionManager::current`] — so the per-session secret required to open
/// `vnc-ws` reaches the caller that just authenticated (via
/// `[server].api_key`) to start the session, and no one who merely polls
/// `GET /v1/session/current` for its id.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionStarted {
    pub id: String,
    pub target_url: String,
    pub vnc_token: String,
}

struct ActiveSession {
    id: String,
    target_url: String,
    /// High-entropy secret required (as a `?token=` query param — a browser's
    /// WebSocket API can't attach custom headers) to open this session's
    /// `vnc-ws`. Closes the takeover window where a session's id, obtainable
    /// from the otherwise-unauthenticated `GET /v1/session/current`, used to
    /// be sufficient on its own to watch *and drive* someone else's solve.
    token: String,
    started: Instant,
    ctx: Box<dyn BrowserContext>,
    vnc: X11Vnc,
    /// Jar coordinates to write the solved state back to.
    jar_domain: String,
    jar_egress: String,
    seed: Option<JarEntry>,
}

/// The manual-session slot: empty, mid-`start()` (reserved so a second
/// `start()` — or a stale-session reclaim racing it — can't also proceed, but
/// *not* holding the manager's lock for the whole browser-launch/navigate
/// duration), or holding the one active session.
enum Slot {
    Empty,
    Starting,
    // Boxed: `ActiveSession` carries a `Box<dyn BrowserContext>` and an
    // `X11Vnc` and is much larger than the other two (data-less) variants —
    // clippy::large_enum_variant.
    Active(Box<ActiveSession>),
}

pub struct SessionManager {
    engine: Arc<dyn BrowserEngine>,
    jar: SharedJar,
    egress: Arc<EgressRegistry>,
    allow_private_targets: bool,
    inner: Mutex<Slot>,
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
            inner: Mutex::new(Slot::Empty),
        }
    }

    /// Reserve the slot (or fail fast if one is already open/starting),
    /// reclaiming a stale session's teardown outside the lock. Returns the
    /// stale session to tear down, if any.
    async fn reserve_slot(&self) -> Result<Option<Box<ActiveSession>>> {
        let mut guard = self.inner.lock().await;
        match &*guard {
            Slot::Active(s) if s.started.elapsed() < SESSION_MAX_AGE => Err(CobwebError::Conflict(
                format!("a manual session is already open ({})", s.id),
            )),
            Slot::Starting => Err(CobwebError::Conflict(
                "a manual session is already starting".into(),
            )),
            Slot::Active(_) => {
                let Slot::Active(stale) = std::mem::replace(&mut *guard, Slot::Starting) else {
                    unreachable!()
                };
                Ok(Some(stale))
            }
            Slot::Empty => {
                *guard = Slot::Starting;
                Ok(None)
            }
        }
    }

    pub async fn start(
        &self,
        url_str: &str,
        egress_name: Option<&str>,
        proxy_url: Option<&str>,
    ) -> Result<SessionStarted> {
        let stale = match self.reserve_slot().await {
            Ok(stale) => stale,
            Err(e) => return Err(e),
        };
        if let Some(stale) = stale {
            // Best-effort teardown, no jar writeback (we don't know if it
            // solved) — done with the lock free so it can't stack on top of
            // the slow work below.
            let stale = *stale;
            tracing::warn!(id = %stale.id, "reclaiming a stale manual session");
            stale.ctx.close().await;
            stale.vnc.kill().await;
        }

        // The slot is reserved (`Starting`) but the lock is free from here on:
        // `current()` / `close()` / a concurrent `start()` all see `Starting`
        // and return immediately instead of blocking behind the
        // seconds-long browser acquire + navigate + x11vnc spawn below.
        let outcome = self.start_inner(url_str, egress_name, proxy_url).await;

        let mut guard = self.inner.lock().await;
        match outcome {
            Ok((info, session)) => {
                *guard = Slot::Active(Box::new(session));
                Ok(info)
            }
            Err(e) => {
                *guard = Slot::Empty;
                Err(e)
            }
        }
    }

    async fn start_inner(
        &self,
        url_str: &str,
        egress_name: Option<&str>,
        proxy_url: Option<&str>,
    ) -> Result<(SessionStarted, ActiveSession)> {
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
        crate::ssrf::guard_egress(&egress, self.allow_private_targets).await?;
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
        let token = crate::util::random_token(24);
        let info = SessionStarted {
            id: id.clone(),
            target_url: url.to_string(),
            vnc_token: token.clone(),
        };

        let session = ActiveSession {
            id,
            target_url: url.to_string(),
            token,
            started: Instant::now(),
            ctx,
            vnc,
            jar_domain: domain,
            jar_egress: egress.jar_key(),
            seed,
        };
        tracing::info!(url = %crate::util::redact_url_query(&url), "manual session started");
        Ok((info, session))
    }

    /// Tear the session down. When `save_cookies` is true (the default from the
    /// API), the solved `storage_state` is written back to the jar for reuse by
    /// automated calls; when false, the session is discarded — for a
    /// look-around on a tab that doesn't need authorizing, whose cookies would
    /// only pollute the jar.
    pub async fn close(&self, id: &str, save_cookies: bool) -> Result<()> {
        let mut session = {
            let mut guard = self.inner.lock().await;
            match &*guard {
                Slot::Active(s) if s.id == id => {}
                Slot::Active(_) => {
                    return Err(CobwebError::BadRequest(
                        "session id does not match the open one".into(),
                    ))
                }
                Slot::Starting => {
                    return Err(CobwebError::Conflict(
                        "a manual session is still starting".into(),
                    ))
                }
                Slot::Empty => {
                    return Err(CobwebError::BadRequest("no manual session is open".into()))
                }
            }
            let Slot::Active(s) = std::mem::replace(&mut *guard, Slot::Empty) else {
                unreachable!()
            };
            *s
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
        match &*self.inner.lock().await {
            Slot::Active(s) => SessionInfo {
                id: s.id.clone(),
                target_url: s.target_url.clone(),
            },
            Slot::Starting | Slot::Empty => SessionInfo {
                id: String::new(),
                target_url: String::new(),
            },
        }
    }

    /// RFB port for the websocket bridge, if `id` is the open session **and**
    /// `token` matches its per-session secret.
    pub async fn rfb_port(&self, id: &str, token: &str) -> Option<u16> {
        match &*self.inner.lock().await {
            Slot::Active(s) if s.id == id && crate::util::constant_time_eq(&s.token, token) => {
                Some(s.vnc.port)
            }
            _ => None,
        }
    }
}
