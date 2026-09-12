//! `AppState` — the shared handle every axum handler gets via `State<AppState>`.
//!
//! All fields are `Arc`, so `AppState` is cheap to `Clone` (axum clones it per
//! request).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::browser::{BrowserEngine, CdpEngine};
use crate::config::{BrowserEngine as EngineKind, Config};
use crate::egress::EgressRegistry;
use crate::fastpath::{FastClient, WreqClient};
use crate::jar::{Jar, SharedJar};
use crate::metrics::Metrics;
use crate::pipeline::{BrowserSniffTier, FastPathTier, Tier};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub egress: Arc<EgressRegistry>,
    pub jar: SharedJar,
    /// The fast-path client (`/v1/navigate`, tier 2) — also serves `/v1/fetch`
    /// via `FastClient::raw_client`, so one per-egress connection pool.
    pub fast: Arc<dyn FastClient>,
    /// Tier-2 wrapped as a pipeline `Tier` (used by `resolve()`).
    pub fast_tier: Arc<dyn Tier>,
    /// Tier-3 browser engine — `None` when `browser_engine = "none"`.
    pub browser: Option<Arc<dyn BrowserEngine>>,
    /// Tier-3 wrapped as a pipeline `Tier`. `Some` iff `browser` is `Some`.
    pub browser_tier: Option<Arc<dyn Tier>>,
    /// Process-wide counters for `/metrics`.
    pub metrics: Arc<Metrics>,
    /// Tier-4 manual VNC solve. `Some` iff `browser` is `Some`.
    #[cfg(feature = "vnc")]
    pub sessions: Option<Arc<crate::vnc::SessionManager>>,
    /// Tier-3b outbound FlareSolverr delegate. `Some` iff `[flaresolverr].endpoint` is set.
    #[cfg(feature = "flaresolverr")]
    pub flaresolverr: Option<Arc<crate::flaresolverr_client::FlaresolverrClient>>,
    /// yt-dlp subprocess path. `Some` iff `[ytdlp].enabled` and the binary resolves.
    #[cfg(feature = "ytdlp")]
    pub ytdlp: Option<Arc<crate::ytdlp::Ytdlp>>,
    started: Instant,
}

impl AppState {
    pub fn new(
        config: Config,
        egress: EgressRegistry,
        jar: Jar,
        fast: Arc<dyn FastClient>,
        browser: Option<Arc<dyn BrowserEngine>>,
    ) -> Self {
        let egress = Arc::new(egress);
        let jar = Arc::new(jar);

        let fast_tier: Arc<dyn Tier> = Arc::new(FastPathTier::new(fast.clone()));
        let browser_tier: Option<Arc<dyn Tier>> = browser
            .clone()
            .map(|b| Arc::new(BrowserSniffTier::new(b)) as Arc<dyn Tier>);

        #[cfg(feature = "vnc")]
        let sessions = browser.clone().map(|b| {
            Arc::new(crate::vnc::SessionManager::new(
                b,
                jar.clone(),
                egress.clone(),
                config.server.allow_private_targets,
            ))
        });

        #[cfg(feature = "flaresolverr")]
        let flaresolverr = config
            .flaresolverr
            .endpoint
            .as_deref()
            .filter(|e| !e.is_empty())
            .and_then(|ep| match crate::flaresolverr_client::FlaresolverrClient::new(ep) {
                Ok(c) => Some(Arc::new(c)),
                Err(e) => {
                    tracing::warn!(error = %e, "flaresolverr endpoint set but client build failed");
                    None
                }
            });

        #[cfg(feature = "ytdlp")]
        let ytdlp = crate::ytdlp::Ytdlp::from_config(&config.ytdlp).map(Arc::new);

        Self {
            config: Arc::new(config),
            egress,
            jar,
            fast,
            fast_tier,
            browser,
            browser_tier,
            metrics: Arc::new(Metrics::new()),
            #[cfg(feature = "vnc")]
            sessions,
            #[cfg(feature = "flaresolverr")]
            flaresolverr,
            #[cfg(feature = "ytdlp")]
            ytdlp,
            started: Instant::now(),
        }
    }

    /// Build from a parsed config with the production `wreq` fast client and,
    /// when `browser_engine = "chromium"`, the hand-rolled CDP engine.
    pub fn from_config(config: Config) -> crate::error::Result<Self> {
        let egress = EgressRegistry::from_config(&config)?;
        let jar = Jar::new(
            config.jar.path.clone(),
            Duration::from_secs(config.jar.default_ttl_secs),
            config.jar.fail_streak,
        );

        let browser: Option<Arc<dyn BrowserEngine>> = match config.server.browser_engine {
            EngineKind::None => None,
            EngineKind::Chromium => {
                // prewarm => keep Chromium hot: disable the idle reaper.
                let idle = if config.browser.prewarm {
                    0
                } else {
                    config.server.idle_shutdown_secs
                };
                Some(Arc::new(CdpEngine::new(
                    config.browser.clone(),
                    config.server.max_contexts,
                    idle,
                    config.server.allow_private_targets,
                )))
            }
        };

        let fast = Arc::new(WreqClient::new(config.server.allow_private_targets));
        Ok(Self::new(config, egress, jar, fast, browser))
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }
}
