//! Tracker/ad domain blocklist (AdGuard-style), managed **at runtime** via
//! `GET/PATCH /v1/blocklist` + `POST/PATCH/DELETE /v1/blocklist/sources`
//! (`src/api/blocklist.rs`) — not `config.toml`. Unlike every other piece of
//! state in cobweb (egress profiles, jar path, …), which is read once at
//! startup and never changes, sources here are meant to be added/toggled/
//! removed by an operator (typically mycelium's dashboard) without a
//! restart, the same way jar entries are managed via `GET/DELETE /v1/jar`.
//!
//! Independent of `block_resources`'s small, built-in ad-domain set
//! (`src/browser/cdp_engine.rs`): this pulls domains from hosts-format /
//! simple Adblock lists over HTTP. Each source's last successfully parsed
//! domain list is persisted alongside it (`BlocklistSource::domains`), so
//! toggling/removing a source recomputes the merged pattern set locally,
//! with no network fetch. The resulting glob patterns feed the same
//! `Network.setBlockedURLs` call `block_resources` already uses.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

use crate::config::BlocklistConfig;
use crate::egress::Egress;
use crate::error::{CobwebError, Result};
use crate::fastpath::{FastClient, FetchRequest};
use crate::util::{persist_json, random_token};

/// Parse one block-list body into a set of bare, lowercased domains.
///
/// Recognises hosts format (`0.0.0.0 domain` / `127.0.0.1 domain`, including
/// multiple hostnames on one line), bare `domain.tld` lines, and simple
/// Adblock domain rules (`||domain.tld^`, any trailing options ignored —
/// this is not a general ABP-rule parser, cosmetic/script rules are silently
/// skipped since they never match the `IP`/bare-domain/`||...^` shapes).
/// Comments (`#`, `!`), blank lines, and loopback/broadcast placeholder
/// entries are dropped.
pub fn parse_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("||") {
            let domain = rest.split(['^', '/', '$']).next().unwrap_or("");
            push_domain(&mut out, domain);
            continue;
        }
        let mut fields = line.split_whitespace();
        let first = fields.next().unwrap_or("");
        if first.parse::<std::net::IpAddr>().is_ok() {
            for host in fields {
                push_domain(&mut out, host);
            }
        } else {
            push_domain(&mut out, first);
        }
    }
    out
}

fn push_domain(out: &mut Vec<String>, candidate: &str) {
    let d = candidate.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || !d.contains('.') || is_placeholder(&d) {
        return;
    }
    out.push(d);
}

fn is_placeholder(domain: &str) -> bool {
    matches!(
        domain,
        "localhost.localdomain" | "ip6-localhost" | "ip6-loopback" | "0.0.0.0" | "255.255.255.255"
    )
}

/// The two glob patterns `Network.setBlockedURLs` needs to catch a domain
/// and every subdomain of it, anchored on the scheme/host boundary (more
/// precise than the existing static list's flat `*domain*` substring globs).
pub fn domain_to_patterns(domain: &str) -> [String; 2] {
    [format!("*://{domain}/*"), format!("*://*.{domain}/*")]
}

/// One operator-added list source. Persisted as part of [`BlocklistState`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSource {
    pub id: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub added_at: DateTime<Utc>,
    #[serde(default)]
    pub last_fetch_at: Option<DateTime<Utc>>,
    /// `None` == last fetch (if any) succeeded.
    #[serde(default)]
    pub last_error: Option<String>,
    /// This source's last successfully parsed domain list — kept even when a
    /// later refresh fails, so a transient outage doesn't blank the source.
    #[serde(default)]
    pub domains: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// The API-facing view of a source — `domain_count` instead of the full
/// `domains` list, which can run into the hundreds of thousands of entries.
#[derive(Debug, Clone, Serialize)]
pub struct BlocklistSourceView {
    pub id: String,
    pub url: String,
    pub enabled: bool,
    pub added_at: DateTime<Utc>,
    pub last_fetch_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub domain_count: usize,
}

impl From<&BlocklistSource> for BlocklistSourceView {
    fn from(s: &BlocklistSource) -> Self {
        Self {
            id: s.id.clone(),
            url: s.url.clone(),
            enabled: s.enabled,
            added_at: s.added_at,
            last_fetch_at: s.last_fetch_at,
            last_error: s.last_error.clone(),
            domain_count: s.domains.len(),
        }
    }
}

/// `GET /v1/blocklist` response.
#[derive(Debug, Clone, Serialize)]
pub struct BlocklistStatusView {
    pub enabled: bool,
    pub pattern_count: usize,
    pub sources: Vec<BlocklistSourceView>,
}

/// The whole persisted document — one JSON file at `[blocklist].state_path`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BlocklistState {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    sources: Vec<BlocklistSource>,
}

/// Runtime-managed blocklist. `state` (sources + master switch) is mutated
/// through the `add_source`/`set_*`/`remove_source` API below and persisted
/// to `cfg.state_path` on every change; `patterns` is the compiled glob-set
/// snapshot `CdpEngine` reads on every context acquire — kept in a separate,
/// synchronous lock so a hot-path read never contends with an admin mutation
/// or a background refresh.
pub struct Blocklist {
    cfg: BlocklistConfig,
    state: AsyncMutex<BlocklistState>,
    patterns: StdRwLock<Arc<Vec<String>>>,
}

impl Blocklist {
    /// Best-effort synchronous load from `cfg.state_path` (survives a
    /// restart); empty/disabled if there's no state file yet or it's
    /// unreadable/corrupt.
    pub fn new(cfg: BlocklistConfig) -> Self {
        let state: BlocklistState = std::fs::read(&cfg.state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        if !state.sources.is_empty() {
            tracing::info!(
                sources = state.sources.len(),
                enabled = state.enabled,
                path = %cfg.state_path.display(),
                "blocklist: loaded persisted state"
            );
        }
        let patterns = compute_patterns(&state, &cfg.extra_domains, &cfg.allow_domains);
        Self {
            cfg,
            state: AsyncMutex::new(state),
            patterns: StdRwLock::new(Arc::new(patterns)),
        }
    }

    /// Cheap read for `CdpEngine` — never touches `state`'s async lock.
    pub fn snapshot(&self) -> Arc<Vec<String>> {
        self.patterns
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub async fn status(&self) -> BlocklistStatusView {
        let state = self.state.lock().await;
        self.status_locked(&state)
    }

    fn status_locked(&self, state: &BlocklistState) -> BlocklistStatusView {
        BlocklistStatusView {
            enabled: state.enabled,
            pattern_count: self.snapshot().len(),
            sources: state
                .sources
                .iter()
                .map(BlocklistSourceView::from)
                .collect(),
        }
    }

    /// Toggle the master switch. No network fetch — just recomputes from
    /// whatever domains each source already has cached.
    pub async fn set_enabled(&self, enabled: bool) -> BlocklistStatusView {
        let mut state = self.state.lock().await;
        state.enabled = enabled;
        self.recompute_and_persist(&mut state).await;
        self.status_locked(&state)
    }

    /// Add a source and fetch+parse it immediately, so the caller gets a
    /// real answer (success + domain count, or the fetch error) rather than
    /// having to poll. The source is kept even on a failed fetch — retried
    /// by the next periodic `refresh()` — matching the rest of this module's
    /// "one failure doesn't nuke everything" posture.
    pub async fn add_source(
        &self,
        url: String,
        fast: &Arc<dyn FastClient>,
    ) -> Result<BlocklistSourceView> {
        Url::parse(&url)
            .map_err(|e| CobwebError::BadRequest(format!("blocklist source url: {e}")))?;
        let (domains, last_error) = match fetch_source(fast, &url).await {
            Ok(body) => (parse_list(&body), None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        let source = BlocklistSource {
            id: random_token(8),
            url,
            enabled: true,
            added_at: Utc::now(),
            last_fetch_at: Some(Utc::now()),
            last_error,
            domains,
        };
        let view = BlocklistSourceView::from(&source);
        let mut state = self.state.lock().await;
        state.sources.push(source);
        self.recompute_and_persist(&mut state).await;
        Ok(view)
    }

    /// Toggle one source on/off — no network fetch, recomputed locally from
    /// its already-cached `domains`.
    pub async fn set_source_enabled(&self, id: &str, enabled: bool) -> Result<BlocklistSourceView> {
        let mut state = self.state.lock().await;
        let source = state
            .sources
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| CobwebError::BadRequest(format!("no such blocklist source: {id}")))?;
        source.enabled = enabled;
        let view = BlocklistSourceView::from(&*source);
        self.recompute_and_persist(&mut state).await;
        Ok(view)
    }

    pub async fn remove_source(&self, id: &str) -> bool {
        let mut state = self.state.lock().await;
        let before = state.sources.len();
        state.sources.retain(|s| s.id != id);
        let removed = state.sources.len() != before;
        if removed {
            self.recompute_and_persist(&mut state).await;
        }
        removed
    }

    /// Re-fetch every *enabled* source and recompute the merged pattern set.
    /// A no-op if the master switch is off or there's nothing enabled. The
    /// target list is snapshotted before any network call so this never
    /// holds `state`'s lock — and so blocks no admin API call — for the
    /// whole fetch round; a source added/removed concurrently is simply not
    /// in this round's `results` and is left untouched by the merge below.
    /// A single source's fetch failing is logged and keeps that source's
    /// last-known-good `domains` rather than blanking it.
    pub async fn refresh(&self, fast: &Arc<dyn FastClient>) {
        let targets: Vec<(String, String)> = {
            let state = self.state.lock().await;
            if !state.enabled {
                return;
            }
            state
                .sources
                .iter()
                .filter(|s| s.enabled)
                .map(|s| (s.id.clone(), s.url.clone()))
                .collect()
        };
        if targets.is_empty() {
            return;
        }
        let mut results = Vec::with_capacity(targets.len());
        for (id, url) in targets {
            let result = fetch_source(fast, &url).await;
            match &result {
                Ok(body) => {
                    tracing::debug!(source = %url, count = parse_list(body).len(), "blocklist: refreshed source");
                }
                Err(e) => {
                    tracing::warn!(source = %url, error = %e, "blocklist: source refresh failed, keeping previous domains");
                }
            }
            results.push((id, result));
        }

        let mut state = self.state.lock().await;
        for (id, result) in results {
            if let Some(source) = state.sources.iter_mut().find(|s| s.id == id) {
                source.last_fetch_at = Some(Utc::now());
                match result {
                    Ok(body) => {
                        source.domains = parse_list(&body);
                        source.last_error = None;
                    }
                    Err(e) => source.last_error = Some(e.to_string()),
                }
            }
        }
        self.recompute_and_persist(&mut state).await;
    }

    /// Recompute `patterns` from `state` + `cfg.extra_domains`/`allow_domains`
    /// and persist `state` to `cfg.state_path`. Logs (doesn't propagate) a
    /// persistence failure — the in-memory patterns are already updated
    /// either way, so a disk hiccup here degrades to "forgets on restart",
    /// not "blocklist stops working".
    async fn recompute_and_persist(&self, state: &mut BlocklistState) {
        let patterns = compute_patterns(state, &self.cfg.extra_domains, &self.cfg.allow_domains);
        *self.patterns.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(patterns);
        if let Err(e) = persist_json(&self.cfg.state_path, &*state).await {
            tracing::warn!(error = %e, "blocklist: failed to persist state");
        }
    }

    /// `tokio::spawn`ed by the caller — sleeps `refresh_interval_secs` (never
    /// under 60s), then refreshes, forever. Mirrors the manual sleep-loop
    /// idiom `CdpEngine::start_reaper` uses rather than a `tokio::time::interval`.
    /// Cheap to always run: `refresh()` returns immediately when disabled or
    /// there are no enabled sources.
    pub async fn spawn_refresh_loop(self: Arc<Self>, fast: Arc<dyn FastClient>) {
        let interval = Duration::from_secs(self.cfg.refresh_interval_secs.max(60));
        loop {
            tokio::time::sleep(interval).await;
            self.refresh(&fast).await;
        }
    }
}

fn compute_patterns(state: &BlocklistState, extra: &[String], allow: &[String]) -> Vec<String> {
    if !state.enabled {
        return Vec::new();
    }
    let mut domains: BTreeSet<String> = extra
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    for source in state.sources.iter().filter(|s| s.enabled) {
        domains.extend(source.domains.iter().cloned());
    }
    for a in allow {
        domains.remove(a.trim().to_ascii_lowercase().as_str());
    }
    domains.iter().flat_map(|d| domain_to_patterns(d)).collect()
}

async fn fetch_source(fast: &Arc<dyn FastClient>, src: &str) -> Result<String> {
    let url = Url::parse(src).map_err(|e| {
        CobwebError::Config(format!("blocklist source `{src}` is not a valid URL: {e}"))
    })?;
    let egress = Egress::direct();
    let resp = fast
        .fetch(FetchRequest {
            url: &url,
            egress: &egress,
            user_agent: None,
            accept_language: None,
            cookie_header: None,
            extra_headers: &[],
            timeout: Duration::from_secs(30),
        })
        .await?;
    if resp.status >= 400 {
        return Err(CobwebError::Upstream(format!(
            "GET {src}: HTTP {}",
            resp.status
        )));
    }
    Ok(resp.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fastpath::FetchResponse;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parses_hosts_format() {
        let text = "\
            # comment\n\
            0.0.0.0 ads.example.com\n\
            127.0.0.1 tracker.example.net other.example.net\n\
            0.0.0.0 0.0.0.0\n\
            127.0.0.1 localhost\n\
            \n";
        let domains = parse_list(text);
        assert_eq!(
            domains,
            vec![
                "ads.example.com",
                "tracker.example.net",
                "other.example.net"
            ]
        );
    }

    #[test]
    fn parses_bare_domains_and_abp_rules() {
        let text = "\
            ! abp comment\n\
            ||abp-tracker.example.com^\n\
            bare-domain.example.org\n\
            ||scoped.example.net^$third-party\n";
        let domains = parse_list(text);
        assert_eq!(
            domains,
            vec![
                "abp-tracker.example.com",
                "bare-domain.example.org",
                "scoped.example.net"
            ]
        );
    }

    #[test]
    fn skips_placeholders_and_dotless_entries() {
        let text = "0.0.0.0 localhost\n0.0.0.0 broadcasthost\nlocalhost.localdomain\nnodot\n";
        assert!(parse_list(text).is_empty());
    }

    #[test]
    fn domain_to_patterns_covers_host_and_subdomains() {
        let p = domain_to_patterns("ads.example.com");
        assert_eq!(
            p,
            [
                "*://ads.example.com/*".to_string(),
                "*://*.ads.example.com/*".to_string()
            ]
        );
    }

    struct FakeFast {
        bodies: HashMap<String, String>,
        calls: AtomicUsize,
    }

    impl FakeFast {
        fn arc(bodies: HashMap<String, String>) -> Arc<dyn FastClient> {
            Arc::new(Self {
                bodies,
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl FastClient for FakeFast {
        async fn fetch(&self, req: FetchRequest<'_>) -> Result<FetchResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.bodies.get(req.url.as_str()) {
                Some(body) => Ok(FetchResponse {
                    status: 200,
                    final_url: req.url.clone(),
                    headers: Vec::new(),
                    body: body.clone(),
                    set_cookies: Vec::new(),
                }),
                None => Err(CobwebError::Upstream(format!(
                    "no such fixture: {}",
                    req.url
                ))),
            }
        }
        fn engine(&self) -> &'static str {
            "fake"
        }
    }

    fn cfg() -> BlocklistConfig {
        BlocklistConfig {
            state_path: tempfile::NamedTempFile::new().unwrap().path().to_path_buf(),
            refresh_interval_secs: 86_400,
            extra_domains: vec!["extra.example.com".into()],
            allow_domains: vec!["allowed.example.com".into()],
        }
    }

    #[tokio::test]
    async fn add_source_fetches_immediately_and_computes_patterns() {
        let mut bodies = HashMap::new();
        bodies.insert(
            "http://fixture.invalid/hosts.txt".to_string(),
            "0.0.0.0 tracked.example.com\n0.0.0.0 allowed.example.com\n".to_string(),
        );
        let fast = FakeFast::arc(bodies);
        let bl = Blocklist::new(cfg());

        // Disabled master: patterns stay empty even with a source added.
        let view = bl
            .add_source("http://fixture.invalid/hosts.txt".into(), &fast)
            .await
            .unwrap();
        assert!(view.last_error.is_none());
        // `domain_count` is this source's raw parsed count — `allow_domains`
        // is only subtracted later, when merging into `patterns`.
        assert_eq!(view.domain_count, 2);
        assert!(bl.snapshot().is_empty(), "master switch still off");

        bl.set_enabled(true).await;
        let snap = bl.snapshot();
        assert!(snap.contains(&"*://tracked.example.com/*".to_string()));
        assert!(snap.contains(&"*://extra.example.com/*".to_string()));
        assert!(!snap.iter().any(|p| p.contains("allowed.example.com")));
    }

    #[tokio::test]
    async fn add_source_with_failing_fetch_is_still_recorded() {
        let fast = FakeFast::arc(HashMap::new());
        let bl = Blocklist::new(cfg());
        let view = bl
            .add_source("http://missing.invalid/hosts.txt".into(), &fast)
            .await
            .unwrap();
        assert!(view.last_error.is_some());
        assert_eq!(view.domain_count, 0);
        let status = bl.status().await;
        assert_eq!(status.sources.len(), 1, "kept despite the failed fetch");
    }

    #[tokio::test]
    async fn add_source_rejects_a_malformed_url() {
        let fast = FakeFast::arc(HashMap::new());
        let bl = Blocklist::new(cfg());
        let err = bl.add_source("not a url".into(), &fast).await.unwrap_err();
        assert_eq!(err.kind(), "bad_request");
    }

    #[tokio::test]
    async fn toggling_and_removing_a_source_never_touches_the_network() {
        let mut bodies = HashMap::new();
        bodies.insert(
            "http://fixture.invalid/hosts.txt".to_string(),
            "0.0.0.0 tracked.example.com\n".to_string(),
        );
        let fast = FakeFast::arc(bodies);
        let bl = Blocklist::new(cfg());
        bl.set_enabled(true).await;
        let view = bl
            .add_source("http://fixture.invalid/hosts.txt".into(), &fast)
            .await
            .unwrap();
        assert!(bl
            .snapshot()
            .contains(&"*://tracked.example.com/*".to_string()));

        bl.set_source_enabled(&view.id, false).await.unwrap();
        assert!(!bl
            .snapshot()
            .contains(&"*://tracked.example.com/*".to_string()));
        assert!(bl
            .snapshot()
            .contains(&"*://extra.example.com/*".to_string()));

        bl.set_source_enabled(&view.id, true).await.unwrap();
        assert!(bl
            .snapshot()
            .contains(&"*://tracked.example.com/*".to_string()));

        let removed = bl.remove_source(&view.id).await;
        assert!(removed);
        assert!(!bl
            .snapshot()
            .contains(&"*://tracked.example.com/*".to_string()));
        assert!(!bl.remove_source(&view.id).await, "already gone");
    }

    #[tokio::test]
    async fn set_source_enabled_unknown_id_is_bad_request() {
        let bl = Blocklist::new(cfg());
        let err = bl.set_source_enabled("nope", true).await.unwrap_err();
        assert_eq!(err.kind(), "bad_request");
    }

    #[tokio::test]
    async fn set_enabled_false_empties_patterns_without_losing_source_data() {
        let mut bodies = HashMap::new();
        bodies.insert(
            "http://fixture.invalid/hosts.txt".to_string(),
            "0.0.0.0 tracked.example.com\n".to_string(),
        );
        let fast = FakeFast::arc(bodies);
        let bl = Blocklist::new(cfg());
        bl.set_enabled(true).await;
        bl.add_source("http://fixture.invalid/hosts.txt".into(), &fast)
            .await
            .unwrap();
        assert!(!bl.snapshot().is_empty());

        bl.set_enabled(false).await;
        assert!(bl.snapshot().is_empty());

        bl.set_enabled(true).await;
        assert!(
            bl.snapshot()
                .contains(&"*://tracked.example.com/*".to_string()),
            "re-enabling recomputes from the still-cached source domains, no re-fetch needed"
        );
    }

    #[tokio::test]
    async fn refresh_updates_only_enabled_sources_and_keeps_failed_ones_last_known_good() {
        let mut bodies = HashMap::new();
        bodies.insert(
            "http://a.invalid/hosts.txt".to_string(),
            "0.0.0.0 a.example.com\n".to_string(),
        );
        let fast = FakeFast::arc(bodies.clone());
        let bl = Blocklist::new(cfg());
        bl.set_enabled(true).await;
        let a = bl
            .add_source("http://a.invalid/hosts.txt".into(), &fast)
            .await
            .unwrap();
        let b = bl
            .add_source("http://b.invalid/hosts.txt".into(), &fast) // not in `bodies` => fails
            .await
            .unwrap();
        assert!(b.last_error.is_some());
        bl.set_source_enabled(&a.id, false).await.unwrap();

        // Refresh: `a` is disabled (skipped), `b` fails again (network still
        // has no fixture for it) but must keep whatever domains it had
        // (none, in this case, since its first fetch also failed).
        bl.refresh(&fast).await;
        let status = bl.status().await;
        let a_after = status.sources.iter().find(|s| s.id == a.id).unwrap();
        let b_after = status.sources.iter().find(|s| s.id == b.id).unwrap();
        assert_eq!(
            a_after.domain_count, 1,
            "disabled source untouched, not re-fetched"
        );
        assert!(b_after.last_error.is_some());
    }

    #[tokio::test]
    async fn new_loads_persisted_state_and_recomputes_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let mut bodies = HashMap::new();
        bodies.insert(
            "http://fixture.invalid/hosts.txt".to_string(),
            "0.0.0.0 tracked.example.com\n".to_string(),
        );
        let fast = FakeFast::arc(bodies);
        {
            let bl = Blocklist::new(BlocklistConfig {
                state_path: state_path.clone(),
                ..cfg()
            });
            bl.set_enabled(true).await;
            bl.add_source("http://fixture.invalid/hosts.txt".into(), &fast)
                .await
                .unwrap();
        }

        let reloaded = Blocklist::new(BlocklistConfig {
            state_path,
            ..cfg()
        });
        assert!(reloaded
            .snapshot()
            .contains(&"*://tracked.example.com/*".to_string()));
    }
}
