//! Configuration: `serde` + `toml`, loaded once at startup.
//!
//! Shape mirrors `config.example.toml`. Everything here is plain data; the
//! runtime registries (`EgressRegistry`, `Jar`) are built *from* this in
//! `main.rs` / `AppState::from_config`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{CobwebError, Result};

/// Top-level config file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub browser: BrowserConfig,
    #[serde(default)]
    pub jar: JarConfig,
    /// `[egress.<name>]` tables. Every request picks one by name (or passes a
    /// raw `proxy_url`). At least `direct` should exist.
    #[serde(default)]
    pub egress: BTreeMap<String, EgressConfig>,
    #[serde(default)]
    pub flaresolverr: FlaresolverrConfig,
    #[serde(default)]
    pub ytdlp: YtdlpConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub settings: SettingsConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind. Defaults to loopback (`127.0.0.1`): the API is
    /// unauthenticated and exposes an SSRF-capable fetcher and a browser-eval
    /// endpoint, so it must not face an untrusted network. Set `"0.0.0.0"`
    /// (or `"::"`) only when a trusted reverse proxy or a container network is
    /// in front.
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// `"chromium"` = full pipeline (M2+). `"none"` = fast-path only, tiers 3-4
    /// disabled, process stays ~10 MB.
    #[serde(default)]
    pub browser_engine: BrowserEngine,
    /// Concurrent browser contexts; requests beyond this queue. Static —
    /// resizing the underlying semaphore live isn't safe, unlike the other
    /// tier-3 knob (idle-shutdown), which moved to `[settings]`/
    /// `GET/PATCH /v1/settings` (`RuntimeSettings::idle_shutdown_secs`).
    #[serde(default = "default_max_contexts")]
    pub max_contexts: usize,
    /// SSRF guard relaxation. When `false` (the default) every fetcher resolves
    /// the target host first and refuses any address that is private / loopback
    /// / link-local / CGNAT / ULA, re-checked after each redirect. Set `true`
    /// only when cobweb is *meant* to reach hosts on your own private network
    /// (e.g. a LAN media server) — containment is then your firewall's job.
    /// The cloud metadata address and a few always-bogus ranges stay blocked
    /// either way.
    #[serde(default)]
    pub allow_private_targets: bool,
    /// Shared secret required on every request (`Authorization: Bearer <key>`
    /// or `X-Api-Key: <key>`) except `GET /health`. Unset => the API is
    /// unauthenticated; `main.rs` warns loudly at startup if that's combined
    /// with a non-loopback bind.
    #[serde(default)]
    pub api_key: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            browser_engine: BrowserEngine::default(),
            max_contexts: default_max_contexts(),
            allow_private_targets: false,
            api_key: None,
        }
    }
}

impl ServerConfig {
    /// The configured API key, or `None` if unset/blank (so `api_key = ""` in
    /// a config file behaves the same as omitting the key entirely, instead of
    /// silently requiring callers to send an empty header value).
    pub fn effective_api_key(&self) -> Option<&str> {
        self.api_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
    }

    pub fn listen_addr(&self) -> SocketAddr {
        // `validate()` already rejected an unparseable bind; fall back to
        // loopback rather than the old 0.0.0.0 if something slips through.
        let ip = self
            .bind
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        SocketAddr::new(ip, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BrowserEngine {
    /// Tiers 3-4 disabled at runtime. Process stays ~10 MB.
    #[default]
    None,
    /// Full pipeline: the hand-rolled CDP client drives a single Chromium.
    Chromium,
}

/// `[browser]` — how the tier-3 Chromium is launched. Only consulted when
/// `server.browser_engine = "chromium"`. The per-navigation default timeout
/// moved to `[settings]`/`GET/PATCH /v1/settings`
/// (`RuntimeSettings::nav_timeout_ms`) — it's a request-tuning knob, not a
/// launch flag, so it can change without relaunching Chromium.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConfig {
    /// Chromium/Chrome binary. `"auto"` => search PATH for common names.
    #[serde(default = "default_chromium_path")]
    pub chromium_path: String,
    /// Pass `--no-sandbox`. Auto-enabled when cobweb runs as root (the usual
    /// container case, where the sandbox can't initialise and Chromium exits).
    #[serde(default)]
    pub no_sandbox: bool,
    /// Launch Chromium at startup and never idle-shut-down. Trades resident
    /// memory for ~2 s off every tier-3 resolve. Off => lazy.
    #[serde(default)]
    pub prewarm: bool,
    /// Extra flags appended to the Chromium command line.
    #[serde(default)]
    pub extra_args: Vec<String>,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            chromium_path: default_chromium_path(),
            no_sandbox: false,
            prewarm: false,
            extra_args: Vec::new(),
        }
    }
}

/// `[jar]` — just the on-disk path now. The default TTL and fail-streak
/// threshold moved to `[settings]`/`GET/PATCH /v1/settings`
/// (`RuntimeSettings::jar_default_ttl_secs`/`jar_fail_streak`) — tuning
/// knobs, not the jar's location.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JarConfig {
    #[serde(default = "default_jar_path")]
    pub path: PathBuf,
}

impl Default for JarConfig {
    fn default() -> Self {
        Self {
            path: default_jar_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConfig {
    /// SOCKS5/HTTP proxy URL, or `""` for no proxy (only meaningful for a
    /// profile conceptually named `direct`).
    #[serde(default)]
    pub proxy: String,
}

/// `session_ttl_secs` moved to `[settings]`/`GET/PATCH /v1/settings`
/// (`RuntimeSettings::flaresolverr_session_ttl_secs`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlaresolverrConfig {
    /// Unset => outbound delegate (tier 3b) disabled.
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YtdlpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ytdlp_bin")]
    pub bin: String,
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl Default for YtdlpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bin: default_ytdlp_bin(),
            hosts: Vec::new(),
        }
    }
}

/// `[blocklist]` — operational knobs for the AdGuard-style tracker/ad domain
/// blocking on the tier-3 Chromium sniff (`src/blocklist.rs`). Independent of
/// `block_resources` (which blocks media/asset extensions for a cheaper
/// sniff): this blocks *domains* pulled from lists.
///
/// Unlike every other section here, **the lists themselves and the master
/// on/off switch are not config** — they're runtime state, managed via
/// `GET/PATCH /v1/blocklist` and `POST/PATCH/DELETE /v1/blocklist/sources`
/// (same `[server].api_key` auth as the rest of `/v1/*`), persisted at
/// `state_path`, and meant to be added/toggled by an operator (typically
/// mycelium's dashboard) without a restart — the same way jar entries are
/// managed via `GET/DELETE /v1/jar` instead of a config file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistConfig {
    /// Where the source list + master switch are persisted.
    #[serde(default = "default_blocklist_state_path")]
    pub state_path: PathBuf,
    /// How often to re-fetch every enabled source (seconds).
    #[serde(default = "default_blocklist_refresh_secs")]
    pub refresh_interval_secs: u64,
    /// Extra domains to block, merged in on every refresh (no source URL
    /// needed).
    #[serde(default)]
    pub extra_domains: Vec<String>,
    /// Domains to always exclude, even if a source blocks them — the escape
    /// hatch for a false positive that breaks a site's resolution.
    #[serde(default)]
    pub allow_domains: Vec<String>,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            state_path: default_blocklist_state_path(),
            refresh_interval_secs: default_blocklist_refresh_secs(),
            extra_domains: Vec::new(),
            allow_domains: Vec::new(),
        }
    }
}

/// `[settings]` — just where `RuntimeSettings` (`src/settings.rs`) persists
/// itself. Everything it manages (DNS servers, `nav_timeout_ms`, jar TTL/
/// fail-streak, the FlareSolverr session TTL, the browser idle-shutdown
/// threshold) is runtime state, not config — see `GET/PATCH /v1/settings`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsConfig {
    #[serde(default = "default_settings_state_path")]
    pub state_path: PathBuf,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            state_path: default_settings_state_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

impl Config {
    /// Parse a TOML string.
    pub fn parse(toml_str: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(toml_str)
            .map_err(|e| CobwebError::Config(format!("invalid config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load from a file path.
    pub async fn load(path: &Path) -> Result<Self> {
        let text = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| CobwebError::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// A minimal usable default (used by tests and `--print-config`).
    pub fn minimal() -> Self {
        let mut egress = BTreeMap::new();
        egress.insert(
            "direct".to_string(),
            EgressConfig {
                proxy: String::new(),
            },
        );
        Config {
            server: ServerConfig::default(),
            browser: BrowserConfig::default(),
            jar: JarConfig::default(),
            egress,
            flaresolverr: FlaresolverrConfig::default(),
            ytdlp: YtdlpConfig::default(),
            blocklist: BlocklistConfig::default(),
            settings: SettingsConfig::default(),
            log: LogConfig::default(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.server.bind.parse::<IpAddr>().is_err() {
            return Err(CobwebError::Config(format!(
                "server.bind is not a valid IP address: {}",
                self.server.bind
            )));
        }
        if self.egress.is_empty() {
            return Err(CobwebError::Config(
                "no [egress.*] profiles configured; at least `direct` is required".into(),
            ));
        }
        for (name, e) in &self.egress {
            if !e.proxy.is_empty() {
                url::Url::parse(&e.proxy).map_err(|_| {
                    CobwebError::Config(format!(
                        "egress `{name}`: proxy is not a valid URL: {}",
                        e.proxy
                    ))
                })?;
            }
        }
        if self.server.max_contexts == 0 {
            return Err(CobwebError::Config(
                "server.max_contexts must be >= 1".into(),
            ));
        }
        Ok(())
    }
}

fn default_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    8191
}
fn default_max_contexts() -> usize {
    2
}
fn default_jar_path() -> PathBuf {
    PathBuf::from("/data/jar")
}
fn default_ytdlp_bin() -> String {
    "yt-dlp".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_chromium_path() -> String {
    "auto".to_string()
}
fn default_blocklist_refresh_secs() -> u64 {
    86_400
}
fn default_blocklist_state_path() -> PathBuf {
    PathBuf::from("/data/blocklist/state.json")
}
fn default_settings_state_path() -> PathBuf {
    PathBuf::from("/data/settings.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_example_config() {
        let text = include_str!("../config.example.toml");
        let cfg = Config::parse(text).expect("example config must parse");
        assert_eq!(cfg.server.port, 8191);
        assert_eq!(cfg.jar.path, PathBuf::from("/data/jar"));
        assert!(cfg.egress.contains_key("direct"));
        assert_eq!(cfg.egress["mullvad"].proxy, "socks5://mullvad:1080");
        assert!(cfg.flaresolverr.endpoint.is_none());
        assert!(!cfg.ytdlp.enabled);
        assert_eq!(
            cfg.blocklist.state_path,
            PathBuf::from("/data/blocklist/state.json")
        );
        assert_eq!(
            cfg.settings.state_path,
            PathBuf::from("/data/settings.json")
        );
    }

    #[test]
    fn blocklist_config_parses_and_defaults() {
        let text = r#"
            [egress.direct]
            proxy = ""
            [blocklist]
            state_path = "/data/blocklist/state.json"
            extra_domains = ["ads.example.net"]
            allow_domains = ["cdn.example.com"]
        "#;
        let cfg = Config::parse(text).expect("blocklist config must parse");
        assert_eq!(cfg.blocklist.extra_domains, vec!["ads.example.net"]);
        assert_eq!(cfg.blocklist.allow_domains, vec!["cdn.example.com"]);
        assert_eq!(cfg.blocklist.refresh_interval_secs, 86_400);
    }

    #[test]
    fn blocklist_section_is_optional() {
        let text = r#"
            [egress.direct]
            proxy = ""
        "#;
        let cfg = Config::parse(text).expect("config without [blocklist] must still parse");
        assert_eq!(
            cfg.blocklist.state_path,
            PathBuf::from("/data/blocklist/state.json")
        );
    }

    #[test]
    fn rejects_config_with_no_egress() {
        let err = Config::parse("[server]\nport = 9000\n").unwrap_err();
        assert!(matches!(err, CobwebError::Config(_)));
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = Config::parse("[server]\nnope = 1\n[egress.direct]\nproxy = \"\"\n").unwrap_err();
        assert!(matches!(err, CobwebError::Config(_)));
    }

    #[test]
    fn browser_engine_defaults_to_none() {
        let cfg = Config::parse("[egress.direct]\nproxy = \"\"\n").unwrap();
        assert_eq!(cfg.server.browser_engine, BrowserEngine::None);
    }

    #[test]
    fn bind_defaults_to_loopback() {
        let cfg = Config::parse("[egress.direct]\nproxy = \"\"\n").unwrap();
        assert_eq!(cfg.server.bind, "127.0.0.1");
        assert_eq!(cfg.server.listen_addr(), "127.0.0.1:8191".parse().unwrap());
    }

    #[test]
    fn honours_explicit_bind() {
        let cfg =
            Config::parse("[server]\nbind = \"0.0.0.0\"\n[egress.direct]\nproxy = \"\"\n").unwrap();
        assert_eq!(cfg.server.listen_addr(), "0.0.0.0:8191".parse().unwrap());
    }

    #[test]
    fn rejects_invalid_bind() {
        let err = Config::parse("[server]\nbind = \"not-an-ip\"\n[egress.direct]\nproxy = \"\"\n")
            .unwrap_err();
        assert!(matches!(err, CobwebError::Config(_)));
    }
}
