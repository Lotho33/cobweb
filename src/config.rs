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
    #[serde(default = "default_max_contexts")]
    pub max_contexts: usize,
    #[serde(default = "default_idle_shutdown_secs")]
    pub idle_shutdown_secs: u64,
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
    /// or `X-Api-Key: <key>`) except `GET /health`, the vendored noVNC static
    /// assets, and the VNC websocket upgrade (which carries its own
    /// per-session token — see `[server].allow_private_targets` neighbour
    /// `vnc::session`). Unset => the API is unauthenticated; `main.rs` warns
    /// loudly at startup if that's combined with a non-loopback bind.
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
            idle_shutdown_secs: default_idle_shutdown_secs(),
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
/// `server.browser_engine = "chromium"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConfig {
    /// Chromium/Chrome binary. `"auto"` => search PATH for common names.
    #[serde(default = "default_chromium_path")]
    pub chromium_path: String,
    /// Run headed inside an Xvfb display. Required only for the tier-4 manual
    /// VNC solve. Default `false` => `--headless=new`, which is lighter (no Xvfb
    /// process, ~150-250 MB less resident) at the cost of a "new headless"
    /// detection signal. Set `true` if you rely on the manual solve.
    #[serde(default)]
    pub xvfb: bool,
    /// Pass `--no-sandbox`. Auto-enabled when cobweb runs as root (the usual
    /// container case, where the sandbox can't initialise and Chromium exits).
    #[serde(default)]
    pub no_sandbox: bool,
    /// Launch Chromium + Xvfb at startup and never idle-shut-down. Trades
    /// ~500 MB resident for ~2 s off every tier-3 resolve. Off => lazy.
    #[serde(default)]
    pub prewarm: bool,
    /// Extra flags appended to the Chromium command line.
    #[serde(default)]
    pub extra_args: Vec<String>,
    /// Per-navigation default timeout (ms) when a request doesn't set one.
    #[serde(default = "default_nav_timeout_ms")]
    pub nav_timeout_ms: u64,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            chromium_path: default_chromium_path(),
            xvfb: false,
            no_sandbox: false,
            prewarm: false,
            extra_args: Vec::new(),
            nav_timeout_ms: default_nav_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JarConfig {
    #[serde(default = "default_jar_path")]
    pub path: PathBuf,
    /// Fallback `cf_clearance` lifetime when `Set-Cookie` gives no `Max-Age`.
    #[serde(default = "default_jar_ttl_secs")]
    pub default_ttl_secs: u64,
    /// N consecutive 403/challenge responses on a jar entry => mark it stale.
    #[serde(default = "default_fail_streak")]
    pub fail_streak: u32,
}

impl Default for JarConfig {
    fn default() -> Self {
        Self {
            path: default_jar_path(),
            default_ttl_secs: default_jar_ttl_secs(),
            fail_streak: default_fail_streak(),
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlaresolverrConfig {
    /// Unset => outbound delegate (tier 3b) disabled.
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_fs_session_ttl_secs")]
    pub session_ttl_secs: u64,
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
fn default_idle_shutdown_secs() -> u64 {
    900
}
fn default_jar_path() -> PathBuf {
    PathBuf::from("/data/jar")
}
fn default_jar_ttl_secs() -> u64 {
    2700
}
fn default_fail_streak() -> u32 {
    3
}
fn default_fs_session_ttl_secs() -> u64 {
    1800
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
fn default_nav_timeout_ms() -> u64 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_example_config() {
        let text = include_str!("../config.example.toml");
        let cfg = Config::parse(text).expect("example config must parse");
        assert_eq!(cfg.server.port, 8191);
        assert_eq!(cfg.jar.default_ttl_secs, 2700);
        assert!(cfg.egress.contains_key("direct"));
        assert_eq!(cfg.egress["mullvad"].proxy, "socks5://mullvad:1080");
        assert!(cfg.flaresolverr.endpoint.is_none());
        assert!(!cfg.ytdlp.enabled);
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
