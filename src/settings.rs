//! Runtime-configurable operational settings — `GET/PATCH /v1/settings`
//! (`src/api/settings.rs`). DNS servers plus a handful of timeout/TTL knobs
//! mycelium can tune without a `config.toml` edit + restart, mirroring how
//! `src/blocklist.rs` turned `[blocklist]`'s sources into runtime state: one
//! persisted JSON document (`[settings].state_path`) that is the live
//! source of truth for the process.
//!
//! Deliberately **excluded** (stay `config.toml`-only, operator/restart-only):
//! `[server].bind`/`api_key`/`allow_private_targets`, `[egress.*]` (the SSRF
//! guard specifically trusts these *because* they're static operator config,
//! not request/API-mutable — see `src/ssrf.rs::guard_egress`), Chromium
//! launch flags, and `[server].max_contexts` (sizes a `tokio::sync::Semaphore`
//! at construction; safely shrinking one live is materially riskier than the
//! knobs here and stays restart-only for now).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};

use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};

use crate::config::SettingsConfig;
use crate::error::{CobwebError, Result};
use crate::util::persist_json;

/// Cloudflare's public resolver — the default so cobweb resolves correctly
/// out of the box even when a target site is DNS-blocked by the host/
/// container's own resolver, without needing an operator to configure
/// anything first (the concrete motivation: many streaming sites cobweb
/// resolves are blocked at the DNS level by ISPs).
const DEFAULT_DNS_SERVERS: &[&str] = &["1.1.1.1", "1.0.0.1"];

/// The live DNS backend behind [`crate::ssrf::GuardedResolver`].
pub enum DnsBackend {
    /// `dns_servers` is empty: system resolver only (`GuardedResolver`
    /// builds a fresh `wreq::dns::GaiResolver` per call — cheap, and matches
    /// this variant carrying no state of its own).
    System,
    /// One or more explicit servers. `GuardedResolver` tries these first and
    /// falls back to the system resolver on failure — required so a SOCKS5/
    /// HTTP proxy's own hostname (e.g. a Docker-Compose service name like
    /// `mullvad`, resolved today via the container's embedded DNS) keeps
    /// working even when `dns_servers` points at a public resolver that has
    /// never heard of it.
    Custom(Arc<TokioResolver>),
}

pub struct ResolvedDns {
    pub servers: Vec<String>,
    pub backend: DnsBackend,
}

fn build_dns(servers: &[String]) -> Result<ResolvedDns> {
    if servers.is_empty() {
        return Ok(ResolvedDns {
            servers: Vec::new(),
            backend: DnsBackend::System,
        });
    }
    let mut name_servers = Vec::with_capacity(servers.len());
    for s in servers {
        let ip: IpAddr = s
            .parse()
            .map_err(|_| CobwebError::BadRequest(format!("dns_servers: not an IP address: {s}")))?;
        name_servers.push(NameServerConfig::udp_and_tcp(ip));
    }
    let resolver_config = ResolverConfig::from_name_servers(name_servers);
    let resolver =
        TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
            .build()
            .map_err(|e| CobwebError::Other(anyhow::anyhow!("build DNS resolver: {e}")))?;
    Ok(ResolvedDns {
        servers: servers.to_vec(),
        backend: DnsBackend::Custom(Arc::new(resolver)),
    })
}

/// The persisted document.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettingsDoc {
    #[serde(default = "default_dns_servers")]
    dns_servers: Vec<String>,
    #[serde(default = "default_nav_timeout_ms")]
    nav_timeout_ms: u64,
    #[serde(default = "default_jar_ttl_secs")]
    jar_default_ttl_secs: u64,
    #[serde(default = "default_fail_streak")]
    jar_fail_streak: u32,
    #[serde(default = "default_fs_session_ttl_secs")]
    flaresolverr_session_ttl_secs: u64,
    #[serde(default = "default_idle_shutdown_secs")]
    idle_shutdown_secs: u64,
}

impl Default for SettingsDoc {
    fn default() -> Self {
        Self {
            dns_servers: default_dns_servers(),
            nav_timeout_ms: default_nav_timeout_ms(),
            jar_default_ttl_secs: default_jar_ttl_secs(),
            jar_fail_streak: default_fail_streak(),
            flaresolverr_session_ttl_secs: default_fs_session_ttl_secs(),
            idle_shutdown_secs: default_idle_shutdown_secs(),
        }
    }
}

fn default_dns_servers() -> Vec<String> {
    DEFAULT_DNS_SERVERS.iter().map(|s| s.to_string()).collect()
}
fn default_nav_timeout_ms() -> u64 {
    30_000
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
fn default_idle_shutdown_secs() -> u64 {
    900
}

/// `GET /v1/settings` response, and the body of `PATCH /v1/settings`'s
/// response.
#[derive(Debug, Clone, Serialize)]
pub struct SettingsView {
    pub dns_servers: Vec<String>,
    pub nav_timeout_ms: u64,
    pub jar_default_ttl_secs: u64,
    pub jar_fail_streak: u32,
    pub flaresolverr_session_ttl_secs: u64,
    pub idle_shutdown_secs: u64,
}

/// `PATCH /v1/settings` request — every field optional, only the ones
/// present are changed.
#[derive(Debug, Default, Deserialize)]
pub struct SettingsPatch {
    pub dns_servers: Option<Vec<String>>,
    pub nav_timeout_ms: Option<u64>,
    pub jar_default_ttl_secs: Option<u64>,
    pub jar_fail_streak: Option<u32>,
    pub flaresolverr_session_ttl_secs: Option<u64>,
    pub idle_shutdown_secs: Option<u64>,
}

/// Live settings store. `dns` is read on every outbound DNS resolution
/// (`GuardedResolver`), so it's a cheap sync `RwLock` over an `Arc` snapshot;
/// the scalar knobs are independent atomics — no shared lock needed since
/// they're read/written one at a time.
pub struct RuntimeSettings {
    state_path: std::path::PathBuf,
    dns: StdRwLock<Arc<ResolvedDns>>,
    nav_timeout_ms: AtomicU64,
    jar_default_ttl_secs: AtomicU64,
    jar_fail_streak: AtomicU32,
    flaresolverr_session_ttl_secs: AtomicU64,
    idle_shutdown_secs: AtomicU64,
}

impl RuntimeSettings {
    /// Best-effort synchronous load from `cfg.state_path` (survives a
    /// restart); defaults (incl. `dns_servers = ["1.1.1.1", "1.0.0.1"]`) if
    /// there's no state file yet or it's unreadable/corrupt. A corrupt
    /// `dns_servers` entry falls back to the default servers rather than
    /// failing startup outright.
    pub fn new(cfg: SettingsConfig) -> Self {
        let doc: SettingsDoc = std::fs::read(&cfg.state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let dns = build_dns(&doc.dns_servers).unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "settings: persisted dns_servers invalid, falling back to defaults"
            );
            build_dns(&default_dns_servers()).expect("default DNS servers must build")
        });
        Self {
            state_path: cfg.state_path,
            dns: StdRwLock::new(Arc::new(dns)),
            nav_timeout_ms: AtomicU64::new(doc.nav_timeout_ms),
            jar_default_ttl_secs: AtomicU64::new(doc.jar_default_ttl_secs),
            jar_fail_streak: AtomicU32::new(doc.jar_fail_streak.max(1)),
            flaresolverr_session_ttl_secs: AtomicU64::new(doc.flaresolverr_session_ttl_secs),
            idle_shutdown_secs: AtomicU64::new(doc.idle_shutdown_secs),
        }
    }

    pub fn view(&self) -> SettingsView {
        SettingsView {
            dns_servers: self
                .dns
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .servers
                .clone(),
            nav_timeout_ms: self.nav_timeout_ms(),
            jar_default_ttl_secs: self.jar_default_ttl_secs(),
            jar_fail_streak: self.jar_fail_streak(),
            flaresolverr_session_ttl_secs: self.flaresolverr_session_ttl_secs(),
            idle_shutdown_secs: self.idle_shutdown_secs(),
        }
    }

    /// Apply a partial update, persist the result, and return the fresh
    /// view. `dns_servers`, if present, is validated (every entry must parse
    /// as an IP — no hostnames/DoH in this round) before anything is
    /// changed, so a bad request never partially applies.
    pub async fn apply(&self, patch: SettingsPatch) -> Result<SettingsView> {
        let new_dns = match &patch.dns_servers {
            Some(servers) => Some(build_dns(servers)?),
            None => None,
        };
        if let Some(dns) = new_dns {
            *self.dns.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(dns);
        }
        if let Some(v) = patch.nav_timeout_ms {
            self.nav_timeout_ms.store(v, Ordering::Relaxed);
        }
        if let Some(v) = patch.jar_default_ttl_secs {
            self.jar_default_ttl_secs.store(v, Ordering::Relaxed);
        }
        if let Some(v) = patch.jar_fail_streak {
            self.jar_fail_streak.store(v.max(1), Ordering::Relaxed);
        }
        if let Some(v) = patch.flaresolverr_session_ttl_secs {
            self.flaresolverr_session_ttl_secs
                .store(v, Ordering::Relaxed);
        }
        if let Some(v) = patch.idle_shutdown_secs {
            self.idle_shutdown_secs.store(v, Ordering::Relaxed);
        }

        let view = self.view();
        let doc = SettingsDoc {
            dns_servers: view.dns_servers.clone(),
            nav_timeout_ms: view.nav_timeout_ms,
            jar_default_ttl_secs: view.jar_default_ttl_secs,
            jar_fail_streak: view.jar_fail_streak,
            flaresolverr_session_ttl_secs: view.flaresolverr_session_ttl_secs,
            idle_shutdown_secs: view.idle_shutdown_secs,
        };
        if let Err(e) = persist_json(&self.state_path, &doc).await {
            tracing::warn!(error = %e, "settings: failed to persist");
        }
        Ok(view)
    }

    pub fn nav_timeout_ms(&self) -> u64 {
        self.nav_timeout_ms.load(Ordering::Relaxed)
    }
    pub fn jar_default_ttl_secs(&self) -> u64 {
        self.jar_default_ttl_secs.load(Ordering::Relaxed)
    }
    pub fn jar_fail_streak(&self) -> u32 {
        self.jar_fail_streak.load(Ordering::Relaxed)
    }
    pub fn flaresolverr_session_ttl_secs(&self) -> u64 {
        self.flaresolverr_session_ttl_secs.load(Ordering::Relaxed)
    }
    pub fn idle_shutdown_secs(&self) -> u64 {
        self.idle_shutdown_secs.load(Ordering::Relaxed)
    }

    /// Cheap read for [`crate::ssrf::GuardedResolver`] — called on every
    /// outbound DNS resolution.
    pub fn dns_snapshot(&self) -> Arc<ResolvedDns> {
        self.dns.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SettingsConfig {
        SettingsConfig {
            state_path: tempfile::NamedTempFile::new().unwrap().path().to_path_buf(),
        }
    }

    #[test]
    fn defaults_match_todays_config_defaults_except_dns() {
        let s = RuntimeSettings::new(cfg());
        assert_eq!(s.view().dns_servers, vec!["1.1.1.1", "1.0.0.1"]);
        assert_eq!(s.nav_timeout_ms(), 30_000);
        assert_eq!(s.jar_default_ttl_secs(), 2700);
        assert_eq!(s.jar_fail_streak(), 3);
        assert_eq!(s.flaresolverr_session_ttl_secs(), 1800);
        assert_eq!(s.idle_shutdown_secs(), 900);
    }

    #[tokio::test]
    async fn apply_partial_update_only_touches_given_fields() {
        let s = RuntimeSettings::new(cfg());
        s.apply(SettingsPatch {
            nav_timeout_ms: Some(5_000),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(s.nav_timeout_ms(), 5_000);
        assert_eq!(
            s.jar_default_ttl_secs(),
            2700,
            "untouched field keeps its value"
        );
    }

    #[tokio::test]
    async fn apply_rejects_a_non_ip_dns_server_and_changes_nothing() {
        let s = RuntimeSettings::new(cfg());
        let err = s
            .apply(SettingsPatch {
                dns_servers: Some(vec!["dns.example.com".into()]),
                nav_timeout_ms: Some(1),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "bad_request");
        assert_eq!(
            s.view().dns_servers,
            vec!["1.1.1.1", "1.0.0.1"],
            "unchanged"
        );
        assert_eq!(
            s.nav_timeout_ms(),
            30_000,
            "unchanged — validation failed first"
        );
    }

    #[tokio::test]
    async fn apply_empty_dns_servers_means_system_only() {
        let s = RuntimeSettings::new(cfg());
        s.apply(SettingsPatch {
            dns_servers: Some(Vec::new()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(s.view().dns_servers.is_empty());
        assert!(matches!(s.dns_snapshot().backend, DnsBackend::System));
    }

    #[tokio::test]
    async fn apply_valid_dns_servers_builds_a_custom_backend() {
        let s = RuntimeSettings::new(cfg());
        s.apply(SettingsPatch {
            dns_servers: Some(vec!["9.9.9.9".into()]),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(s.view().dns_servers, vec!["9.9.9.9"]);
        assert!(matches!(s.dns_snapshot().backend, DnsBackend::Custom(_)));
    }

    #[tokio::test]
    async fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("settings.json");
        {
            let s = RuntimeSettings::new(SettingsConfig {
                state_path: state_path.clone(),
            });
            s.apply(SettingsPatch {
                jar_fail_streak: Some(7),
                idle_shutdown_secs: Some(60),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let reloaded = RuntimeSettings::new(SettingsConfig { state_path });
        assert_eq!(reloaded.jar_fail_streak(), 7);
        assert_eq!(reloaded.idle_shutdown_secs(), 60);
    }
}
