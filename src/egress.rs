//! Named egress profiles (DESIGN.md §4).
//!
//! A request either names a profile (`"egress": "mullvad"`) or passes a raw
//! `proxy_url` (cobweb back-compat). Both resolve to an [`Egress`]. Named
//! profiles are **fail-closed**: if the proxy is configured but unreachable the
//! request errors — it never silently falls back to `direct`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use url::Url;

use crate::config::Config;
use crate::error::{CobwebError, Result};

/// A resolved exit: a name plus an optional proxy. `proxy == None` means direct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Egress {
    pub name: String,
    pub proxy: Option<Url>,
}

impl Egress {
    pub fn direct() -> Self {
        Self {
            name: "direct".into(),
            proxy: None,
        }
    }

    /// Build from a raw `proxy_url` field (cobweb-compatible path). An empty
    /// string is treated as direct.
    pub fn from_raw_proxy(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(Self::direct());
        }
        let url = Url::parse(raw)
            .map_err(|_| CobwebError::BadRequest(format!("proxy_url is not a valid URL: {raw}")))?;
        Ok(Self {
            name: format!("raw:{raw}"),
            proxy: Some(url),
        })
    }

    pub fn is_direct(&self) -> bool {
        self.proxy.is_none()
    }

    /// Stable key used to name this egress's jar files. A `cf_clearance` is
    /// bound to the exit IP, so during the cobweb drop-in phase — where every
    /// request comes in as a raw `proxy_url` with no profile name (DESIGN.md
    /// §12 Phase 0) — we key on the proxy's `host:port` rather than losing jar
    /// reuse entirely. Named profiles just use their name.
    pub fn jar_key(&self) -> String {
        match &self.proxy {
            None => "direct".to_string(),
            Some(_) if !self.name.starts_with("raw:") => self.name.clone(),
            Some(proxy) => {
                let host = proxy.host_str().unwrap_or("proxy");
                let port = proxy.port_or_known_default().unwrap_or(0);
                format!("proxy-{host}-{port}")
            }
        }
    }
}

/// Cached result of a health check, valid for [`HEALTHCHECK_TTL`].
struct HealthEntry {
    ok: bool,
    checked_at: Instant,
}

const HEALTHCHECK_TTL: Duration = Duration::from_secs(30);

pub struct EgressRegistry {
    profiles: HashMap<String, Egress>,
    /// name -> last health check. `Mutex` because checks are cheap and rare;
    /// no need for an async lock.
    health: Mutex<HashMap<String, HealthEntry>>,
}

impl EgressRegistry {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let mut profiles = HashMap::new();
        for (name, ec) in &cfg.egress {
            let proxy = if ec.proxy.trim().is_empty() {
                None
            } else {
                Some(Url::parse(ec.proxy.trim()).map_err(|_| {
                    CobwebError::Config(format!("egress `{name}`: bad proxy URL {}", ec.proxy))
                })?)
            };
            profiles.insert(
                name.clone(),
                Egress {
                    name: name.clone(),
                    proxy,
                },
            );
        }
        // Guarantee a `direct` profile always exists.
        profiles
            .entry("direct".to_string())
            .or_insert_with(Egress::direct);
        Ok(Self {
            profiles,
            health: Mutex::new(HashMap::new()),
        })
    }

    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.profiles.keys().cloned().collect();
        v.sort();
        v
    }

    /// Resolve `"egress"` and/or `"proxy_url"` request fields to one [`Egress`].
    ///
    /// - both empty  -> `direct`
    /// - `proxy_url` set -> raw proxy (named profile, if any, is ignored — this
    ///   matches how mycelium's current client only ever sends `proxy_url`)
    /// - `egress` set -> the named profile, or [`CobwebError::UnknownEgress`]
    pub fn resolve(
        &self,
        egress: Option<&str>,
        proxy_url: Option<&str>,
    ) -> Result<Cow<'_, Egress>> {
        if let Some(raw) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
            return Ok(Cow::Owned(Egress::from_raw_proxy(raw)?));
        }
        match egress.map(str::trim).filter(|s| !s.is_empty()) {
            None => Ok(Cow::Owned(Egress::direct())),
            Some(name) => self
                .profiles
                .get(name)
                .map(Cow::Borrowed)
                .ok_or_else(|| CobwebError::UnknownEgress(name.to_string())),
        }
    }

    /// Fail-closed gate. `direct` is always up. For a proxied profile we do a
    /// TCP connect to the proxy host:port, cached for [`HEALTHCHECK_TTL`].
    ///
    /// A deeper check (one known-good HTTPS GET through the proxy) is deferred —
    /// see DESIGN.md §14.2 "Egress healthcheck semantics".
    pub async fn ensure_available(&self, e: &Egress) -> Result<()> {
        let Some(proxy) = &e.proxy else {
            return Ok(());
        };

        if let Some(entry) = self.health.lock().unwrap().get(&e.name) {
            if entry.checked_at.elapsed() < HEALTHCHECK_TTL {
                return if entry.ok {
                    Ok(())
                } else {
                    Err(CobwebError::EgressUnavailable {
                        name: e.name.clone(),
                        reason: "proxy unreachable (cached)".into(),
                    })
                };
            }
        }

        let ok = tcp_reachable(proxy).await;
        self.health.lock().unwrap().insert(
            e.name.clone(),
            HealthEntry {
                ok,
                checked_at: Instant::now(),
            },
        );

        if ok {
            Ok(())
        } else {
            Err(CobwebError::EgressUnavailable {
                name: e.name.clone(),
                reason: format!("cannot connect to proxy {proxy}"),
            })
        }
    }
}

/// TCP-connect to a proxy URL's host:port with a short timeout.
async fn tcp_reachable(proxy: &Url) -> bool {
    let Some(host) = proxy.host_str() else {
        return false;
    };
    let port = proxy.port_or_known_default().unwrap_or(1080);
    let addr = format!("{host}:{port}");
    matches!(
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(&addr)
        )
        .await,
        Ok(Ok(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn registry() -> EgressRegistry {
        let cfg = Config::parse(
            r#"
            [egress.direct]
            proxy = ""
            [egress.mullvad]
            proxy = "socks5://127.0.0.1:1080"
            "#,
        )
        .unwrap();
        EgressRegistry::from_config(&cfg).unwrap()
    }

    #[test]
    fn resolves_named_profile() {
        let r = registry();
        let e = r.resolve(Some("mullvad"), None).unwrap();
        assert_eq!(e.name, "mullvad");
        assert!(e.proxy.is_some());
    }

    #[test]
    fn unknown_named_profile_errors() {
        let r = registry();
        let err = r.resolve(Some("nope"), None).unwrap_err();
        assert!(matches!(err, CobwebError::UnknownEgress(_)));
    }

    #[test]
    fn raw_proxy_url_takes_precedence_and_is_backcompat() {
        let r = registry();
        let e = r
            .resolve(Some("mullvad"), Some("socks5://10.0.0.1:9050"))
            .unwrap();
        assert_eq!(e.proxy.as_ref().unwrap().host_str(), Some("10.0.0.1"));
    }

    #[test]
    fn empty_fields_resolve_to_direct() {
        let r = registry();
        let e = r.resolve(None, None).unwrap();
        assert!(e.is_direct());
        let e = r.resolve(Some(""), Some("")).unwrap();
        assert!(e.is_direct());
    }

    #[tokio::test]
    async fn direct_is_always_available() {
        let r = registry();
        r.ensure_available(&Egress::direct()).await.unwrap();
    }

    #[tokio::test]
    async fn unreachable_proxy_fails_closed() {
        let r = registry();
        // 127.0.0.1:1 is reserved/closed; connect fails fast.
        let e = Egress {
            name: "dead".into(),
            proxy: Some(Url::parse("socks5://127.0.0.1:1").unwrap()),
        };
        let err = r.ensure_available(&e).await.unwrap_err();
        assert!(matches!(err, CobwebError::EgressUnavailable { .. }));
    }
}
