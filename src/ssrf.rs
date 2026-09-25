//! SSRF guard.
//!
//! Every request cobweb makes on a caller's behalf goes through here first: the
//! target host is resolved and any address that is not globally routable —
//! loopback, RFC1918, link-local (incl. the `169.254.169.254` cloud-metadata
//! endpoint), CGNAT, IPv6 ULA, and friends — is refused. On the fast path the
//! same check is installed as the `wreq` DNS resolver ([`GuardedResolver`]), so
//! it re-runs on every redirect hop as well.
//!
//! Two tiers of "bad":
//!   * **hard-blocked** — `0.0.0.0` / `::`, `169.254.169.254`, multicast,
//!     broadcast, documentation, benchmarking, reserved. Never a legitimate
//!     scrape target; refused regardless of config.
//!   * **private** — loopback, RFC1918, the rest of link-local, CGNAT, ULA.
//!     Refused unless `[server].allow_private_targets = true` (for operators
//!     who deliberately point cobweb at their own LAN).
//!
//! Only meaningful for the `direct` egress: a proxied egress resolves at the
//! proxy and the operator owns that exit. Callers still run the literal-IP part
//! unconditionally so an obviously bogus target is rejected either way.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use url::Url;

use crate::error::{CobwebError, Result};
use crate::settings::{DnsBackend, RuntimeSettings};

/// Always-refused addresses. `None` = not in this tier.
fn ipv4_hard_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if ip.is_unspecified() {
        return Some("unspecified (0.0.0.0)");
    }
    // 0.0.0.0/8 "this network" — not globally routable.
    if o[0] == 0 {
        return Some("this-network (0.0.0.0/8)");
    }
    if o == [169, 254, 169, 254] {
        return Some("cloud metadata (169.254.169.254)");
    }
    if ip.is_broadcast() {
        return Some("broadcast");
    }
    if ip.is_documentation() {
        return Some("documentation");
    }
    if ip.is_multicast() {
        return Some("multicast");
    }
    // 192.0.0.0/24 IETF protocol assignments.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Some("IETF protocol assignments (192.0.0.0/24)");
    }
    // 198.18.0.0/15 benchmarking.
    if o[0] == 198 && (o[1] & 0xfe) == 18 {
        return Some("benchmarking (198.18.0.0/15)");
    }
    // 240.0.0.0/4 reserved (255.255.255.255 is caught by is_broadcast above).
    if o[0] >= 240 {
        return Some("reserved (240.0.0.0/4)");
    }
    None
}

/// Refused unless `allow_private_targets`. `None` = not in this tier.
fn ipv4_private_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if ip.is_loopback() {
        return Some("loopback (127.0.0.0/8)");
    }
    if ip.is_private() {
        return Some("private (RFC1918)");
    }
    if ip.is_link_local() {
        return Some("link-local (169.254.0.0/16)");
    }
    // 100.64.0.0/10 carrier-grade NAT.
    if o[0] == 100 && (o[1] & 0xc0) == 64 {
        return Some("carrier-grade NAT (100.64.0.0/10)");
    }
    None
}

fn ipv6_hard_reason(ip: Ipv6Addr) -> Option<&'static str> {
    if ip.is_unspecified() {
        return Some("unspecified (::)");
    }
    if ip.is_multicast() {
        return Some("multicast");
    }
    let s = ip.segments();
    // 2001:db8::/32 documentation.
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return Some("documentation (2001:db8::/32)");
    }
    None
}

fn ipv6_private_reason(ip: Ipv6Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("loopback (::1)");
    }
    let s = ip.segments();
    // fc00::/7 unique local.
    if (s[0] & 0xfe00) == 0xfc00 {
        return Some("unique-local (fc00::/7)");
    }
    // fe80::/10 link-local.
    if (s[0] & 0xffc0) == 0xfe80 {
        return Some("link-local (fe80::/10)");
    }
    None
}

/// Classify an IP. Returns `(reason, hard)` when the address should be refused:
/// `hard = true` means "refuse even with `allow_private_targets`".
fn classify(ip: IpAddr) -> Option<(&'static str, bool)> {
    match ip {
        IpAddr::V4(v4) => ipv4_hard_reason(v4)
            .map(|r| (r, true))
            .or_else(|| ipv4_private_reason(v4).map(|r| (r, false))),
        IpAddr::V6(v6) => {
            // An IPv4-mapped / -compatible v6 address is really a v4 target.
            if let Some(v4) = v6.to_ipv4_mapped().or_else(|| embedded_v4(v6)) {
                return classify(IpAddr::V4(v4));
            }
            ipv6_hard_reason(v6)
                .map(|r| (r, true))
                .or_else(|| ipv6_private_reason(v6).map(|r| (r, false)))
        }
    }
}

/// The v4 address embedded in `::ffff:a.b.c.d`, `::a.b.c.d`, or the NAT64
/// well-known prefix `64:ff9b::/96`. `None` for a genuine v6 address.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    // 64:ff9b::/96 (RFC 6052).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        ));
    }
    // ::a.b.c.d (deprecated IPv4-compatible) — top 96 bits zero, not ::/::1.
    if s[0] == 0
        && s[1] == 0
        && s[2] == 0
        && s[3] == 0
        && s[4] == 0
        && s[5] == 0
        && (s[6] != 0 || s[7] > 1)
    {
        return Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        ));
    }
    None
}

/// `Some(reason)` if this address must be refused given `allow_private`.
pub fn block_reason(ip: IpAddr, allow_private: bool) -> Option<&'static str> {
    match classify(ip) {
        Some((reason, true)) => Some(reason),
        Some((reason, false)) if !allow_private => Some(reason),
        _ => None,
    }
}

/// Guard a target URL before fetching it.
///
/// * `is_direct` — whether the chosen egress is `direct`. DNS resolution is only
///   checked for direct egress; a proxied egress resolves at the proxy.
/// * `allow_private` — `[server].allow_private_targets`.
///
/// Always enforced (any egress): the scheme must be http/https, and a literal
/// non-global IP or `localhost` in the URL is refused.
pub async fn guard_url(url: &Url, is_direct: bool, allow_private: bool) -> Result<()> {
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(CobwebError::Blocked(format!(
                "unsupported URL scheme `{other}` (only http/https)"
            )))
        }
    }

    let host = url
        .host_str()
        .ok_or_else(|| CobwebError::BadRequest(format!("URL has no host: {url}")))?;

    let lower = host.to_ascii_lowercase();
    if !allow_private && (lower == "localhost" || lower.ends_with(".localhost")) {
        return Err(CobwebError::Blocked(format!(
            "refusing to fetch `{host}`: localhost"
        )));
    }

    // A literal IP in the URL: classify without touching DNS, on every egress.
    if let Ok(ip) = strip_brackets(host).parse::<IpAddr>() {
        if let Some(reason) = block_reason(ip, allow_private) {
            return Err(blocked(host, reason));
        }
        return Ok(());
    }

    if !is_direct {
        return Ok(());
    }

    // Hostname on the direct egress: resolve and classify every A/AAAA. Reject
    // if *any* is non-global — a name that straddles public and private space
    // is a DNS-rebinding lure.
    //
    // A resolution *failure* is not treated as "blocked" here: the fetch can't
    // reach the host either, and on the fast path [`GuardedResolver`] re-checks
    // at connect time anyway. Only an address that actually resolves and is
    // non-global is refused.
    let port = url.port_or_known_default().unwrap_or(0);
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            for sa in addrs {
                if let Some(reason) = block_reason(sa.ip(), allow_private) {
                    return Err(blocked(host, reason));
                }
            }
        }
        Err(e) => tracing::debug!(%host, error = %e, "ssrf guard: could not resolve target"),
    }
    Ok(())
}

/// `url::Url::host_str()` includes the surrounding brackets for an IPv6
/// literal host (`"http://[::1]/"` → `"[::1]"`, matching how it must appear
/// when the URL is re-serialised) — but `std::net::IpAddr::from_str` rejects
/// brackets outright, so a bare `host.parse::<IpAddr>()` silently fails (and
/// falls through to the "not a literal IP" path) for exactly the URLs an
/// attacker would use to smuggle a bracketed IPv6 loopback/private/metadata
/// address past the literal-IP check below. Strip them first.
pub(crate) fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

fn blocked(host: &str, reason: &str) -> CobwebError {
    CobwebError::Blocked(format!(
        "refusing to fetch `{host}`: resolves to a {reason} address"
    ))
}

/// Vet the proxy host of a caller-supplied egress before using it.
///
/// [`guard_url`] only ever looks at the *target* URL; when the chosen egress
/// carries a proxy, everything actually rides through the proxy's host:port
/// instead — including [`crate::egress::EgressRegistry::ensure_available`]'s
/// own TCP-connect health check, which runs *before* any other guard and would
/// otherwise double as a blind port-scan oracle against whatever host a caller
/// names in `proxy_url`. A `[egress.*]` profile from the config file is
/// operator-configured and trusted (the operator owns that exit, same as
/// `guard_url`'s treatment of a *target* reached through a proxied egress);
/// only a raw `proxy_url` supplied on the request itself — tagged
/// `"raw:<url>"` by [`crate::egress::Egress::from_raw_proxy`] — is untrusted
/// input and needs this check.
pub async fn guard_egress(egress: &crate::egress::Egress, allow_private: bool) -> Result<()> {
    if !egress.name.starts_with("raw:") {
        return Ok(()); // operator-configured profile: trusted, operator owns the exit
    }
    let Some(proxy) = &egress.proxy else {
        return Ok(());
    };
    let Some(host) = proxy.host_str() else {
        return Err(CobwebError::BadRequest("proxy_url has no host".into()));
    };

    let lower = host.to_ascii_lowercase();
    if !allow_private && (lower == "localhost" || lower.ends_with(".localhost")) {
        return Err(blocked(host, "localhost"));
    }

    if let Ok(ip) = strip_brackets(host).parse::<IpAddr>() {
        if let Some(reason) = block_reason(ip, allow_private) {
            return Err(blocked(host, reason));
        }
        return Ok(());
    }

    // A hostname proxy: resolve and vet every address, same rationale as
    // `guard_url`'s direct-egress branch — a resolution failure is not itself
    // "blocked" (the connect that follows can't reach it either).
    let port = proxy.port_or_known_default().unwrap_or(0);
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            for sa in addrs {
                if let Some(reason) = block_reason(sa.ip(), allow_private) {
                    return Err(blocked(host, reason));
                }
            }
        }
        Err(e) => {
            tracing::debug!(%host, error = %e, "ssrf guard: could not resolve proxy_url host")
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// wreq redirect policy
// ─────────────────────────────────────────────────────────────────────────────

/// Max redirect hops a `wreq` client follows (same as `Policy::limited(10)`).
pub const MAX_REDIRECTS: usize = 10;

/// Why a redirect to `host` must be refused, if it must. Covers exactly the
/// case [`GuardedResolver`] can't: an **IP-literal** host, for which `wreq`
/// never calls the DNS resolver — without this, a public page answering
/// `302 Location: http://192.168.1.1/…` (or `169.254.169.254`) sailed past the
/// SSRF guard, since [`guard_url`] only vets the entry-point URL. Hostnames
/// are left to the resolver (it re-runs on every hop). Same rule as
/// [`guard_url`]: literals are vetted on ANY egress (a proxy would happily
/// reach its own LAN), `localhost` names are refused unless relaxed.
pub fn redirect_block_reason(host: &str, allow_private: bool) -> Option<&'static str> {
    let bare = strip_brackets(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return block_reason(ip, allow_private);
    }
    let lower = bare.to_ascii_lowercase();
    if !allow_private && (lower == "localhost" || lower.ends_with(".localhost")) {
        return Some("loopback (localhost)");
    }
    None
}

/// The redirect policy every `wreq` client in cobweb uses: at most
/// [`MAX_REDIRECTS`] hops, each hop's host vetted by [`redirect_block_reason`].
pub fn redirect_policy(allow_private: bool) -> wreq::redirect::Policy {
    wreq::redirect::Policy::custom(move |attempt| {
        // `previous` includes the initial request, which is not a redirect.
        if attempt.previous.len() > MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let host = attempt.uri.host().unwrap_or("").to_string();
        match redirect_block_reason(&host, allow_private) {
            Some(reason) => attempt.error(format!(
                "ssrf: refusing redirect to `{host}`: {reason} address"
            )),
            None => attempt.follow(),
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// wreq DNS resolver
// ─────────────────────────────────────────────────────────────────────────────

/// A `wreq` DNS resolver that runs [`block_reason`] over every resolved
/// address. Installed on the fast-path clients so the SSRF check is
/// re-applied on each redirect hop (`wreq` calls the resolver again for every
/// new connection) *and* against whatever `[settings].dns_servers`
/// (`src/settings.rs`) currently point at, live.
#[derive(Clone)]
pub struct GuardedResolver {
    settings: Arc<RuntimeSettings>,
    allow_private: bool,
}

impl GuardedResolver {
    pub fn new(allow_private: bool, settings: Arc<RuntimeSettings>) -> Self {
        Self {
            settings,
            allow_private,
        }
    }
}

/// Resolve via the system resolver — `DnsBackend::System`'s own path, and
/// `DnsBackend::Custom`'s fallback when the configured server(s) can't
/// answer (see [`GuardedResolver::resolve`]).
async fn gai_resolve(name: wreq::dns::Name) -> Result<Vec<SocketAddr>, tower::BoxError> {
    use wreq::dns::Resolve;
    let gai = wreq::dns::GaiResolver::new();
    Ok(gai.resolve(name).await?.collect())
}

impl wreq::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let dns = self.settings.dns_snapshot();
        let allow_private = self.allow_private;
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addrs: Vec<SocketAddr> = match &dns.backend {
                DnsBackend::Custom(resolver) => match resolver.lookup_ip(name.as_str()).await {
                    Ok(lookup) => lookup.iter().map(|ip| SocketAddr::new(ip, 0)).collect(),
                    Err(e) => {
                        // Covers a proxy/Docker-Compose-internal hostname the
                        // configured server(s) will never know about (see
                        // `src/settings.rs`'s module doc) as well as a
                        // genuinely unreachable/misconfigured DNS server.
                        tracing::debug!(
                            %host, error = %e,
                            "custom DNS server(s) failed to resolve, falling back to system resolver"
                        );
                        gai_resolve(name.clone()).await?
                    }
                },
                DnsBackend::System => gai_resolve(name.clone()).await?,
            };
            for sa in &addrs {
                if let Some(reason) = block_reason(sa.ip(), allow_private) {
                    return Err(
                        format!("ssrf: refusing `{host}`: resolves to a {reason} address").into(),
                    );
                }
            }
            Ok(Box::new(addrs.into_iter()) as wreq::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_the_usual_private_and_meta_ranges() {
        for s in [
            "127.0.0.1",
            "127.10.20.30",
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.1.2",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1", // NAT64-wrapped 127.0.0.1
        ] {
            assert!(
                block_reason(ip(s), false).is_some(),
                "{s} should be blocked"
            );
        }
    }

    #[test]
    fn allow_private_still_blocks_hard_ranges() {
        // relaxed: ordinary private space is now allowed …
        assert!(block_reason(ip("10.0.0.1"), true).is_none());
        assert!(block_reason(ip("127.0.0.1"), true).is_none());
        assert!(block_reason(ip("fd00::1"), true).is_none());
        // … but the metadata IP and bogus ranges never are.
        assert!(block_reason(ip("169.254.169.254"), true).is_some());
        assert!(block_reason(ip("0.0.0.0"), true).is_some());
        assert!(block_reason(ip("255.255.255.255"), true).is_some());
        assert!(block_reason(ip("224.0.0.1"), true).is_some());
    }

    #[test]
    fn passes_public_addresses() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(block_reason(ip(s), false).is_none(), "{s} should pass");
        }
    }

    #[tokio::test]
    async fn guard_url_rejects_literals_on_any_egress() {
        let u = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        // even a proxied egress (is_direct = false) rejects the metadata literal
        assert!(guard_url(&u, false, false).await.is_err());
        assert!(guard_url(&u, false, true).await.is_err());

        let lo = Url::parse("http://127.0.0.1:8096/x").unwrap();
        assert!(guard_url(&lo, true, false).await.is_err());
        assert!(guard_url(&lo, true, true).await.is_ok());
    }

    // Regression: `Url::host_str()` keeps the brackets for an IPv6 literal
    // (`"[::1]"`), and `IpAddr::from_str` rejects a bracketed string outright
    // — a bare `host.parse::<IpAddr>()` therefore missed the literal-IP branch
    // entirely for a bracketed IPv6 target, on both `guard_url` and
    // `guard_egress`, letting it fall through as if it weren't a literal IP at
    // all. Found via the `strip_brackets` fix, not by inspection — worth its
    // own guard against a future refactor reintroducing a bare `.parse()`.
    #[tokio::test]
    async fn guard_url_rejects_bracketed_ipv6_literals() {
        for s in [
            "http://[::1]/",
            "http://[::1]:8080/x",
            "http://[fd00::1]/",
            "http://[fe80::1]/",
        ] {
            let u = Url::parse(s).unwrap();
            assert!(guard_url(&u, true, false).await.is_err(), "{s} on direct");
            assert!(guard_url(&u, false, false).await.is_err(), "{s} on proxied");
        }
        // relaxed: ordinary private IPv6 passes, same as its IPv4 counterpart
        let u = Url::parse("http://[fd00::1]/").unwrap();
        assert!(guard_url(&u, true, true).await.is_ok());
    }

    #[tokio::test]
    async fn guard_url_rejects_non_http_schemes() {
        let u = Url::parse("file:///etc/passwd").unwrap();
        assert!(matches!(
            guard_url(&u, true, true).await,
            Err(CobwebError::Blocked(_))
        ));
    }

    fn raw_egress(url: &str) -> crate::egress::Egress {
        crate::egress::Egress::from_raw_proxy(url).unwrap()
    }

    fn named_egress(name: &str, url: &str) -> crate::egress::Egress {
        crate::egress::Egress {
            name: name.to_string(),
            proxy: Some(Url::parse(url).unwrap()),
        }
    }

    #[tokio::test]
    async fn guard_egress_blocks_a_raw_proxy_url_pointing_at_a_private_host() {
        // e.g. `proxy_url: "http://127.0.0.1:2375/"` (a Docker socket proxy, an
        // internal admin panel, ...) — this must never reach ensure_available's
        // TCP-connect probe, let alone the actual request.
        for url in [
            "http://127.0.0.1:2375/",
            "http://10.0.0.5:6379",
            "http://169.254.169.254/",
            "socks5://[::1]:1080",
        ] {
            let e = raw_egress(url);
            assert!(
                guard_egress(&e, false).await.is_err(),
                "{url} should be blocked"
            );
        }
    }

    #[tokio::test]
    async fn guard_egress_allows_a_raw_proxy_url_pointing_at_a_public_host() {
        // NOT 203.0.113.0/24 / 192.0.2.0/24 / 198.51.100.0/24 — those are the
        // RFC 5737 TEST-NET ranges, which `Ipv4Addr::is_documentation()` (and
        // so `block_reason`) correctly treats as always-blocked, not "public".
        let e = raw_egress("socks5://93.184.216.34:1080");
        assert!(guard_egress(&e, false).await.is_ok());
    }

    #[tokio::test]
    async fn guard_egress_trusts_a_named_config_profile_even_if_private() {
        // A `[egress.*]` profile is operator-configured (e.g. a WireGuard
        // sidecar reachable only at a private container IP) — never subject to
        // this check, unlike a raw `proxy_url` from a request.
        let e = named_egress("mullvad", "socks5://10.0.0.9:1080");
        assert!(guard_egress(&e, false).await.is_ok());
    }

    #[tokio::test]
    async fn guard_egress_allows_direct() {
        assert!(guard_egress(&crate::egress::Egress::direct(), false)
            .await
            .is_ok());
    }

    // `guard_url` only ever vets the *entry-point* URL of a request; the
    // property that a *redirect* hop is also vetted (DESIGN.md §6.3: "the same
    // predicate is the wreq DNS resolver... so it re-runs on every redirect
    // hop") lives entirely in `GuardedResolver`, since `wreq` calls its
    // installed resolver again for every new connection a redirect causes —
    // identically to the first one. There is no separate "redirect guard" to
    // test end-to-end (and no hermetic way to make a test server look like a
    // "public" host that then redirects to a "private" one without reaching
    // the real network); testing that this resolver refuses to resolve a
    // private/loopback name is a faithful, direct test of the exact mechanism
    // a redirect hop goes through.
    /// System-only DNS settings (`dns_servers = []`) so this module's tests
    /// never depend on live network access to a real resolver.
    async fn system_only_settings() -> Arc<RuntimeSettings> {
        let settings = Arc::new(RuntimeSettings::new(crate::config::SettingsConfig {
            state_path: tempfile::NamedTempFile::new().unwrap().path().to_path_buf(),
        }));
        settings
            .apply(crate::settings::SettingsPatch {
                dns_servers: Some(Vec::new()),
                ..Default::default()
            })
            .await
            .unwrap();
        settings
    }

    // The resolver never runs for an IP-literal host, so redirect hops to a
    // literal are vetted by `redirect_block_reason` instead (redirect_policy).
    #[test]
    fn redirect_block_reason_vets_literals_and_localhost() {
        // strict
        for h in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "169.254.169.254",
            "[::1]",
            "[fd00::1]",
            "localhost",
            "a.localhost",
        ] {
            assert!(
                redirect_block_reason(h, false).is_some(),
                "{h} must be refused"
            );
        }
        for h in ["93.184.216.34", "example.com", "cdn.example.org"] {
            assert!(
                redirect_block_reason(h, false).is_none(),
                "{h} must be allowed"
            );
        }
        // relaxed: private ok, hard ranges still refused
        assert!(redirect_block_reason("192.168.1.1", true).is_none());
        assert!(redirect_block_reason("localhost", true).is_none());
        assert!(redirect_block_reason("169.254.169.254", true).is_some());
        assert!(redirect_block_reason("0.0.0.0", true).is_some());
    }

    #[tokio::test]
    async fn guarded_resolver_blocks_localhost_and_allows_it_when_relaxed() {
        use wreq::dns::{Name, Resolve};

        let settings = system_only_settings().await;
        let strict = GuardedResolver::new(false, settings.clone());
        assert!(
            Resolve::resolve(&strict, Name::from("localhost"))
                .await
                .is_err(),
            "a resolution landing on loopback must be refused when allow_private is false"
        );

        let relaxed = GuardedResolver::new(true, settings);
        assert!(
            Resolve::resolve(&relaxed, Name::from("localhost"))
                .await
                .is_ok(),
            "allow_private_targets = true must let a loopback resolution through"
        );
    }

    // Proves the fallback this whole design exists for (see `src/settings.rs`'s
    // module doc): a custom DNS server that can't answer must not break
    // resolution of a name only the system resolver knows about (in
    // production, a proxy/Docker-Compose-internal hostname; here,
    // `localhost`, resolved hermetically via loopback so this test needs no
    // outbound network access).
    #[tokio::test]
    async fn guarded_resolver_falls_back_to_system_dns_when_the_custom_server_is_unreachable() {
        use wreq::dns::{Name, Resolve};

        let settings = Arc::new(RuntimeSettings::new(crate::config::SettingsConfig {
            state_path: tempfile::NamedTempFile::new().unwrap().path().to_path_buf(),
        }));
        // Nothing listens on UDP/53 at loopback in the test sandbox, so this
        // fails fast (ICMP port-unreachable, in-kernel) rather than timing
        // out against a routable-but-black-holed address.
        settings
            .apply(crate::settings::SettingsPatch {
                dns_servers: Some(vec!["127.0.0.1".to_string()]),
                ..Default::default()
            })
            .await
            .unwrap();

        let resolver = GuardedResolver::new(true, settings);
        assert!(
            Resolve::resolve(&resolver, Name::from("localhost"))
                .await
                .is_ok(),
            "must fall back to the system resolver when the custom DNS server is unreachable"
        );
    }
}
