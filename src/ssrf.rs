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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

use crate::error::{CobwebError, Result};

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
    if let Ok(ip) = host.parse::<IpAddr>() {
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

fn blocked(host: &str, reason: &str) -> CobwebError {
    CobwebError::Blocked(format!(
        "refusing to fetch `{host}`: resolves to a {reason} address"
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// wreq DNS resolver
// ─────────────────────────────────────────────────────────────────────────────

/// A `wreq` DNS resolver that runs [`block_reason`] over every resolved address.
/// Installed on the fast-path clients so the SSRF check is re-applied on each
/// redirect hop (`wreq` calls the resolver again for every new connection).
#[derive(Clone)]
pub struct GuardedResolver {
    inner: wreq::dns::GaiResolver,
    allow_private: bool,
}

impl GuardedResolver {
    pub fn new(allow_private: bool) -> Self {
        Self {
            inner: wreq::dns::GaiResolver::new(),
            allow_private,
        }
    }
}

impl wreq::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let inner = self.inner.clone();
        let allow_private = self.allow_private;
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addrs = wreq::dns::Resolve::resolve(&inner, name).await?;
            let vetted: Vec<std::net::SocketAddr> = addrs.collect();
            for sa in &vetted {
                if let Some(reason) = block_reason(sa.ip(), allow_private) {
                    return Err(
                        format!("ssrf: refusing `{host}`: resolves to a {reason} address").into(),
                    );
                }
            }
            Ok(Box::new(vetted.into_iter()) as wreq::dns::Addrs)
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

    #[tokio::test]
    async fn guard_url_rejects_non_http_schemes() {
        let u = Url::parse("file:///etc/passwd").unwrap();
        assert!(matches!(
            guard_url(&u, true, true).await,
            Err(CobwebError::Blocked(_))
        ));
    }
}
