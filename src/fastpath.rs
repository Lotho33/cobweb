//! Tier 2 — the fast path (DESIGN.md §2).
//!
//! An impersonated HTTP GET with the jar's cookies attached, sent through the
//! request's egress. If the response carries a stream URL (regex/known-pattern
//! sniff on the player HTML) we're done in ~10 MB and never touch a browser.
//! A Cloudflare challenge or a "needs JS" page escalates.
//!
//! The client is behind the [`FastClient`] trait so `wreq` can be swapped for
//! `impit` without touching the pipeline (DESIGN.md §14.1).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use url::Url;

use crate::egress::Egress;
use crate::error::{CobwebError, Result};
use crate::jar::Cookie;

/// What the pipeline hands the client for one fetch.
pub struct FetchRequest<'a> {
    pub url: &'a Url,
    pub egress: &'a Egress,
    pub user_agent: Option<&'a str>,
    pub accept_language: Option<&'a str>,
    /// Pre-built `Cookie:` header value from the jar (already domain-filtered).
    pub cookie_header: Option<&'a str>,
    /// Impersonation profile id (e.g. `chrome-147`). `None` => client default.
    pub fingerprint: Option<&'a str>,
    pub extra_headers: &'a [(String, String)],
    pub timeout: Duration,
}

pub struct FetchResponse {
    pub status: u16,
    pub final_url: Url,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Parsed from every `Set-Cookie` on the response.
    pub set_cookies: Vec<Cookie>,
}

impl FetchResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[async_trait]
pub trait FastClient: Send + Sync {
    async fn fetch(&self, req: FetchRequest<'_>) -> Result<FetchResponse>;
    /// Identifier for logs / `/health` (`"wreq"`, `"impit"`, `"mock"`).
    fn engine(&self) -> &'static str;
    /// A raw streaming `wreq::Client` for the `/v1/fetch` proxy — shares this
    /// client's per-egress connection pool. Only the real `wreq` engine
    /// implements it.
    fn raw_client(&self, _egress: &Egress) -> Result<wreq::Client> {
        Err(CobwebError::NotImplemented(
            "raw fetch client not available for this fast engine",
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// wreq implementation
// ─────────────────────────────────────────────────────────────────────────────

/// `wreq`-backed client. Holds one `wreq::Client` per `(egress, fingerprint)` —
/// building one sets up a TLS/H2 fingerprint and a proxy connector, both worth
/// reusing across requests.
pub struct WreqClient {
    cache: Mutex<HashMap<String, wreq::Client>>,
}

/// How a cached `wreq::Client` should be tuned.
#[derive(Clone, Copy)]
enum ClientKind {
    /// Buffer-and-sniff fast path (`FastClient::fetch`): caller sets a
    /// per-request total timeout, body capped at 8 MiB.
    FastPath,
    /// Streaming `/v1/fetch` proxy: connect + read-inactivity guards only.
    Stream,
}

impl Default for WreqClient {
    fn default() -> Self {
        Self::new()
    }
}

impl WreqClient {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn emulation_for(_fingerprint: Option<&str>) -> wreq_util::Profile {
        // TODO(M2): map the jar's `fingerprint_id` onto other `wreq_util::Profile`
        // variants (Firefox*, Safari*, Edge*). For now every fast-path request
        // impersonates a current Chrome — the profile the browser tier will pin too.
        wreq_util::Profile::Chrome147
    }

    fn client_for(
        &self,
        egress: &Egress,
        fingerprint: Option<&str>,
        kind: ClientKind,
    ) -> Result<wreq::Client> {
        let kind_tag = match kind {
            ClientKind::FastPath => "fp",
            ClientKind::Stream => "st",
        };
        let key = format!(
            "{}|{}|{kind_tag}",
            egress.jar_key(),
            fingerprint.unwrap_or("default")
        );
        if let Some(c) = self.cache.lock().unwrap().get(&key) {
            return Ok(c.clone());
        }

        let mut builder = wreq::Client::builder()
            .emulation(Self::emulation_for(fingerprint))
            // Keep sockets to the same origin warm across the repeated calls a
            // single resolve makes (player HTML, then the manifest probe).
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(8)
            .tcp_keepalive(Duration::from_secs(60))
            .redirect(wreq::redirect::Policy::limited(10));

        builder = match kind {
            // Fast path: the caller sets a per-request total timeout and the
            // body is hard-capped at 8 MiB, so a client-wide timeout would only
            // get in the way.
            ClientKind::FastPath => builder,
            // Stream: a total timeout truncates a healthy long download; guard
            // the two things that actually indicate a stuck upstream instead.
            ClientKind::Stream => builder
                .connect_timeout(Duration::from_secs(15))
                .read_timeout(Duration::from_secs(60)),
        };

        if let Some(proxy_url) = &egress.proxy {
            let proxy = wreq::Proxy::all(proxy_url.as_str())
                .map_err(|e| CobwebError::Config(format!("bad proxy {proxy_url}: {e}")))?;
            builder = builder.proxy(proxy);
        } else {
            // Named `direct` must never inherit an ambient HTTP(S)_PROXY env.
            builder = builder.no_proxy();
        }

        let client = builder
            .build()
            .map_err(|e| CobwebError::Other(anyhow::anyhow!("build wreq client: {e}")))?;
        self.cache.lock().unwrap().insert(key, client.clone());
        Ok(client)
    }
}

#[async_trait]
impl FastClient for WreqClient {
    fn engine(&self) -> &'static str {
        "wreq"
    }

    /// Streaming client for `/v1/fetch`: no total request timeout (would
    /// truncate a long segment / progressive file mid-stream), just connect +
    /// read-inactivity guards. Shares the per-egress pool with the fast path.
    fn raw_client(&self, egress: &Egress) -> Result<wreq::Client> {
        self.client_for(egress, None, ClientKind::Stream)
    }

    async fn fetch(&self, req: FetchRequest<'_>) -> Result<FetchResponse> {
        let client = self.client_for(req.egress, req.fingerprint, ClientKind::FastPath)?;

        let mut rb = client.get(req.url.as_str()).timeout(req.timeout);
        if let Some(ua) = req.user_agent {
            rb = rb.header("user-agent", ua);
        }
        if let Some(al) = req.accept_language {
            rb = rb.header("accept-language", al);
        }
        if let Some(ch) = req.cookie_header {
            rb = rb.header("cookie", ch);
        }
        for (k, v) in req.extra_headers {
            rb = rb.header(k.as_str(), v.as_str());
        }

        let resp = rb
            .send()
            .await
            .map_err(|e| CobwebError::Upstream(format!("{} {}: {e}", "GET", req.url)))?;

        let status = resp.status().as_u16();
        // wreq's `Response` exposes the final URI (post-redirect) as `uri()`.
        let final_url = Url::parse(&resp.uri().to_string()).unwrap_or_else(|_| req.url.clone());

        let mut headers = Vec::with_capacity(resp.headers().len());
        let mut set_cookies = Vec::new();
        for (name, value) in resp.headers().iter() {
            let v = value.to_str().unwrap_or("").to_string();
            if name.as_str().eq_ignore_ascii_case("set-cookie") {
                if let Some(c) = parse_set_cookie(&v, &final_url) {
                    set_cookies.push(c);
                }
            }
            headers.push((name.as_str().to_string(), v));
        }

        // Bound the body: the fast path only ever wants player HTML / a JSON
        // blob (kilobytes), then runs regexes over the whole thing and may echo
        // it back on /v1/navigate. An unbounded `resp.text()` let a hostile or
        // misconfigured upstream drive memory. Reject a declared oversize
        // Content-Length up front, and hard-cap the streamed read for the
        // chunked / lying case.
        const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
        let content_length = resp.content_length();
        if let Some(len) = content_length {
            if len as usize > MAX_BODY_BYTES {
                return Err(CobwebError::Upstream(format!(
                    "body of {} is {len} bytes, over the {MAX_BODY_BYTES}-byte fast-path cap",
                    req.url
                )));
            }
        }
        let mut stream = resp.bytes_stream();
        let mut buf: Vec<u8> = match content_length {
            Some(len) if (len as usize) <= MAX_BODY_BYTES => Vec::with_capacity(len as usize),
            _ => Vec::new(),
        };
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| CobwebError::Upstream(format!("read body of {}: {e}", req.url)))?;
            if buf.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(CobwebError::Upstream(format!(
                    "body of {} exceeded the {MAX_BODY_BYTES}-byte fast-path cap",
                    req.url
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        // Move the buffer straight into the String when it's valid UTF-8 (the
        // common case: player HTML / JSON) — no second copy.
        let body = match String::from_utf8(buf) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        };

        Ok(FetchResponse {
            status,
            final_url,
            headers,
            body,
            set_cookies,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Set-Cookie parsing (enough for cf_clearance ttl extraction, not RFC-complete)
// ─────────────────────────────────────────────────────────────────────────────

pub fn parse_set_cookie(header: &str, request_url: &Url) -> Option<Cookie> {
    let mut parts = header.split(';');
    let first = parts.next()?.trim();
    let (name, value) = first.split_once('=')?;
    let mut c = Cookie::new(name.trim(), value.trim(), "");
    c.domain = request_url.host_str().unwrap_or_default().to_string();

    let mut max_age: Option<i64> = None;
    for attr in parts {
        let attr = attr.trim();
        let (k, v) = match attr.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
            None => (attr.to_ascii_lowercase(), String::new()),
        };
        match k.as_str() {
            "domain" if !v.is_empty() => c.domain = v.trim_start_matches('.').to_string(),
            "path" if !v.is_empty() => c.path = v,
            "secure" => c.secure = true,
            "httponly" => c.http_only = true,
            "samesite" if !v.is_empty() => c.same_site = Some(v),
            "max-age" => max_age = v.parse().ok(),
            _ => {}
        }
    }

    if let Some(secs) = max_age {
        let now = chrono::Utc::now().timestamp() as f64;
        c.expires = if secs <= 0 { 1.0 } else { now + secs as f64 };
    }
    Some(c)
}

/// `Max-Age` of a named cookie among a batch, as a TTL hint in seconds.
pub fn ttl_hint_from(cookies: &[Cookie], name: &str) -> Option<u64> {
    let now = chrono::Utc::now().timestamp() as f64;
    cookies
        .iter()
        .find(|c| c.name == name && c.expires > now)
        .map(|c| (c.expires - now).max(0.0) as u64)
}

// ─────────────────────────────────────────────────────────────────────────────
// Challenge detection + stream-URL sniffers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    Hls,
    Dash,
    Progressive,
}

impl StreamKind {
    pub fn from_url(u: &Url) -> Option<Self> {
        let path = u.path().to_ascii_lowercase();
        if path.ends_with(".m3u8") {
            Some(Self::Hls)
        } else if path.ends_with(".mpd") {
            Some(Self::Dash)
        } else if path.ends_with(".mp4") || path.ends_with(".webm") {
            Some(Self::Progressive)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct StreamHit {
    pub url: Url,
    pub kind: StreamKind,
}

/// True if `body` (or a challenge status) looks like a Cloudflare interstitial.
pub fn looks_like_cloudflare_challenge(
    status: u16,
    body: &str,
    server_header: Option<&str>,
) -> bool {
    let cf_server = server_header
        .map(|s| s.to_ascii_lowercase().contains("cloudflare"))
        .unwrap_or(false);
    let markers = [
        "just a moment",
        "cf-browser-verification",
        "cf_chl_opt",
        "_cf_chl_",
        "challenge-platform",
        "turnstile",
        "/cdn-cgi/challenge-platform/",
    ];
    // The interstitial markers are always in the document head (title + first
    // scripts); a real challenge page is a few KB. Cap the scan+lowercase alloc
    // instead of copying a body that can be up to MAX_BODY_BYTES.
    let mut end = body.len().min(64 * 1024);
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let lc = body[..end].to_ascii_lowercase();
    let has_marker = markers.iter().any(|m| lc.contains(m));
    has_marker || ((status == 403 || status == 503) && cf_server && lc.contains("challenge"))
}

/// Look for an HLS/DASH URL in a player page. Ordered: explicit player-config
/// keys first (least likely to be a decoy), then any bare `*.m3u8`/`*.mpd`.
pub fn sniff_stream_url(body: &str, base: &Url) -> Option<StreamHit> {
    use once_cell_regex::*;

    for re in [KEYED_SOURCE.get(), BARE_MANIFEST.get()] {
        for caps in re.captures_iter(body) {
            let raw = caps
                .name("u")
                .or_else(|| caps.get(1))
                .map(|m| m.as_str())
                .unwrap_or_default()
                .trim()
                .trim_matches(|c| c == '"' || c == '\'' || c == '\\');
            if raw.is_empty() {
                continue;
            }
            // Unescape the two things that actually show up in inlined JSON/JS.
            let cleaned = raw
                .replace("\\/", "/")
                .replace("\\u002F", "/")
                .replace("\\u002f", "/");
            let Ok(resolved) = base.join(&cleaned) else {
                continue;
            };
            if let Some(kind) = StreamKind::from_url(&resolved) {
                return Some(StreamHit {
                    url: resolved,
                    kind,
                });
            }
        }
    }
    None
}

/// Tiny lazily-compiled regex holder so we don't pull `once_cell`/`lazy_static`
/// just for this. `OnceLock` is in std.
mod once_cell_regex {
    use regex::Regex;
    use std::sync::OnceLock;

    pub struct LazyRe(OnceLock<Regex>, &'static str);
    impl LazyRe {
        pub const fn new(pat: &'static str) -> Self {
            Self(OnceLock::new(), pat)
        }
        pub fn get(&self) -> &Regex {
            self.0
                .get_or_init(|| Regex::new(self.1).expect("static regex"))
        }
    }

    /// `"file": "....m3u8..."`, `source: '...mpd...'`, `hls: "..."`, `src="..."`.
    pub static KEYED_SOURCE: LazyRe = LazyRe::new(
        r#"(?i)(?:"?(?:file|source|src|hls|dash|url|playlist|manifest)"?\s*[:=]\s*)["'](?P<u>[^"'<>\s]+?\.(?:m3u8|mpd)(?:\?[^"'<>\s]*)?)["']"#,
    );

    /// Any bare occurrence of an absolute or root-relative manifest URL.
    pub static BARE_MANIFEST: LazyRe =
        LazyRe::new(r#"(?i)((?:https?:)?/{1,2}[^"'<>\s\\]+?\.(?:m3u8|mpd)(?:\?[^"'<>\s\\]*)?)"#);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://example.com/embed/movie/123").unwrap()
    }

    #[test]
    fn sniffs_keyed_player_config() {
        let html = r#"<script>var player = {"file":"https://cdn.example.com/hls/master.m3u8?token=abc","type":"hls"};</script>"#;
        let hit = sniff_stream_url(html, &base()).unwrap();
        assert_eq!(hit.kind, StreamKind::Hls);
        assert_eq!(
            hit.url.as_str(),
            "https://cdn.example.com/hls/master.m3u8?token=abc"
        );
    }

    #[test]
    fn sniffs_escaped_json_slashes() {
        let html = r#"{"sources":[{"src":"https:\/\/x.example\/v\/out.m3u8"}]}"#;
        let hit = sniff_stream_url(html, &base()).unwrap();
        assert_eq!(hit.url.as_str(), "https://x.example/v/out.m3u8");
    }

    #[test]
    fn sniffs_root_relative_manifest() {
        let html = r#"<video-js data-setup='{"sources":[{"src":"/live/stream.mpd"}]}'></video-js>"#;
        let hit = sniff_stream_url(html, &base()).unwrap();
        assert_eq!(hit.kind, StreamKind::Dash);
        assert_eq!(hit.url.as_str(), "https://example.com/live/stream.mpd");
    }

    #[test]
    fn no_false_positive_on_plain_html() {
        let html = "<html><body>nothing to see, watch.mp4x not a stream</body></html>";
        assert!(sniff_stream_url(html, &base()).is_none());
    }

    #[test]
    fn detects_cloudflare_interstitial() {
        assert!(looks_like_cloudflare_challenge(
            403,
            "<title>Just a moment...</title><div class=\"cf-browser-verification\">",
            Some("cloudflare")
        ));
        assert!(!looks_like_cloudflare_challenge(
            200,
            "<html>normal page</html>",
            Some("nginx")
        ));
    }

    #[test]
    fn parses_set_cookie_with_max_age() {
        let url = Url::parse("https://example.com/").unwrap();
        let c = parse_set_cookie(
            "cf_clearance=abcdef; path=/; domain=.example.com; Max-Age=2700; Secure; HttpOnly; SameSite=None",
            &url,
        )
        .unwrap();
        assert_eq!(c.name, "cf_clearance");
        assert_eq!(c.domain, "example.com");
        assert!(c.secure && c.http_only);
        let ttl = ttl_hint_from(&[c], "cf_clearance").unwrap();
        assert!((2600..=2700).contains(&ttl));
    }
}
