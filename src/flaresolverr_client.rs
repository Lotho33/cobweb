//! Outbound delegate to an external FlareSolverr (DESIGN.md §11, tier 3b).
//! `#[cfg(feature = "flaresolverr")]`.

use std::time::Duration;

use serde_json::{json, Value};
use url::Url;

use crate::error::{CobwebError, Result};
use crate::jar::Cookie;

pub struct FlaresolverrClient {
    endpoint: String,
    http: wreq::Client,
}

#[derive(Debug, Default)]
pub struct FsSolution {
    pub cookies: Vec<Cookie>,
    pub user_agent: String,
    pub html: String,
    pub status: u16,
}

impl FlaresolverrClient {
    pub fn new(endpoint: &str) -> Result<Self> {
        let http = wreq::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|e| CobwebError::Config(format!("flaresolverr client: {e}")))?;
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// `request.get` the URL through the external FlareSolverr; hand back its
    /// cookies + userAgent so cobweb's jar can ride them.
    pub async fn solve(
        &self,
        url: &Url,
        proxy: Option<&Url>,
        max_timeout: Duration,
    ) -> Result<FsSolution> {
        let mut body = json!({
            "cmd": "request.get",
            "url": url.as_str(),
            "maxTimeout": max_timeout.as_millis().min(180_000) as u64,
        });
        let mut req = self.http.post(format!("{}/v1", self.endpoint));
        if let Some(p) = proxy {
            let p = &delegate_proxy(p);
            body["proxy"] = json!({ "url": p.as_str() });
            // Byparr ignores the body `proxy` and reads these headers instead.
            // The cf_clearance it earns is bound to the egress IP, so it must
            // solve through the same exit the request will ride.
            for (name, value) in byparr_proxy_headers(p) {
                req = req.header(name, value);
            }
        }

        let resp = req
            .json(&body)
            .send()
            .await
            .map_err(|e| CobwebError::Upstream(format!("flaresolverr POST: {e}")))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| CobwebError::Upstream(format!("flaresolverr body: {e}")))?;

        if v.get("status").and_then(Value::as_str) != Some("ok") {
            let msg = v
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            return Err(CobwebError::Browser(format!("flaresolverr: {msg}")));
        }
        let sol = v
            .get("solution")
            .ok_or_else(|| CobwebError::Upstream("flaresolverr: no solution".into()))?;

        let cookies = sol
            .get("cookies")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(fs_cookie).collect())
            .unwrap_or_default();

        Ok(FsSolution {
            cookies,
            user_agent: sol
                .get("userAgent")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            html: sol
                .get("response")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            status: sol.get("status").and_then(Value::as_u64).unwrap_or(0) as u16,
        })
    }
}

/// The egress proxy as the delegate's browser understands it: Chromium (and
/// Camoufox) know no `socks5h`/`socks4a` and resolve at a SOCKS5 proxy anyway.
fn delegate_proxy(p: &Url) -> Url {
    let scheme = match p.scheme() {
        "socks5h" => "socks5",
        "socks4a" => "socks4",
        _ => return p.clone(),
    };
    let mut out = p.clone();
    let _ = out.set_scheme(scheme);
    out
}

/// `X-Proxy-Server` (`scheme://host:port`, no credentials) plus
/// `X-Proxy-Username`/`X-Proxy-Password` when the proxy URL carries them.
fn byparr_proxy_headers(p: &Url) -> Vec<(&'static str, String)> {
    let mut server = format!("{}://{}", p.scheme(), p.host_str().unwrap_or_default());
    if let Some(port) = p.port() {
        server.push_str(&format!(":{port}"));
    }
    let mut out = vec![("X-Proxy-Server", server)];
    if !p.username().is_empty() {
        out.push(("X-Proxy-Username", percent_decode(p.username())));
        out.push((
            "X-Proxy-Password",
            percent_decode(p.password().unwrap_or_default()),
        ));
    }
    out
}

/// Url keeps userinfo percent-encoded; Byparr wants it raw.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn fs_cookie(v: &Value) -> Option<Cookie> {
    Some(Cookie {
        name: v.get("name")?.as_str()?.to_string(),
        value: v.get("value")?.as_str()?.to_string(),
        domain: v
            .get("domain")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        path: v
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string(),
        expires: v.get("expires").and_then(Value::as_f64).unwrap_or(-1.0),
        http_only: v.get("httpOnly").and_then(Value::as_bool).unwrap_or(false),
        secure: v.get("secure").and_then(Value::as_bool).unwrap_or(false),
        same_site: v
            .get("sameSite")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegate_proxy_drops_the_remote_dns_suffix() {
        let u = |s: &str| Url::parse(s).unwrap();
        assert_eq!(
            delegate_proxy(&u("socks5h://u:p@warp:40000")).as_str(),
            "socks5://u:p@warp:40000"
        );
        assert_eq!(
            delegate_proxy(&u("http://proxy:3128")).as_str(),
            "http://proxy:3128/"
        );
    }

    #[test]
    fn byparr_headers_from_proxy_url() {
        let u = Url::parse("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(
            byparr_proxy_headers(&u),
            vec![("X-Proxy-Server", "socks5://127.0.0.1:1080".to_string())]
        );
        let u = Url::parse("http://us%40er:p%3Ass@proxy.example:3128").unwrap();
        assert_eq!(
            byparr_proxy_headers(&u),
            vec![
                ("X-Proxy-Server", "http://proxy.example:3128".to_string()),
                ("X-Proxy-Username", "us@er".to_string()),
                ("X-Proxy-Password", "p:ss".to_string()),
            ]
        );
        assert_eq!(percent_decode("a%zz%4"), "a%zz%4");
    }
}
