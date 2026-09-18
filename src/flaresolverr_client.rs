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
        if let Some(p) = proxy {
            body["proxy"] = json!({ "url": p.as_str() });
        }

        let resp = self
            .http
            .post(format!("{}/v1", self.endpoint))
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
