//! Cookie + storage-state types.
//!
//! [`Cookie`] follows the CDP `Network.Cookie` shape so it round-trips cleanly
//! into a browser context (`Network.setCookies`) in M2 and out of a `Set-Cookie`
//! header on the fast-path. [`StorageState`] is Playwright's `storageState`
//! shape: v1 only ever writes `cookies`; `origins` (localStorage) stays empty
//! and is a non-breaking add later (DESIGN.md §5 / §14.1).

use serde::{Deserialize, Serialize};

/// CDP `Network.Cookie`. Unknown fields from a real CDP dump are ignored on
/// read; we only serialize what we set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default = "default_path")]
    pub path: String,
    /// Unix seconds. `-1` (or absent) = session cookie.
    #[serde(default = "session_expiry")]
    pub expires: f64,
    #[serde(default, rename = "httpOnly")]
    pub http_only: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default, rename = "sameSite", skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

fn default_path() -> String {
    "/".to_string()
}
fn session_expiry() -> f64 {
    -1.0
}

impl Cookie {
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: domain.into(),
            path: default_path(),
            expires: session_expiry(),
            http_only: false,
            secure: false,
            same_site: None,
        }
    }

    /// Session cookie, or expiry strictly in the future relative to `now_unix`.
    pub fn is_live(&self, now_unix: f64) -> bool {
        self.expires < 0.0 || self.expires > now_unix
    }

    /// One `name=value` pair for a `Cookie:` request header.
    pub fn header_pair(&self) -> String {
        format!("{}={}", self.name, self.value)
    }

    /// One line of a Netscape `cookies.txt` (what `yt-dlp --cookies` wants).
    /// Format: `domain \t include_subdomains \t path \t secure \t expiry \t name \t value`
    pub fn to_netscape_line(&self) -> String {
        let domain = if self.domain.starts_with('.') {
            self.domain.clone()
        } else {
            format!(".{}", self.domain.trim_start_matches('.'))
        };
        let include_sub = "TRUE";
        let secure = if self.secure { "TRUE" } else { "FALSE" };
        let expiry = if self.expires < 0.0 {
            0
        } else {
            self.expires as i64
        };
        let line = format!(
            "{domain}\t{include_sub}\t{}\t{secure}\t{expiry}\t{}\t{}",
            self.path, self.name, self.value
        );
        if self.http_only {
            format!("#HttpOnly_{line}")
        } else {
            line
        }
    }
}

/// Playwright `storageState`. `origins` is empty in v1.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StorageState {
    #[serde(default)]
    pub cookies: Vec<Cookie>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<OriginState>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OriginState {
    pub origin: String,
    #[serde(rename = "localStorage", default)]
    pub local_storage: Vec<LocalStorageEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalStorageEntry {
    pub name: String,
    pub value: String,
}

impl StorageState {
    pub fn from_cookies(cookies: Vec<Cookie>) -> Self {
        Self {
            cookies,
            origins: Vec::new(),
        }
    }

    /// Build a `Cookie:` header value from the live cookies, optionally filtered
    /// to those whose domain matches `host` (suffix match, handles a leading dot).
    pub fn cookie_header(&self, host: &str, now_unix: f64) -> Option<String> {
        let pairs: Vec<String> = self
            .cookies
            .iter()
            .filter(|c| c.is_live(now_unix))
            .filter(|c| domain_matches(&c.domain, host))
            .map(Cookie::header_pair)
            .collect();
        if pairs.is_empty() {
            None
        } else {
            Some(pairs.join("; "))
        }
    }

    /// Merge `incoming` on top of `self`: cookies with the same `(name, domain,
    /// path)` are replaced, the rest appended. Used when a fast-path response
    /// carries `Set-Cookie`, or a browser context hands back an updated state.
    pub fn merge_from(&mut self, incoming: impl IntoIterator<Item = Cookie>) {
        for c in incoming {
            if let Some(slot) = self
                .cookies
                .iter_mut()
                .find(|e| e.name == c.name && e.domain == c.domain && e.path == c.path)
            {
                *slot = c;
            } else {
                self.cookies.push(c);
            }
        }
    }

    pub fn to_netscape(&self) -> String {
        let mut out = String::from("# Netscape HTTP Cookie File\n# generated by cobweb\n");
        for c in &self.cookies {
            out.push_str(&c.to_netscape_line());
            out.push('\n');
        }
        out
    }
}

/// `cookie_domain` matches `host` if it is equal, or a dot-suffix of it.
fn domain_matches(cookie_domain: &str, host: &str) -> bool {
    let cd = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    let h = host.trim_start_matches('.').to_ascii_lowercase();
    if cd.is_empty() {
        return true; // unscoped cookie
    }
    h == cd || h.ends_with(&format!(".{cd}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_serde_matches_cdp_camelcase() {
        let json = r#"{"name":"cf_clearance","value":"abc","domain":".example.com",
            "path":"/","expires":1900000000.0,"httpOnly":true,"secure":true,"sameSite":"None"}"#;
        let c: Cookie = serde_json::from_str(json).unwrap();
        assert_eq!(c.name, "cf_clearance");
        assert!(c.http_only && c.secure);
        assert_eq!(c.same_site.as_deref(), Some("None"));
        let round = serde_json::to_string(&c).unwrap();
        assert!(round.contains("\"httpOnly\":true"));
    }

    #[test]
    fn ignores_unknown_cdp_fields() {
        let json = r#"{"name":"a","value":"b","domain":"x.com","size":10,"priority":"Medium","sameParty":false}"#;
        let c: Cookie = serde_json::from_str(json).unwrap();
        assert_eq!(c.value, "b");
    }

    #[test]
    fn cookie_header_filters_by_domain_and_liveness() {
        let state = StorageState::from_cookies(vec![
            Cookie::new("a", "1", ".example.com"),
            Cookie::new("b", "2", "other.com"),
            {
                let mut c = Cookie::new("expired", "x", "example.com");
                c.expires = 1.0;
                c
            },
        ]);
        let hdr = state.cookie_header("cdn.example.com", 1000.0).unwrap();
        assert_eq!(hdr, "a=1");
    }

    #[test]
    fn merge_replaces_same_key_appends_new() {
        let mut s = StorageState::from_cookies(vec![Cookie::new("a", "old", "x.com")]);
        s.merge_from(vec![
            Cookie::new("a", "new", "x.com"),
            Cookie::new("b", "2", "x.com"),
        ]);
        assert_eq!(s.cookies.len(), 2);
        assert_eq!(s.cookies[0].value, "new");
    }

    #[test]
    fn netscape_export_marks_httponly() {
        let mut c = Cookie::new("s", "v", "example.com");
        c.http_only = true;
        c.secure = true;
        c.expires = 1900000000.0;
        let line = c.to_netscape_line();
        assert!(line.starts_with("#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1900000000\ts\tv"));
    }

    #[test]
    fn origins_omitted_from_json_when_empty() {
        let s = StorageState::from_cookies(vec![Cookie::new("a", "1", "x.com")]);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("origins"));
    }
}
