//! Optional `yt-dlp` subprocess path (DESIGN.md §10). `#[cfg(feature = "ytdlp")]`.
//!
//! For hosts on the configured list cobweb shells out to `yt-dlp -g` instead of
//! running its own pipeline — inheriting ~1800 extractors, signature handling,
//! PO-token plugins, none of which cobweb maintains.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use url::Url;

use crate::config::YtdlpConfig;
use crate::error::{CobwebError, Result};
use crate::jar::StorageState;

pub struct Ytdlp {
    bin: String,
    /// Registrable-domain suffixes: `youtube.com` matches `www.youtube.com`.
    hosts: Vec<String>,
}

impl Ytdlp {
    /// `Some` when enabled and the binary resolves; else `None`.
    pub fn from_config(cfg: &YtdlpConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        if !binary_ok(&cfg.bin) {
            tracing::warn!(bin = %cfg.bin, "ytdlp enabled but binary not found; disabling");
            return None;
        }
        Some(Self {
            bin: cfg.bin.clone(),
            hosts: cfg
                .hosts
                .iter()
                .map(|h| h.trim_start_matches('.').to_ascii_lowercase())
                .collect(),
        })
    }

    pub fn handles(&self, url: &Url) -> bool {
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return false;
        };
        self.hosts
            .iter()
            .any(|h| host == *h || host.ends_with(&format!(".{h}")))
    }

    /// `yt-dlp -g <url>` → direct stream URL(s), first one is the primary.
    pub async fn resolve(
        &self,
        url: &Url,
        jar: Option<&StorageState>,
        proxy: Option<&Url>,
        timeout: Duration,
    ) -> Result<Vec<String>> {
        // Export the jar cookies to a Netscape file yt-dlp can read.
        let cookie_file = match jar.filter(|s| !s.cookies.is_empty()) {
            Some(s) => Some(TempCookies::write(&s.to_netscape())?),
            None => None,
        };

        let mut cmd = Command::new(&self.bin);
        cmd.kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("-g")
            .arg("--no-warnings")
            .arg("--no-playlist");
        if let Some(p) = proxy {
            cmd.arg("--proxy").arg(p.as_str());
        }
        if let Some(f) = &cookie_file {
            cmd.arg("--cookies").arg(&f.0);
        }
        // `--` so nothing in the URL can ever be read as an option.
        cmd.arg("--").arg(url.as_str());

        let out = tokio::time::timeout(timeout, cmd.output())
            .await
            .map_err(|_| CobwebError::Upstream(format!("yt-dlp timed out after {timeout:?}")))?
            .map_err(|e| CobwebError::Upstream(format!("yt-dlp spawn: {e}")))?;

        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(CobwebError::NotResolved(format!(
                "yt-dlp failed ({}): {}",
                out.status,
                err.lines().next().unwrap_or("").trim()
            )));
        }

        let urls: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("http"))
            .map(str::to_string)
            .collect();
        if urls.is_empty() {
            return Err(CobwebError::NotResolved("yt-dlp returned no URL".into()));
        }
        Ok(urls)
    }
}

/// A `600`-perm cookie file that deletes itself on drop.
struct TempCookies(PathBuf);

impl TempCookies {
    /// Created `0600` + `create_new` under an unguessable name: never
    /// follows a symlink planted in the shared temp dir, and never briefly
    /// world-readable (it used to be written with the default umask and
    /// `chmod`ed afterwards).
    fn write(contents: &str) -> Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!(
            "cobweb-cookies-{}-{}.txt",
            std::process::id(),
            crate::util::random_token(8)
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| CobwebError::Other(anyhow::anyhow!("write cookies: {e}")))?;
        let guard = Self(path);
        f.write_all(contents.as_bytes())
            .map_err(|e| CobwebError::Other(anyhow::anyhow!("write cookies: {e}")))?;
        Ok(guard)
    }
}

impl Drop for TempCookies {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn binary_ok(bin: &str) -> bool {
    if bin.contains('/') {
        return Path::new(bin).is_file();
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}
