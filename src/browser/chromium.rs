//! Launch and own the single Chromium process (DESIGN.md §3).
//!
//! `--headless=new` by default; headed under a spawned Xvfb when
//! `browser.xvfb = true` (only the tier-4 manual VNC solve needs that).
//! Chromium runs in its own process group so teardown kills the whole tree —
//! Chromium's zygote/renderers reparent to init otherwise and pile up.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

use super::engine::{BrowserError, BrowserResult};
use super::xvfb::Xvfb;
use crate::config::BrowserConfig;

/// A running Chromium plus the CDP browser-level WebSocket URL.
pub struct Chromium {
    child: Child,
    /// Process-group id (== the launcher pid) for a group kill on teardown.
    pgid: Option<i32>,
    pub ws_url: String,
    /// Kept so the temp profile dir lives as long as the process.
    _profile: tempdir::TempProfile,
    /// Kept so the virtual display outlives Chromium (headed mode).
    xvfb: Option<Xvfb>,
    pub headless: bool,
    /// The UA we pinned via `--user-agent` (real Chrome string, no "Headless").
    pub user_agent: String,
}

impl Chromium {
    /// `max_contexts` sizes `--renderer-process-limit`: a sniff context is one
    /// page plus (often) one out-of-process embed subframe, so two renderers.
    pub async fn launch(cfg: &BrowserConfig, max_contexts: usize) -> BrowserResult<Self> {
        let bin = resolve_binary(&cfg.chromium_path)?;
        let renderer_limit = max_contexts.saturating_mul(2).clamp(2, 8);
        let profile = tempdir::TempProfile::new()
            .map_err(|e| BrowserError::Unavailable(format!("temp profile dir: {e}")))?;
        let port = free_port()?;

        // Headed under an Xvfb we own (needed so x11vnc can attach to the same
        // display in M3). Ambient $DISPLAY is deliberately ignored. Falls back
        // to `--headless=new` if Xvfb isn't installed.
        let (display, xvfb): (Option<String>, Option<Xvfb>) = if !cfg.xvfb {
            (None, None)
        } else {
            match Xvfb::spawn().await {
                Ok(x) => (Some(x.display.clone()), Some(x)),
                Err(e) => {
                    tracing::warn!(error = %e, "Xvfb unavailable; using --headless=new");
                    (None, None)
                }
            }
        };
        let headless = display.is_none();

        let no_sandbox = cfg.no_sandbox || running_as_root();
        if no_sandbox {
            tracing::debug!("launching Chromium with --no-sandbox");
        }

        // Pin a real desktop-Chrome UA + Accept-Language at the network layer so
        // every frame/worker request is consistent (CDP overrides race with
        // same-origin subframes and mangle Accept-Language q-values).
        let user_agent = desktop_ua(&bin).await;

        let mut cmd = Command::new(&bin);
        if let Some(d) = &display {
            cmd.env("DISPLAY", d);
        }
        cmd.kill_on_drop(true)
            .process_group(0) // own group == own pid; teardown kills the tree
            .env_remove("WAYLAND_DISPLAY") // force X11 (our Xvfb), never Wayland
            .env_remove("XDG_SESSION_TYPE")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .arg(format!("--remote-debugging-port={port}"))
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-blink-features=AutomationControlled")
            .arg("--disable-background-networking")
            .arg("--disable-backgrounding-occluded-windows")
            .arg("--disable-renderer-backgrounding")
            .arg("--disable-background-timer-throttling")
            .arg("--disable-hang-monitor")
            .arg("--disable-ipc-flooding-protection")
            .arg("--disable-gpu") // no real GPU under Xvfb / headless
            .arg("--disable-software-rasterizer")
            .arg("--block-new-web-contents") // ad popups open in-tab, not new targets
            .arg(format!("--renderer-process-limit={renderer_limit}")) // cap RAM; a sniff needs few
            .arg("--js-flags=--max-old-space-size=512") // cap a runaway V8 heap per renderer
            .arg("--disable-features=Translate,OptimizationHints,MediaRouter,BackForwardCache,CalculateNativeWinOcclusion,AcceptCHFrame,InterestCohort")
            .arg("--disable-sync")
            .arg("--disable-extensions")
            .arg("--disable-component-update") // no background component downloads
            .arg("--disable-domain-reliability")
            .arg("--metrics-recording-only")
            .arg("--mute-audio")
            .arg("--hide-scrollbars")
            .arg("--window-size=1280,720")
            .arg("--accept-lang=en-US,en")
            .arg(format!("--user-agent={user_agent}"))
            .arg("--disable-dev-shm-usage"); // containers: /dev/shm is often tiny

        if headless {
            cmd.arg("--headless=new");
        }
        if no_sandbox {
            cmd.arg("--no-sandbox");
        }
        for extra in &cfg.extra_args {
            cmd.arg(extra);
        }
        cmd.arg("about:blank");

        tracing::info!(bin = %bin.display(), port, headless, no_sandbox, "launching Chromium");
        let mut child = cmd
            .spawn()
            .map_err(|e| BrowserError::Unavailable(format!("spawn {}: {e}", bin.display())))?;
        let pgid = child.id().map(|p| p as i32);

        // Drain stderr into a bounded buffer so a launch failure can say why.
        let stderr_tail: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        if let Some(mut err) = child.stderr.take() {
            let tail = stderr_tail.clone();
            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                while let Ok(n) = err.read(&mut chunk).await {
                    if n == 0 {
                        break;
                    }
                    let mut g = tail.lock().unwrap();
                    g.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    if g.len() > 8192 {
                        let cut = g.len() - 8192;
                        g.drain(..cut);
                    }
                }
            });
        }

        let ws_url = match discover_ws(port).await {
            Ok(u) => u,
            Err(e) => {
                let _ = child.start_kill();
                let tail = stderr_tail.lock().unwrap().clone();
                return Err(BrowserError::Unavailable(format!(
                    "Chromium started but CDP never came up: {e}\n--- chromium stderr (tail) ---\n{}",
                    tail.trim()
                )));
            }
        };

        Ok(Self {
            child,
            pgid,
            ws_url,
            _profile: profile,
            xvfb,
            headless,
            user_agent,
        })
    }

    /// The Xvfb display we spawned (`":100"`), if headed under our own Xvfb.
    pub fn xvfb_display(&self) -> Option<&str> {
        self.xvfb.as_ref().map(|x| x.display.as_str())
    }

    pub async fn kill(mut self) {
        // SIGKILL the whole process group first (zygote + renderers), then reap.
        if let Some(pgid) = self.pgid {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
        if let Some(x) = self.xvfb.take() {
            x.kill().await;
        }
    }

    /// Synchronous best-effort kill for `Drop` (a panic must not orphan Chromium).
    pub fn kill_sync(&self) {
        if let Some(pgid) = self.pgid {
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
        if let Some(x) = &self.xvfb {
            x.kill_sync();
        }
    }
}

/// `<bin> --version` -> a desktop-Chrome UA string with the real major version.
/// Memoised: the version can't change under a running cobweb, but Chromium is
/// relaunched on every cold start after an idle shutdown and the probe is a
/// full process spawn. Falls back to a recent-ish major if the probe fails.
async fn desktop_ua(bin: &std::path::Path) -> String {
    static CACHE: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
    CACHE
        .get_or_init(|| async { probe_desktop_ua(bin).await })
        .await
        .clone()
}

async fn probe_desktop_ua(bin: &std::path::Path) -> String {
    let major = Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            // "Chromium 151.0.7278.5" / "Google Chrome 151.0.7278.5"
            s.split_whitespace()
                .find_map(|t| t.split('.').next().filter(|n| n.parse::<u32>().is_ok()))
                .map(str::to_string)
        })
        .unwrap_or_else(|| "151".to_string());

    format!(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/{major}.0.0.0 Safari/537.36"
    )
}

/// Poll `http://127.0.0.1:PORT/json/version` until it hands back a
/// `webSocketDebuggerUrl` (Chromium needs ~0.3–1.5 s to open the port).
async fn discover_ws(port: u16) -> anyhow::Result<String> {
    let client = wreq::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| anyhow::anyhow!("build CDP probe client: {e}"))?;
    let url = format!("http://127.0.0.1:{port}/json/version");

    let mut last_err = String::from("timed out");
    for _ in 0..60 {
        match client.get(&url).send().await {
            Ok(resp) => {
                let v: Value = resp.json().await.unwrap_or(Value::Null);
                if let Some(ws) = v.get("webSocketDebuggerUrl").and_then(|s| s.as_str()) {
                    return Ok(ws.to_string());
                }
                last_err = format!("no webSocketDebuggerUrl in {v}");
            }
            Err(e) => last_err = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("{last_err}")
}

/// Linux: read our real UID from `/proc/self/status`. Root => the Chromium
/// sandbox can't drop privileges and the process exits, so we need `--no-sandbox`.
fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .map(|l| l.split_whitespace().nth(1) == Some("0"))
        })
        .unwrap_or(false)
}

fn free_port() -> BrowserResult<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| BrowserError::Unavailable(format!("cannot pick a debug port: {e}")))?;
    let p = l
        .local_addr()
        .map_err(|e| BrowserError::Unavailable(e.to_string()))?
        .port();
    Ok(p)
}

fn resolve_binary(configured: &str) -> BrowserResult<PathBuf> {
    if configured != "auto" {
        let p = PathBuf::from(configured);
        return if p.exists() || which(configured).is_some() {
            Ok(which(configured).unwrap_or(p))
        } else {
            Err(BrowserError::Unavailable(format!(
                "configured chromium_path `{configured}` not found"
            )))
        };
    }
    const CANDIDATES: &[&str] = &[
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
    ];
    CANDIDATES.iter().find_map(|c| which(c)).ok_or_else(|| {
        BrowserError::Unavailable(format!(
            "no Chromium on PATH (tried {}); set [browser].chromium_path",
            CANDIDATES.join(", ")
        ))
    })
}

/// Minimal `which`: scan `$PATH` for an executable file named `name`.
fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

/// Tiny self-cleaning temp dir (avoids a `tempfile` dependency reaching into the
/// non-test build just for this).
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempProfile(PathBuf);

    impl TempProfile {
        pub fn new() -> std::io::Result<Self> {
            let mut p = std::env::temp_dir();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            p.push(format!("cobweb-chromium-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&p)?;
            Ok(Self(p))
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempProfile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
