//! Launch and own the single Chromium process (DESIGN.md §3), always under
//! `--headless=new`. Chromium runs in its own process group so teardown
//! kills the whole tree — Chromium's zygote/renderers reparent to init
//! otherwise and pile up.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tokio::process::{Child, Command};

use super::cdp::CdpClient;
use super::engine::{BrowserError, BrowserResult};
use crate::config::BrowserConfig;

/// A running Chromium plus the CDP connection to it (over
/// `--remote-debugging-pipe` — see `browser/cdp.rs`).
pub struct Chromium {
    child: Child,
    /// Process-group id (== the launcher pid) for a group kill on teardown.
    pgid: Option<i32>,
    pub client: Arc<CdpClient>,
    /// Kept so the temp profile dir lives as long as the process.
    _profile: tempdir::TempProfile,
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
        // CDP rides a pipe pair instead of a TCP port: Chromium reads
        // commands on its fd 3 and writes replies/events on its fd 4.
        let (cmd_rd, cmd_wr) =
            cloexec_pipe().map_err(|e| BrowserError::Unavailable(format!("cdp pipe: {e}")))?;
        let (evt_rd, evt_wr) =
            cloexec_pipe().map_err(|e| BrowserError::Unavailable(format!("cdp pipe: {e}")))?;

        let no_sandbox = cfg.no_sandbox || running_as_root();
        if no_sandbox {
            tracing::debug!("launching Chromium with --no-sandbox");
        }

        // Pin a real desktop-Chrome UA + Accept-Language at the network layer so
        // every frame/worker request is consistent (CDP overrides race with
        // same-origin subframes and mangle Accept-Language q-values).
        let user_agent = desktop_ua(&bin).await;

        let mut cmd = Command::new(&bin);
        cmd.kill_on_drop(true)
            .process_group(0) // own group == own pid; teardown kills the tree
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .arg("--remote-debugging-pipe")
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
            .arg("--disable-gpu") // no real GPU under headless
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
            .arg("--disable-dev-shm-usage") // containers: /dev/shm is often tiny
            .arg("--headless=new");

        if no_sandbox {
            cmd.arg("--no-sandbox");
        }
        for extra in &cfg.extra_args {
            cmd.arg(extra);
        }
        cmd.arg("about:blank");

        let (child_in, child_out) = (cmd_rd.as_raw_fd(), evt_wr.as_raw_fd());
        // SAFETY: only async-signal-safe libc calls (fcntl/dup2) between fork
        // and exec. The two fds are first moved above 9 so the dup2s onto 3
        // and 4 can't clobber each other (either could already *be* 3 or 4);
        // dup2 clears FD_CLOEXEC on the target, so exactly 3 and 4 survive
        // the exec (the F_DUPFD_CLOEXEC copies and the originals don't).
        unsafe {
            cmd.pre_exec(move || {
                let a = libc::fcntl(child_in, libc::F_DUPFD_CLOEXEC, 10);
                let b = libc::fcntl(child_out, libc::F_DUPFD_CLOEXEC, 10);
                if a < 0 || b < 0 || libc::dup2(a, 3) < 0 || libc::dup2(b, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        tracing::info!(bin = %bin.display(), no_sandbox, "launching Chromium");
        let mut child = cmd
            .spawn()
            .map_err(|e| BrowserError::Unavailable(format!("spawn {}: {e}", bin.display())))?;
        let pgid = child.id().map(|p| p as i32);
        // Our copies of Chromium's ends must go, or we'd never see EOF when
        // it exits.
        drop(cmd_rd);
        drop(evt_wr);

        // Drain stderr into a bounded buffer so a launch failure can say why.
        let stderr_tail: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        if let Some(err) = child.stderr.take() {
            tokio::spawn(crate::util::drain_bounded(err, stderr_tail.clone(), 8192));
        }

        let client = match connect_pipe(cmd_wr, evt_rd).await {
            Ok(c) => c,
            Err(e) => {
                let _ = child.start_kill();
                let tail = stderr_tail
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                return Err(BrowserError::Unavailable(format!(
                    "Chromium started but CDP never came up: {e}\n--- chromium stderr (tail) ---\n{}",
                    tail.trim()
                )));
            }
        };

        Ok(Self {
            child,
            pgid,
            client,
            _profile: profile,
            user_agent,
        })
    }

    /// Still running with a live CDP connection? A crashed/OOM-killed
    /// Chromium used to stay "launched" forever — every browser-tier request
    /// failed until the idle reaper happened to fire, which it never does
    /// under steady traffic.
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None)) && !self.client.is_closed()
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
    }

    /// Synchronous best-effort kill for `Drop` (a panic must not orphan Chromium).
    pub fn kill_sync(&self) {
        if let Some(pgid) = self.pgid {
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
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

/// Wrap our ends of the pipe pair as a [`CdpClient`] and wait until the
/// browser answers a first command (it takes ~0.3–1.5 s to come up).
async fn connect_pipe(cmd_wr: OwnedFd, evt_rd: OwnedFd) -> anyhow::Result<Arc<CdpClient>> {
    use tokio::net::unix::pipe;
    let wr = pipe::Sender::from_owned_fd(cmd_wr)?;
    let rd = pipe::Receiver::from_owned_fd(evt_rd)?;
    let client = CdpClient::from_transport(rd, wr);
    client
        .call_timeout(
            "Browser.getVersion",
            json!({}),
            None,
            Duration::from_secs(15),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(client)
}

/// `pipe2(O_CLOEXEC)` → (read end, write end).
fn cloexec_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: plain syscall into a 2-int array; on success both fds are
    // fresh and exclusively ours.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
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

fn resolve_binary(configured: &str) -> BrowserResult<PathBuf> {
    use crate::util::which;
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

/// Tiny self-cleaning temp dir (avoids a `tempfile` dependency reaching into the
/// non-test build just for this).
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempProfile(PathBuf);

    impl TempProfile {
        /// A fresh `0700` directory with an unguessable name. `create`
        /// (not `create_dir_all`) fails if the path already exists, so a
        /// local user can't pre-create/symlink it to capture the profile —
        /// cookies included — and the mode keeps it private to our uid.
        pub fn new() -> std::io::Result<Self> {
            use std::os::unix::fs::DirBuilderExt;
            let p = std::env::temp_dir().join(format!(
                "cobweb-chromium-{}-{}",
                std::process::id(),
                crate::util::random_token(8)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p)?;
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
