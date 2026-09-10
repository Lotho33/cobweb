//! Own an `Xvfb` virtual display so Chromium runs **headed** (DESIGN.md §3):
//! needed for the VNC solve (M3) and a smaller fingerprint than `--headless=new`.
//!
//! Lazy + short-lived: spawned with Chromium on the first tier-3 request, torn
//! down with it on the idle timer.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

use super::engine::{BrowserError, BrowserResult};

pub struct Xvfb {
    child: Child,
    pgid: Option<i32>,
    /// e.g. `":99"` — goes into Chromium's `DISPLAY` env.
    pub display: String,
    display_num: u32,
}

impl Xvfb {
    pub async fn spawn() -> BrowserResult<Self> {
        let bin =
            which("Xvfb").ok_or_else(|| BrowserError::Unavailable("Xvfb not on PATH".into()))?;
        let n = free_display_number()?;
        let disp = format!(":{n}");

        let mut child = Command::new(&bin)
            .kill_on_drop(true)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .arg(&disp)
            .arg("-screen")
            .arg("0")
            // matches Chromium's --window-size; smaller framebuffer = less RAM
            // and less VNC bandwidth. Plenty for a challenge checkbox.
            .arg("1280x720x24")
            .arg("-nolisten")
            .arg("tcp")
            .arg("-ac")
            .arg("-noreset")
            .spawn()
            .map_err(|e| BrowserError::Unavailable(format!("spawn Xvfb: {e}")))?;
        let pgid = child.id().map(|p| p as i32);

        // Wait for the X socket to appear.
        let sock = PathBuf::from(format!("/tmp/.X11-unix/X{n}"));
        let mut ready = false;
        for _ in 0..60 {
            if sock.exists() {
                ready = true;
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(BrowserError::Unavailable(format!(
                    "Xvfb {disp} exited early ({status})"
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !ready {
            let _ = child.start_kill();
            return Err(BrowserError::Unavailable(format!(
                "Xvfb {disp} did not come up"
            )));
        }
        tokio::time::sleep(Duration::from_millis(150)).await;

        tracing::info!("Xvfb ready on {disp}");
        Ok(Self {
            child,
            pgid,
            display: disp,
            display_num: n,
        })
    }

    pub async fn kill(mut self) {
        if let Some(pgid) = self.pgid {
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
        let _ = std::fs::remove_file(format!("/tmp/.X{}-lock", self.display_num));
    }

    /// Synchronous best-effort kill for `Drop` paths (no reaping).
    pub fn kill_sync(&self) {
        if let Some(pgid) = self.pgid {
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
        let _ = std::fs::remove_file(format!("/tmp/.X{}-lock", self.display_num));
    }
}

/// First display `:N` (100..=999) with no X socket and no lock file.
fn free_display_number() -> BrowserResult<u32> {
    for n in 100..1000 {
        let sock = PathBuf::from(format!("/tmp/.X11-unix/X{n}"));
        let lock = PathBuf::from(format!("/tmp/.X{n}-lock"));
        if !sock.exists() && !lock.exists() {
            return Ok(n);
        }
    }
    Err(BrowserError::Unavailable("no free X display number".into()))
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}
