//! Own an `x11vnc` process attached to the same Xvfb display Chromium is on.

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::process::{Child, Command};

use crate::error::{CobwebError, Result};
use crate::util::{drain_bounded, free_port, which};

pub struct X11Vnc {
    child: Child,
    pgid: Option<i32>,
    /// Loopback RFB port cobweb bridges the admin websocket to.
    pub port: u16,
}

impl X11Vnc {
    pub async fn spawn(disp: &str) -> Result<Self> {
        let bin =
            which("x11vnc").ok_or_else(|| CobwebError::NotImplemented("x11vnc not installed"))?;
        let port = free_port().map_err(|e| CobwebError::Browser(format!("pick rfb port: {e}")))?;

        let mut child = Command::new(&bin)
            .kill_on_drop(true)
            .process_group(0)
            // x11vnc bails if it sees a Wayland session env, even with -display.
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("XDG_SESSION_TYPE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args([
                "-display",
                disp,
                "-rfbport",
                &port.to_string(),
                "-localhost", // cobweb is the only client; it bridges the WS
                "-nopw",      // access is gated by cobweb's HTTP layer + the per-session
                // vnc-ws token (SessionManager); see also -shared below
                "-forever", // don't exit when a viewer disconnects
                // Deliberately NOT `-shared`: x11vnc then refuses a second
                // concurrent RFB TCP connection outright, so even a leaked or
                // guessed vnc-ws token lets an attacker *replace* the admin's
                // view at most, never silently ride along beside it with its
                // own mouse/keyboard input.
                "-noxdamage",
                "-noxfixes",
                "-noxrandr",
            ])
            .spawn()
            .map_err(|e| CobwebError::Browser(format!("spawn x11vnc: {e}")))?;
        let pgid = child.id().map(|p| p as i32);

        let stderr_tail: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        if let Some(out) = child.stdout.take() {
            tokio::spawn(drain_bounded(out, stderr_tail.clone(), 4096));
        }
        if let Some(err) = child.stderr.take() {
            tokio::spawn(drain_bounded(err, stderr_tail.clone(), 4096));
        }

        // Wait for the RFB port to accept connections.
        let addr = format!("127.0.0.1:{port}");
        let mut ok = false;
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                ok = true;
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                let tail = stderr_tail
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                return Err(CobwebError::Browser(format!(
                    "x11vnc exited early ({status}): {}",
                    tail.trim()
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !ok {
            let _ = child.start_kill();
            let tail = stderr_tail
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            return Err(CobwebError::Browser(format!(
                "x11vnc did not open its RFB port: {}",
                tail.trim()
            )));
        }

        tracing::info!("x11vnc attached to {disp} on rfb port {port}");
        Ok(Self { child, pgid, port })
    }

    pub async fn kill(mut self) {
        if let Some(pgid) = self.pgid {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}
