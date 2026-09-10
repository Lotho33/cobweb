//! Own an `x11vnc` process attached to the same Xvfb display Chromium is on.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

use crate::error::{CobwebError, Result};

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
        let port = free_port()?;

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
                "-nopw",      // access is gated by cobweb's HTTP layer / mycelium
                "-shared",
                "-forever", // don't exit when a viewer disconnects
                "-noxdamage",
                "-noxfixes",
                "-noxrandr",
            ])
            .spawn()
            .map_err(|e| CobwebError::Browser(format!("spawn x11vnc: {e}")))?;
        let pgid = child.id().map(|p| p as i32);

        let stderr_tail: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        if let Some(mut out) = child.stdout.take() {
            let sink = stderr_tail.clone();
            tokio::spawn(async move { drain(&mut out, sink).await });
        }
        if let Some(mut err) = child.stderr.take() {
            let sink = stderr_tail.clone();
            tokio::spawn(async move { drain(&mut err, sink).await });
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
                let tail = stderr_tail.lock().unwrap().clone();
                return Err(CobwebError::Browser(format!(
                    "x11vnc exited early ({status}): {}",
                    tail.trim()
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !ok {
            let _ = child.start_kill();
            let tail = stderr_tail.lock().unwrap().clone();
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

async fn drain<R: tokio::io::AsyncRead + Unpin>(rd: &mut R, sink: Arc<Mutex<String>>) {
    let mut chunk = [0u8; 2048];
    while let Ok(n) = rd.read(&mut chunk).await {
        if n == 0 {
            break;
        }
        let mut g = sink.lock().unwrap();
        g.push_str(&String::from_utf8_lossy(&chunk[..n]));
        if g.len() > 4096 {
            let cut = g.len() - 4096;
            g.drain(..cut);
        }
    }
}

fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| CobwebError::Browser(format!("pick rfb port: {e}")))?;
    Ok(l.local_addr()
        .map_err(|e| CobwebError::Browser(e.to_string()))?
        .port())
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}
