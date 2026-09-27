//! Connect-time SSRF enforcement for the browser tier.
//!
//! The Fetch-domain guard in `cdp_engine.rs` vets every request *URL* before
//! Chromium sends it, but Chromium then resolves the host again on its own:
//! a name with a 0-TTL record that answers "public" to the guard and
//! "127.0.0.1" to Chromium (DNS rebinding) slips through, and WebSocket
//! handshakes never reach the Fetch domain at all.
//!
//! This is a tiny loopback-only HTTP proxy that every `direct`-egress browser
//! context is pointed at (`proxyServer` on `Target.createBrowserContext`).
//! Chromium hands it the *name*; the proxy resolves it once, vets every
//! address with [`crate::ssrf::vetted_socket_addrs`], and connects to one of
//! exactly those addresses — the check and the connect can't disagree.
//!
//! * `CONNECT host:port` (https, wss, and ws — Chromium always tunnels
//!   WebSockets through an HTTP proxy): vetted, then a blind byte tunnel.
//!   TLS stays end to end, so the browser's TLS/H2 fingerprint is unchanged.
//! * absolute-form `GET http://host/…` (plain http): vetted, rewritten to
//!   origin-form with `Connection: close`, so one proxy connection carries
//!   exactly one upstream request and can never be steered to a second host.
//!
//! Anything on the box can connect to the listener, but all it can do
//! through it is what the SSRF policy already allows cobweb itself.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::settings::RuntimeSettings;

/// Max bytes of a request head (request line + headers).
const MAX_HEAD: usize = 64 * 1024;
/// Time allowed for the client to send its request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
/// Time allowed to establish the upstream TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Concurrent proxied connections (a busy page opens a few dozen).
const MAX_CONNS: usize = 512;

/// A running proxy; the accept loop stops when this is dropped.
pub struct EgressProxy {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl EgressProxy {
    /// Bind `127.0.0.1:0` and start serving.
    pub async fn start(
        allow_private: bool,
        settings: Option<Arc<RuntimeSettings>>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let limit = Arc::new(Semaphore::new(MAX_CONNS));
        let task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    continue;
                };
                let Ok(permit) = limit.clone().acquire_owned().await else {
                    break;
                };
                let settings = settings.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = serve(sock, allow_private, settings.as_deref()).await {
                        tracing::trace!(error = %e, "egress proxy: connection ended");
                    }
                });
            }
        });
        tracing::debug!(%addr, "browser egress proxy listening");
        Ok(Self { addr, task })
    }

    /// `http://127.0.0.1:<port>` for `proxyServer`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn serve(
    mut client: TcpStream,
    allow_private: bool,
    settings: Option<&RuntimeSettings>,
) -> std::io::Result<()> {
    let _ = client.set_nodelay(true);
    let (head, rest) = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => return reply(&mut client, 408, "request head timeout").await,
    };
    let Some(req) = parse_head(&head) else {
        return reply(&mut client, 400, "malformed request").await;
    };

    let (host, port) = match &req.target {
        Target::Authority { host, port } => (host.clone(), *port),
        Target::Absolute(u) => {
            let (Some(h), Some(p)) = (u.host_str(), u.port_or_known_default()) else {
                return reply(&mut client, 400, "no host").await;
            };
            (h.to_string(), p)
        }
    };

    let addrs = match crate::ssrf::vetted_socket_addrs(&host, port, allow_private, settings).await {
        Ok(a) => a,
        Err(reason) => {
            tracing::debug!(%host, %reason, "browser egress proxy: refused");
            return reply(&mut client, 403, "blocked by cobweb SSRF policy").await;
        }
    };
    let Some(mut upstream) = connect_any(&addrs).await else {
        return reply(&mut client, 502, "upstream connect failed").await;
    };
    let _ = upstream.set_nodelay(true);

    match &req.target {
        Target::Authority { .. } => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            if !rest.is_empty() {
                upstream.write_all(&rest).await?;
            }
        }
        Target::Absolute(u) => {
            upstream
                .write_all(origin_form_head(&req, u).as_bytes())
                .await?;
            if !rest.is_empty() {
                upstream.write_all(&rest).await?;
            }
        }
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn connect_any(addrs: &[SocketAddr]) -> Option<TcpStream> {
    for a in addrs {
        if let Ok(Ok(s)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
            return Some(s);
        }
    }
    None
}

/// Read until the end of the request head. `(head, bytes read past it)`,
/// `None` on EOF before any byte.
async fn read_head(s: &mut TcpStream) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            };
        }
        // Only the tail can newly complete the terminator.
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = find(&buf[from..], b"\r\n\r\n") {
            let end = from + i + 4;
            let rest = buf.split_off(end);
            return Ok(Some((buf, rest)));
        }
        if buf.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[derive(Debug)]
enum Target {
    /// `CONNECT host:port`
    Authority { host: String, port: u16 },
    /// `GET http://host/path` — plain-http forward proxying.
    Absolute(url::Url),
}

#[derive(Debug)]
struct Head {
    method: String,
    version: String,
    target: Target,
    headers: Vec<(String, String)>,
}

fn parse_head(raw: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let method = parts.next()?.to_string();
    let target_s = parts.next()?;
    let version = parts.next()?.to_string();
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return None;
    }
    let target = if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = target_s.rsplit_once(':')?;
        Target::Authority {
            host: host.to_string(),
            port: port.parse().ok()?,
        }
    } else {
        let u = url::Url::parse(target_s).ok()?;
        // ws:// is tunnelled with CONNECT by Chromium; anything else here
        // (ftp://, file://, …) has no business going through this proxy.
        if u.scheme() != "http" {
            return None;
        }
        Target::Absolute(u)
    };
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    Some(Head {
        method,
        version,
        target,
        headers,
    })
}

/// The request re-serialised for the origin server: origin-form target,
/// proxy-only headers dropped, and `Connection: close` (unless this is a
/// protocol upgrade) so this connection carries exactly one exchange.
fn origin_form_head(req: &Head, u: &url::Url) -> String {
    let mut path = u.path().to_string();
    if let Some(q) = u.query() {
        path.push('?');
        path.push_str(q);
    }
    let upgrade = req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("upgrade"));
    let mut out = format!("{} {} {}\r\n", req.method, path, req.version);
    for (k, v) in &req.headers {
        let lk = k.to_ascii_lowercase();
        let drop = matches!(
            lk.as_str(),
            "proxy-connection" | "proxy-authorization" | "keep-alive"
        ) || (lk == "connection" && !upgrade);
        if !drop {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    if !upgrade {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    out
}

async fn reply(s: &mut TcpStream, code: u16, msg: &str) -> std::io::Result<()> {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        408 => "Request Timeout",
        _ => "Bad Gateway",
    };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
        msg.len()
    );
    s.write_all(resp.as_bytes()).await?;
    s.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn echo_server() -> SocketAddr {
        // Minimal origin: answers every request with its own request line.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let Ok(Some((head, _))) = read_head(&mut s).await else {
                        return;
                    };
                    let head = String::from_utf8_lossy(&head).to_string();
                    let body = head.replace("\r\n", "|");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    async fn roundtrip(proxy: &EgressProxy, raw: &str) -> String {
        let mut s = TcpStream::connect(proxy.addr).await.unwrap();
        s.write_all(raw.as_bytes()).await.unwrap();
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out)).await;
        out
    }

    #[tokio::test]
    async fn forwards_plain_http_in_origin_form_with_connection_close() {
        let origin = echo_server().await;
        let p = EgressProxy::start(true, None).await.unwrap();
        let out = roundtrip(
            &p,
            &format!(
                "GET http://{origin}/a?b=1 HTTP/1.1\r\nHost: {origin}\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n"
            ),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.contains("GET /a?b=1 HTTP/1.1|"), "{out}");
        assert!(out.contains("Connection: close"), "{out}");
        assert!(
            !out.to_ascii_lowercase().contains("proxy-connection"),
            "{out}"
        );
        assert!(!out.contains("keep-alive"), "{out}");
    }

    #[tokio::test]
    async fn tunnels_connect_to_an_allowed_host() {
        let origin = echo_server().await;
        let p = EgressProxy::start(true, None).await.unwrap();
        let out = roundtrip(
            &p,
            &format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\nGET /t HTTP/1.1\r\nHost: x\r\n\r\n"),
        )
        .await;
        assert!(
            out.starts_with("HTTP/1.1 200 Connection Established"),
            "{out}"
        );
        assert!(out.contains("GET /t HTTP/1.1"), "{out}");
    }

    #[tokio::test]
    async fn refuses_private_and_metadata_targets() {
        let origin = echo_server().await;
        let strict = EgressProxy::start(false, None).await.unwrap();
        for raw in [
            format!("CONNECT {origin} HTTP/1.1\r\n\r\n"),
            format!("GET http://{origin}/ HTTP/1.1\r\n\r\n"),
            "CONNECT localhost:80 HTTP/1.1\r\n\r\n".to_string(),
            "CONNECT [::1]:80 HTTP/1.1\r\n\r\n".to_string(),
        ] {
            let out = roundtrip(&strict, &raw).await;
            assert!(out.starts_with("HTTP/1.1 403"), "{raw:?} -> {out}");
        }
        // Hard-blocked even when private targets are allowed.
        let relaxed = EgressProxy::start(true, None).await.unwrap();
        let out = roundtrip(&relaxed, "CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n").await;
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    }

    #[tokio::test]
    async fn rejects_non_http_absolute_targets_and_garbage() {
        let p = EgressProxy::start(true, None).await.unwrap();
        for raw in [
            "GET ftp://example.com/ HTTP/1.1\r\n\r\n",
            "GET /relative HTTP/1.1\r\n\r\n",
            "NONSENSE\r\n\r\n",
        ] {
            let out = roundtrip(&p, raw).await;
            assert!(out.starts_with("HTTP/1.1 400"), "{raw:?} -> {out}");
        }
    }
}
