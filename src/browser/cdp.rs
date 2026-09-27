//! Minimal Chrome DevTools Protocol client (DESIGN.md §3 "CDP client strategy").
//!
//! Talks to Chromium over `--remote-debugging-pipe`: NUL-terminated JSON
//! messages on an inherited pipe pair (we write Chromium's fd 3, read its fd
//! 4). There is no DevTools TCP port at all — with `--remote-debugging-port`
//! any local process (another container user, a compromised sidecar, a page
//! that can reach loopback) could attach to the browser and drive it. A
//! reader task demuxes messages: `{id,…}` replies go to a per-call
//! `oneshot`, `{method,params}` events go to a `broadcast`. **Nothing here
//! enables the `Runtime` domain** — the leak vector this whole approach
//! exists to dodge.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, oneshot};

use super::engine::{BrowserError, BrowserResult};

/// Upper bound on one inbound CDP message. The largest legitimate ones are
/// `Network.getResponseBody` (bodies are capped browser-side by
/// `maxResourceBufferSize`, base64-inflated) and a full `outerHTML`; this is
/// only a backstop so a misbehaving peer can't grow the read buffer forever.
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// A CDP event (`Network.requestWillBeSent`, `Page.lifecycleEvent`, …).
///
/// `params` is an `Arc` because every live [`BrowserContext`](super::engine::BrowserContext)
/// subscribes to the *same* `broadcast` channel off one Chromium-wide
/// connection (`tokio::sync::broadcast::Receiver::recv` clones the value for
/// each receiver), so with `max_contexts > 1` a single event — up to a
/// multi-KB `Network.responseReceived` — was deep-cloned once per concurrent
/// sniff even though almost every receiver immediately discards it on the
/// `session_id` filter. Cloning the `Arc` is a refcount bump instead.
#[derive(Debug, Clone)]
pub struct CdpEvent {
    pub method: String,
    pub params: Arc<Value>,
    pub session_id: Option<String>,
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

pub struct CdpClient {
    next_id: AtomicU64,
    outbound: mpsc::UnboundedSender<String>,
    pending: Pending,
    events: broadcast::Sender<CdpEvent>,
    /// Low-volume control events the per-context guard task acts on
    /// ([`is_control_event`]). Kept off `events` so the flood of
    /// `Network.*` traffic on a busy page can never make the guard *lag*
    /// and silently drop one: a lost `Fetch.requestPaused` hangs that
    /// request forever, a lost `Target.attachedToTarget` leaves a paused
    /// sub-frame un-instrumented.
    control: broadcast::Sender<CdpEvent>,
    /// Set once the reader sees EOF/an error — Chromium exited or crashed.
    closed: Arc<AtomicBool>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl Drop for CdpClient {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

impl CdpClient {
    /// Drive a CDP session over any byte transport speaking the
    /// `--remote-debugging-pipe` framing (NUL-terminated JSON): `rd` is
    /// Chromium's output (its fd 4), `wr` its input (its fd 3).
    pub fn from_transport<R, W>(rd: R, mut wr: W) -> Arc<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (events_tx, _) = broadcast::channel(1024);
        let (control_tx, _) = broadcast::channel(8192);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
        let closed = Arc::new(AtomicBool::new(false));

        let writer = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                let ok = wr.write_all(msg.as_bytes()).await.is_ok()
                    && wr.write_all(b"\0").await.is_ok()
                    && wr.flush().await.is_ok();
                if !ok {
                    break;
                }
            }
        });

        let pending_r = pending.clone();
        let events_r = events_tx.clone();
        let control_r = control_tx.clone();
        let closed_r = closed.clone();
        let reader = tokio::spawn(async move {
            let mut rd = BufReader::with_capacity(64 * 1024, rd);
            let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
            loop {
                match read_message(&mut rd, &mut buf).await {
                    Ok(true) => {}
                    Ok(false) | Err(_) => break,
                }
                let Ok(v) = serde_json::from_slice::<Value>(&buf) else {
                    continue;
                };
                dispatch(v, &pending_r, &events_r, &control_r);
            }
            closed_r.store(true, Ordering::SeqCst);
            // Connection is gone — unblock every waiter.
            for (_, tx) in pending_r.lock().unwrap_or_else(|e| e.into_inner()).drain() {
                let _ = tx.send(Err("cdp connection closed".into()));
            }
        });

        Arc::new(Self {
            next_id: AtomicU64::new(1),
            outbound: out_tx,
            pending,
            events: events_tx,
            control: control_tx,
            closed,
            reader,
            writer,
        })
    }

    /// `true` once the transport hit EOF — the browser is gone.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// New event stream. Subscribe **before** sending the command that triggers
    /// the events you want, or you'll race them.
    pub fn subscribe(&self) -> broadcast::Receiver<CdpEvent> {
        self.events.subscribe()
    }

    /// Stream of control events only (`Fetch.requestPaused`,
    /// `Target.attachedToTarget`) — see [`is_control_event`]. These never
    /// appear on [`subscribe`](Self::subscribe).
    pub fn subscribe_control(&self) -> broadcast::Receiver<CdpEvent> {
        self.control.subscribe()
    }

    /// Fire-and-forget a command: no reply is awaited, no `pending` slot is held.
    /// For teardown from `Drop`, where we can't `.await` and don't care about the
    /// result (e.g. `Target.closeTarget`).
    pub fn notify(&self, method: &str, params: Value, session_id: Option<&str>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut frame = json!({ "id": id, "method": method, "params": params });
        if let Some(sid) = session_id {
            frame["sessionId"] = json!(sid);
        }
        let _ = self.outbound.send(frame.to_string());
    }

    pub async fn call(
        &self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> BrowserResult<Value> {
        self.call_timeout(method, params, session_id, Duration::from_secs(30))
            .await
    }

    pub async fn call_timeout(
        &self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
        timeout: Duration,
    ) -> BrowserResult<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, tx);

        let mut frame = json!({ "id": id, "method": method, "params": params });
        if let Some(sid) = session_id {
            frame["sessionId"] = json!(sid);
        }
        // `closed` is checked *after* registering in `pending`: the reader
        // drains `pending` right after setting it, so either it saw our entry
        // (and failed it) or we see the flag here — never a 30 s hang on a
        // browser that already exited.
        if self.is_closed() || self.outbound.send(frame.to_string()).is_err() {
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            return Err(BrowserError::Cdp(format!(
                "{method}: cdp connection closed"
            )));
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(e))) => Err(BrowserError::Cdp(format!("{method}: {e}"))),
            Ok(Err(_)) => Err(BrowserError::Cdp(format!("{method}: response dropped"))),
            Err(_) => {
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id);
                Err(BrowserError::Cdp(format!("{method}: timed out")))
            }
        }
    }
}

/// Read one NUL-terminated message into `buf` (terminator stripped).
/// `Ok(false)` on a clean EOF; an error on I/O failure or an oversize message.
async fn read_message<R: AsyncRead + Unpin>(
    rd: &mut BufReader<R>,
    buf: &mut Vec<u8>,
) -> std::io::Result<bool> {
    buf.clear();
    loop {
        let avail = rd.fill_buf().await?;
        if avail.is_empty() {
            return Ok(false);
        }
        let (take, done) = match avail.iter().position(|&b| b == 0) {
            Some(i) => (i, true),
            None => (avail.len(), false),
        };
        buf.extend_from_slice(&avail[..take]);
        rd.consume(take + usize::from(done));
        if buf.len() > MAX_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cdp message over size cap",
            ));
        }
        if done {
            return Ok(true);
        }
    }
}

/// Route one decoded message: a reply to its waiting caller, an event to
/// the matching broadcast channel.
fn dispatch(
    mut v: Value,
    pending: &Pending,
    events: &broadcast::Sender<CdpEvent>,
    control: &broadcast::Sender<CdpEvent>,
) {
    if let Some(id) = v.get("id").and_then(Value::as_u64) {
        if let Some(tx) = pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
        {
            let res = match v.get("error") {
                Some(err) => Err(err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("cdp error")
                    .to_string()),
                // Move the result subtree out instead of deep-cloning it —
                // for getResponseBody it's a base64 string up to several MB.
                None => Ok(v.get_mut("result").map(Value::take).unwrap_or(Value::Null)),
            };
            let _ = tx.send(res);
        }
    } else if let Some(method) = v.get("method").and_then(Value::as_str).map(str::to_string) {
        if is_noisy_event(&method) {
            return;
        }
        let session_id = v
            .get("sessionId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let params = v.get_mut("params").map(Value::take).unwrap_or(Value::Null);
        let tx = if is_control_event(&method) {
            control
        } else {
            events
        };
        let _ = tx.send(CdpEvent {
            method,
            params: Arc::new(params),
            session_id,
        });
    }
}

/// Events routed to the dedicated control channel instead of the general one.
pub fn is_control_event(method: &str) -> bool {
    matches!(method, "Fetch.requestPaused" | "Target.attachedToTarget")
}

/// High-frequency CDP events that no consumer in this crate subscribes to
/// (`cdp_engine` only acts on `Page.lifecycleEvent`, `Target.attachedToTarget`
/// and four `Network.*` methods). Dropped in the reader so they never allocate a
/// `CdpEvent` or take a broadcast slot — `Network.dataReceived` alone fires once
/// per body chunk and is what tripped the "event stream lagged" path on
/// media-heavy pages.
fn is_noisy_event(method: &str) -> bool {
    matches!(
        method,
        "Network.dataReceived"
            | "Network.responseReceivedExtraInfo"
            | "Network.resourceChangedPriority"
            | "Network.requestServedFromCache"
            | "Network.loadingFailed"
            | "Network.eventSourceMessageReceived"
            | "Network.webSocketCreated"
            | "Network.webSocketClosed"
            | "Network.webSocketFrameSent"
            | "Network.webSocketFrameReceived"
            | "Network.webSocketFrameError"
            | "Network.webSocketWillSendHandshakeRequest"
            | "Network.webSocketHandshakeResponseReceived"
            | "Page.screencastFrame"
            | "Page.frameResized"
            | "Page.frameStartedLoading"
            | "Page.frameStoppedLoading"
            | "Page.frameRequestedNavigation"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The pipe framing end to end against a fake "browser" on a duplex
    // stream: a call gets its reply, events are split between the general
    // and control channels, and EOF flips `is_closed` and fails callers.
    #[tokio::test]
    async fn pipe_transport_round_trips_and_routes_events() {
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        let (rd, wr) = tokio::io::split(ours);
        let client = CdpClient::from_transport(rd, wr);
        let mut general = client.subscribe();
        let mut control = client.subscribe_control();

        let (mut b_rd, mut b_wr) = tokio::io::split(theirs);
        let browser = tokio::spawn(async move {
            // Read one request, answer it, then emit two events and hang up.
            let mut req = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                b_rd.read_exact(&mut byte).await.unwrap();
                if byte[0] == 0 {
                    break;
                }
                req.push(byte[0]);
            }
            let v: Value = serde_json::from_slice(&req).unwrap();
            assert_eq!(v["method"], "Browser.getVersion");
            let reply = json!({ "id": v["id"], "result": { "product": "X/1" } });
            let mut out = reply.to_string().into_bytes();
            out.push(0);
            out.extend_from_slice(br#"{"method":"Page.lifecycleEvent","params":{"name":"load"}}"#);
            out.push(0);
            out.extend_from_slice(
                br#"{"method":"Fetch.requestPaused","sessionId":"S","params":{}}"#,
            );
            out.push(0);
            b_wr.write_all(&out).await.unwrap();
            b_wr.shutdown().await.unwrap();
        });

        let r = client
            .call("Browser.getVersion", json!({}), None)
            .await
            .unwrap();
        assert_eq!(r["product"], "X/1");
        assert_eq!(general.recv().await.unwrap().method, "Page.lifecycleEvent");
        let c = control.recv().await.unwrap();
        assert_eq!(c.method, "Fetch.requestPaused");
        assert_eq!(c.session_id.as_deref(), Some("S"));
        browser.await.unwrap();

        for _ in 0..50 {
            if client.is_closed() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(client.is_closed());
        assert!(client
            .call("Browser.getVersion", json!({}), None)
            .await
            .is_err());
    }
}
