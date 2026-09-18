//! Minimal Chrome DevTools Protocol client (DESIGN.md §3 "CDP client strategy").
//!
//! One WebSocket to `ws://127.0.0.1:…`. A reader task demuxes frames: `{id,…}`
//! replies go to a per-call `oneshot`, `{method,params}` events go to a
//! `broadcast`. **Nothing here enables the `Runtime` domain** — the leak vector
//! this whole approach exists to dodge.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

use super::engine::{BrowserError, BrowserResult};

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
    outbound: mpsc::UnboundedSender<Message>,
    pending: Pending,
    events: broadcast::Sender<CdpEvent>,
    _reader: tokio::task::JoinHandle<()>,
    _writer: tokio::task::JoinHandle<()>,
}

impl CdpClient {
    pub async fn connect(ws_url: &str) -> BrowserResult<Arc<Self>> {
        let (ws, _) = tokio_tungstenite::connect_async(ws_url)
            .await
            .map_err(|e| BrowserError::Cdp(format!("connect {ws_url}: {e}")))?;
        let (mut sink, mut stream) = ws.split();

        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (events_tx, _) = broadcast::channel(1024);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

        let writer = tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
        });

        let pending_r = pending.clone();
        let events_r = events_tx.clone();
        let reader = tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                let msg = match frame {
                    Ok(m) => m,
                    Err(_) => break,
                };
                if msg.is_close() {
                    break;
                }
                let Ok(txt) = msg.to_text() else { continue };
                let Ok(mut v) = serde_json::from_str::<Value>(txt) else {
                    continue;
                };

                if let Some(id) = v.get("id").and_then(Value::as_u64) {
                    if let Some(tx) = pending_r
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
                            // Move the result subtree out instead of deep-cloning
                            // it — for getResponseBody it's a base64 string up to
                            // several MB.
                            None => Ok(v.get_mut("result").map(Value::take).unwrap_or(Value::Null)),
                        };
                        let _ = tx.send(res);
                    }
                } else if let Some(method) =
                    v.get("method").and_then(Value::as_str).map(str::to_string)
                {
                    if is_noisy_event(&method) {
                        continue;
                    }
                    let session_id = v
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let params = v.get_mut("params").map(Value::take).unwrap_or(Value::Null);
                    let _ = events_r.send(CdpEvent {
                        method,
                        params: Arc::new(params),
                        session_id,
                    });
                }
            }
            // Connection is gone — unblock every waiter.
            for (_, tx) in pending_r.lock().unwrap_or_else(|e| e.into_inner()).drain() {
                let _ = tx.send(Err("cdp connection closed".into()));
            }
        });

        Ok(Arc::new(Self {
            next_id: AtomicU64::new(1),
            outbound: out_tx,
            pending,
            events: events_tx,
            _reader: reader,
            _writer: writer,
        }))
    }

    /// New event stream. Subscribe **before** sending the command that triggers
    /// the events you want, or you'll race them.
    pub fn subscribe(&self) -> broadcast::Receiver<CdpEvent> {
        self.events.subscribe()
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
        let _ = self.outbound.send(Message::Text(frame.to_string()));
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
        if self
            .outbound
            .send(Message::Text(frame.to_string()))
            .is_err()
        {
            self.pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            return Err(BrowserError::Cdp("cdp writer gone".into()));
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
