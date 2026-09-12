//! Pump bytes between the admin's noVNC websocket and x11vnc's RFB TCP socket.
//! RFB is a raw byte stream; noVNC carries it as binary websocket frames.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Close the bridge if neither side has sent anything for this long. A manual
/// VNC session has no idle timeout of its own otherwise — if the admin's
/// client vanishes without a clean close (a dropped Wi-Fi connection, a
/// crashed tab), the bridge task and its TCP connection to x11vnc would
/// otherwise live until the session itself times out or is closed explicitly.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub async fn run(ws: WebSocket, rfb_port: u16) {
    let tcp = match TcpStream::connect(("127.0.0.1", rfb_port)).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(rfb_port, error = %e, "vnc bridge: cannot reach x11vnc");
            return;
        }
    };
    let (mut tcp_rd, mut tcp_wr) = tcp.into_split();
    let (mut ws_tx, mut ws_rx) = ws.split();

    // noVNC -> x11vnc
    let to_vnc = async move {
        loop {
            let next = tokio::time::timeout(IDLE_TIMEOUT, ws_rx.next()).await;
            let msg = match next {
                Ok(Some(Ok(msg))) => msg,
                Ok(Some(Err(_))) | Ok(None) => break,
                Err(_) => {
                    tracing::info!("vnc bridge: idle timeout (client\u{2192}server)");
                    break;
                }
            };
            let stop = match msg {
                Message::Binary(b) => tcp_wr.write_all(&b).await.is_err(),
                Message::Text(t) => tcp_wr.write_all(t.as_bytes()).await.is_err(),
                Message::Close(_) => true,
                Message::Ping(_) | Message::Pong(_) => false,
            };
            if stop {
                break;
            }
        }
    };

    // x11vnc -> noVNC
    let to_ws = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let next = tokio::time::timeout(IDLE_TIMEOUT, tcp_rd.read(&mut buf)).await;
            match next {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => {
                    let frame = Message::Binary(buf[..n].to_vec().into());
                    if ws_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    tracing::info!("vnc bridge: idle timeout (server\u{2192}client)");
                    break;
                }
            }
        }
        let _ = ws_tx.close().await;
    };

    tokio::select! {
        _ = to_vnc => {}
        _ = to_ws => {}
    }
    tracing::debug!("vnc bridge closed");
}
