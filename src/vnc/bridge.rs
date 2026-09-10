//! Pump bytes between the admin's noVNC websocket and x11vnc's RFB TCP socket.
//! RFB is a raw byte stream; noVNC carries it as binary websocket frames.

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
        while let Some(Ok(msg)) = ws_rx.next().await {
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
            match tcp_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let frame = Message::Binary(buf[..n].to_vec().into());
                    if ws_tx.send(frame).await.is_err() {
                        break;
                    }
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
