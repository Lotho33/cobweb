//! `cobweb` — browser/extractor sidecar. See `DESIGN.md`.
//!
//! The crate is a library + a thin binary (`src/main.rs`) so integration tests
//! in `tests/` can build an [`state::AppState`] and drive the router directly.

pub mod api;
pub mod blocklist;
pub mod browser;
pub mod config;
pub mod egress;
pub mod error;
pub mod fastpath;
#[cfg(feature = "flaresolverr")]
pub mod flaresolverr_client;
pub mod jar;
pub mod metrics;
pub mod pipeline;
pub mod settings;
pub mod ssrf;
pub mod state;
pub mod util;
#[cfg(feature = "ytdlp")]
pub mod ytdlp;

pub use error::{CobwebError, Result};
pub use state::AppState;

use std::future::IntoFuture;

use tokio::net::TcpListener;

/// Serve the API on an already-bound listener until the process ends.
/// Tests bind `127.0.0.1:0` and pass the listener here.
pub async fn serve_on(state: AppState, listener: TcpListener) -> Result<()> {
    let app = api::router(state);
    axum::serve(listener, app)
        .await
        .map_err(|e| CobwebError::Other(anyhow::anyhow!("server error: {e}")))
}

/// How long to wait, once the shutdown signal fires, for in-flight connections
/// to drain on their own before forcing the listener closed. Without this a
/// single long-lived connection — e.g. a `/v1/fetch` streaming a large body —
/// can wedge a restart/redeploy indefinitely: `axum`'s graceful
/// shutdown waits for every open connection to finish on its own, with no
/// built-in ceiling.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// Serve with graceful shutdown when `shutdown` resolves. Once it does, new
/// connections stop being accepted and open ones get [`SHUTDOWN_GRACE`] to
/// finish; past that the listener (and every socket riding it) is dropped
/// outright rather than waiting forever, so a very long in-flight download
/// can't block teardown of the Chromium children that follow.
pub async fn serve_on_until<F>(state: AppState, listener: TcpListener, shutdown: F) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let app = api::router(state);
    let (grace_tx, grace_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_then_arm_grace = async move {
        shutdown.await;
        let _ = grace_tx.send(());
    };
    // `WithGracefulShutdown` only implements `IntoFuture` (that's what powers
    // a plain `.await` on it); `tokio::select!` polls its branches as actual
    // `Future`s, so it needs the conversion spelled out explicitly.
    let serve_fut = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_then_arm_grace)
        .into_future();
    tokio::pin!(serve_fut);

    tokio::select! {
        res = &mut serve_fut => res.map_err(|e| CobwebError::Other(anyhow::anyhow!("server error: {e}"))),
        _ = async move {
            // Only start the grace clock once the shutdown signal has actually
            // fired — this branch must never race the server's normal (long)
            // uptime.
            let _ = grace_rx.await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => {
            tracing::warn!(
                grace_secs = SHUTDOWN_GRACE.as_secs(),
                "shutdown grace period elapsed with connections still open; forcing the \
                 listener closed so teardown (Chromium) can proceed"
            );
            Ok(())
        }
    }
}
