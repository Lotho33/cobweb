//! `cobweb` — browser/extractor sidecar. See `DESIGN.md`.
//!
//! The crate is a library + a thin binary (`src/main.rs`) so integration tests
//! in `tests/` can build an [`state::AppState`] and drive the router directly.

pub mod api;
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
pub mod ssrf;
pub mod state;
#[cfg(feature = "vnc")]
pub mod vnc;
#[cfg(feature = "ytdlp")]
pub mod ytdlp;

pub use error::{CobwebError, Result};
pub use state::AppState;

use tokio::net::TcpListener;

/// Serve the API on an already-bound listener until the process ends.
/// Tests bind `127.0.0.1:0` and pass the listener here.
pub async fn serve_on(state: AppState, listener: TcpListener) -> Result<()> {
    let app = api::router(state);
    axum::serve(listener, app)
        .await
        .map_err(|e| CobwebError::Other(anyhow::anyhow!("server error: {e}")))
}

/// Serve with graceful shutdown when `shutdown` resolves.
pub async fn serve_on_until<F>(state: AppState, listener: TcpListener, shutdown: F) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let app = api::router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| CobwebError::Other(anyhow::anyhow!("server error: {e}")))
}
