//! Tier 4 — manual VNC solve (DESIGN.md §3, §6.1). `#[cfg(feature = "vnc")]`.
//!
//! `x11vnc` attaches to the same Xvfb display Chromium is on; a websocket
//! bridge carries RFB to the dashboard's noVNC. One session at a time.

pub mod bridge;
pub mod session;
pub mod x11vnc;

pub use session::{SessionInfo, SessionManager};
