//! Browser tier (DESIGN.md §3). The engine seam lives in [`engine`]; the
//! default impl is the hand-rolled CDP client ([`cdp`] + [`cdp_engine`]) driving
//! one Chromium ([`chromium`]) — **it never sends `Runtime.enable`**.

pub mod cdp;
pub mod cdp_engine;
pub mod chromium;
pub mod engine;
pub mod xvfb;

/// In-memory engine for tests. Public so `tests/` can reach it; not part of the
/// supported API.
#[doc(hidden)]
pub mod mock;

pub use cdp_engine::CdpEngine;
pub use engine::{
    BrowserContext, BrowserEngine, BrowserError, BrowserResult, ContextOptions, PageLoad, SniffHit,
    WaitFor,
};
