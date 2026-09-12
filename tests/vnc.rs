//! M3: the manual VNC solve session. `SessionManager` over the mock engine for
//! the fast checks; a real Chromium + x11vnc for the full round-trip (skips
//! itself when the binaries aren't there).

#![cfg(feature = "vnc")]

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use cobweb::browser::mock::MockEngine;
use cobweb::browser::{BrowserEngine, CdpEngine};
use cobweb::config::{BrowserConfig, Config};
use cobweb::egress::EgressRegistry;
use cobweb::jar::Jar;
use cobweb::vnc::SessionManager;

fn on_path(bin: &str) -> bool {
    // Same CI opt-out as tests/cdp.rs: the full round-trip needs a working
    // headed Chromium, which hosted runners can't provide.
    if std::env::var_os("COBWEB_SKIP_BROWSER_TESTS").is_some() {
        return false;
    }
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

fn manager(engine: Arc<dyn BrowserEngine>) -> (TempDir, SessionManager) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::parse(&format!(
        "[jar]\npath = {:?}\n[egress.direct]\nproxy = \"\"\n",
        dir.path()
    ))
    .unwrap();
    let jar = Arc::new(Jar::new(
        dir.path().to_path_buf(),
        Duration::from_secs(2700),
        3,
    ));
    let egress = Arc::new(EgressRegistry::from_config(&cfg).unwrap());
    (dir, SessionManager::new(engine, jar, egress, true))
}

#[tokio::test]
async fn start_fails_cleanly_without_a_display() {
    let (_d, mgr) = manager(Arc::new(MockEngine::default()));
    let err = mgr
        .start("https://example.com/", None, None)
        .await
        .unwrap_err();
    // MockEngine has no X display.
    assert_eq!(err.kind(), "browser", "{err}");
    assert_eq!(mgr.current().await.id, "");
}

#[tokio::test]
async fn full_session_roundtrip() {
    if !(on_path("chromium") && on_path("x11vnc") && on_path("Xvfb")) {
        eprintln!("skip full_session_roundtrip: need chromium + x11vnc + Xvfb");
        return;
    }

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/challenge"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "set-cookie",
                    "cf_clearance=solved-by-hand; Path=/; Max-Age=3600",
                )
                .set_body_raw(b"<html><body>solve me</body></html>".to_vec(), "text/html"),
        )
        .mount(&upstream)
        .await;

    let engine: Arc<dyn BrowserEngine> = Arc::new(CdpEngine::new(
        BrowserConfig {
            xvfb: true,
            ..Default::default()
        },
        2,
        0,
        false,
    ));
    let (dir, mgr) = manager(engine.clone());
    let url = format!("{}/challenge", upstream.uri());

    let info = mgr.start(&url, None, None).await.expect("session start");
    assert!(!info.id.is_empty());
    assert!(!info.vnc_token.is_empty());
    assert_eq!(mgr.current().await.id, info.id);

    // one at a time
    let again = mgr.start(&url, None, None).await.unwrap_err();
    assert_eq!(again.kind(), "conflict");

    // the bridge can find the RFB port only with the right id *and* token
    assert!(mgr.rfb_port(&info.id, &info.vnc_token).await.is_some());
    assert!(mgr.rfb_port(&info.id, "wrong-token").await.is_none());
    assert!(mgr.rfb_port("bogus", &info.vnc_token).await.is_none());

    mgr.close(&info.id, true).await.expect("session close");
    assert_eq!(mgr.current().await.id, "");

    // the jar picked up the cookie the "solve" set
    let jar_file = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .expect("a jar file was written");
    let contents = std::fs::read_to_string(jar_file.path()).unwrap();
    assert!(contents.contains("cf_clearance"), "jar: {contents}");

    engine.shutdown().await;
}
