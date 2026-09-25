//! M2b: the hand-rolled CDP client + a real Chromium.
//!
//! The Chromium-driven tests skip themselves when no browser is on PATH (or
//! when `COBWEB_SKIP_BROWSER_TESTS` is set), so `cargo test` stays green on a
//! bare box and on hosted CI runners where a preinstalled headless Chrome
//! can't bring up CDP. The devcontainer runs them for real.

use std::sync::Arc;
use std::time::Duration;

use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use cobweb::blocklist::Blocklist;
use cobweb::browser::{BrowserEngine, CdpEngine, ContextOptions};
use cobweb::config::{BlocklistConfig, BrowserConfig};
use cobweb::egress::Egress;
use cobweb::pipeline::build_globset;

/// `[blocklist]` disabled — these tests exercise the CDP layer itself, not
/// tracker blocking.
fn no_blocklist() -> Arc<Blocklist> {
    Arc::new(Blocklist::new(BlocklistConfig::default()))
}

/// Structural guarantee: the CDP layer must never *call* the Runtime domain's
/// `enable` (DESIGN.md §3). Matches the quoted method name as it would appear in
/// a `call("Runtime.enable", …)`, so prose mentioning it is fine. Always runs.
#[test]
fn cdp_layer_never_enables_the_runtime_domain() {
    for (name, src) in [
        ("cdp.rs", include_str!("../src/browser/cdp.rs")),
        (
            "cdp_engine.rs",
            include_str!("../src/browser/cdp_engine.rs"),
        ),
        ("chromium.rs", include_str!("../src/browser/chromium.rs")),
    ] {
        assert!(
            !src.contains(r#""Runtime.enable""#),
            "{name} calls Runtime.enable"
        );
    }
}

fn have_chromium() -> bool {
    // Hosted CI runners (GitHub `ubuntu-latest`) ship `google-chrome-stable` on
    // PATH but its headless launch never brings CDP up in that sandbox. Let CI
    // opt out explicitly rather than fight the runner.
    if std::env::var_os("COBWEB_SKIP_BROWSER_TESTS").is_some() {
        return false;
    }
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                [
                    "chromium",
                    "chromium-browser",
                    "google-chrome",
                    "google-chrome-stable",
                ]
                .iter()
                .any(|b| dir.join(b).is_file())
            })
        })
        .unwrap_or(false)
}

fn headless_cfg() -> BrowserConfig {
    BrowserConfig::default()
}

async fn ctx_opts() -> ContextOptions {
    ContextOptions {
        egress: Egress::direct(),
        seed: None,
        user_agent: None,
        accept_language: None,
        block_resources: true,
        block_trackers: true,
    }
}

/// wiremock's `set_body_string` forces `text/plain`; Chromium then renders the
/// markup as text and no script runs. `set_body_raw` lets us pin `text/html`.
fn html_page(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.as_bytes().to_vec(), "text/html")
}

#[tokio::test]
async fn sniffs_a_url_a_page_script_fetches() {
    if !have_chromium() {
        eprintln!("skip sniffs_a_url_a_page_script_fetches: no chromium on PATH");
        return;
    }

    let upstream = MockServer::start().await;
    // The page pulls the manifest as a sub-resource — a real network request
    // for the CDP sniff to catch, without depending on headless timer behaviour.
    Mock::given(method("GET"))
        .and(path("/embed"))
        .respond_with(html_page(
            r#"<html><body>player
               <script>new Image().src='/media/master.m3u8';
                       fetch('/media/master.m3u8').catch(function(){});</script>
               </body></html>"#,
        ))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/media/master.m3u8"))
        .respond_with(ResponseTemplate::new(200).set_body_string("#EXTM3U"))
        .mount(&upstream)
        .await;

    let engine = CdpEngine::new(headless_cfg(), 2, 0, true, no_blocklist()); // 0 = no idle reaper
    engine.ensure_ready().await.expect("Chromium should launch");
    let mut cx = engine
        .acquire(ctx_opts().await)
        .await
        .expect("acquire context");

    let trigger = Url::parse(&format!("{}/embed", upstream.uri())).unwrap();
    let patterns = build_globset(&["*.m3u8".to_string()]).unwrap();

    let hit = cx
        .sniff(&trigger, &patterns, Duration::from_secs(20), None)
        .await
        .expect("sniff should catch the fetch");
    assert!(
        hit.url.as_str().ends_with("/media/master.m3u8"),
        "got {}",
        hit.url
    );

    cx.close().await;
    engine.shutdown().await;
}

#[tokio::test]
async fn navigate_returns_post_js_dom() {
    if !have_chromium() {
        eprintln!("skip navigate_returns_post_js_dom: no chromium on PATH");
        return;
    }

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/p"))
        .respond_with(html_page(
            r#"<html><body><div id="x">before</div>
               <script>document.getElementById('x').textContent = 'RAN_' + (2 * 21);</script>
               </body></html>"#,
        ))
        .mount(&upstream)
        .await;

    let engine = CdpEngine::new(headless_cfg(), 2, 0, true, no_blocklist()); // 0 = no idle reaper
    let mut cx = engine.acquire(ctx_opts().await).await.expect("acquire");

    let url = Url::parse(&format!("{}/p", upstream.uri())).unwrap();
    let page = cx
        .navigate(
            &url,
            cobweb::browser::WaitFor::Load,
            Duration::from_secs(15),
        )
        .await
        .expect("navigate");

    // "RAN_42" only exists if the script actually executed (the source says
    // "RAN_' + (2 * 21)") and we're reading the live DOM, not raw markup.
    assert!(
        page.html.contains("RAN_42"),
        "DOM was not post-JS: {}",
        page.html
    );
    assert!(!page.html.contains(">before<"));
    assert!(!page.challenge);
    assert_eq!(page.final_url.path(), "/p");

    cx.close().await;
    engine.shutdown().await;
}

#[tokio::test]
async fn eval_runs_in_an_isolated_world() {
    if !have_chromium() {
        eprintln!("skip eval_runs_in_an_isolated_world: no chromium on PATH");
        return;
    }

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/e"))
        .respond_with(html_page("<html><body>hi</body></html>"))
        .mount(&upstream)
        .await;

    let engine = CdpEngine::new(headless_cfg(), 2, 0, true, no_blocklist()); // 0 = no idle reaper
    let mut cx = engine.acquire(ctx_opts().await).await.expect("acquire");
    let url = Url::parse(&format!("{}/e", upstream.uri())).unwrap();

    let v = cx
        .eval(&url, "2 + 40", Duration::from_secs(10))
        .await
        .expect("eval");
    assert_eq!(v.as_i64(), Some(42));

    // webdriver flag is patched by the on-new-document script
    let wd = cx
        .eval(&url, "navigator.webdriver", Duration::from_secs(10))
        .await
        .expect("eval webdriver");
    assert_eq!(wd.as_bool(), Some(false));

    cx.close().await;
    engine.shutdown().await;
}

#[tokio::test]
async fn storage_state_captures_set_cookie() {
    if !have_chromium() {
        eprintln!("skip storage_state_captures_set_cookie: no chromium on PATH");
        return;
    }

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/set"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "sess=abc123; Path=/; Max-Age=3600")
                .set_body_raw(b"<html><body>ok</body></html>".to_vec(), "text/html"),
        )
        .mount(&upstream)
        .await;

    let engine = CdpEngine::new(headless_cfg(), 2, 0, true, no_blocklist());
    let mut cx = engine.acquire(ctx_opts().await).await.expect("acquire");
    let url = Url::parse(&format!("{}/set", upstream.uri())).unwrap();
    cx.navigate(
        &url,
        cobweb::browser::WaitFor::Load,
        Duration::from_secs(15),
    )
    .await
    .expect("navigate");

    let state = cx.storage_state().await.expect("storage_state");
    let sess = state
        .cookies
        .iter()
        .find(|c| c.name == "sess")
        .unwrap_or_else(|| panic!("no `sess` cookie in {:?}", state.cookies));
    assert_eq!(sess.value, "abc123");
    assert!(sess.expires > 0.0, "Max-Age should give a real expiry");

    cx.close().await;
    engine.shutdown().await;
}

// Regression for the browser tier's SSRF guard (Fetch domain): with private
// targets NOT allowed, navigating to the loopback mock must be refused. The
// other tests here run with allow_private_targets = true precisely because of
// this guard — before, they used `false` and silently failed once Chromium
// was present (and skipped without it).
#[tokio::test]
async fn browser_guard_refuses_private_targets() {
    if !have_chromium() {
        eprintln!("skip browser_guard_refuses_private_targets: no chromium on PATH");
        return;
    }
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/p"))
        .respond_with(html_page("<html><body>internal</body></html>"))
        .mount(&upstream)
        .await;

    let engine = CdpEngine::new(headless_cfg(), 2, 0, false, no_blocklist());
    let mut cx = engine.acquire(ctx_opts().await).await.expect("acquire");
    let url = Url::parse(&format!("{}/p", upstream.uri())).unwrap();
    let res = cx
        .navigate(
            &url,
            cobweb::browser::WaitFor::Load,
            Duration::from_secs(15),
        )
        .await;
    assert!(
        res.is_err() || !res.as_ref().unwrap().html.contains("internal"),
        "loopback page loaded with the guard on"
    );
    cx.close().await;
    engine.shutdown().await;
}

// Even when private targets are allowed, a page redirecting to the cloud
// metadata address must not get there (hard-blocked range).
#[tokio::test]
async fn browser_guard_refuses_redirect_to_metadata() {
    if !have_chromium() {
        eprintln!("skip browser_guard_refuses_redirect_to_metadata: no chromium on PATH");
        return;
    }
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hop"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
        )
        .mount(&upstream)
        .await;

    let engine = CdpEngine::new(headless_cfg(), 2, 0, true, no_blocklist());
    let mut cx = engine.acquire(ctx_opts().await).await.expect("acquire");
    let url = Url::parse(&format!("{}/hop", upstream.uri())).unwrap();
    let res = cx
        .navigate(
            &url,
            cobweb::browser::WaitFor::Load,
            Duration::from_secs(15),
        )
        .await;
    if let Ok(page) = &res {
        assert_ne!(
            page.final_url.host_str(),
            Some("169.254.169.254"),
            "browser followed the redirect to the metadata address"
        );
    }
    cx.close().await;
    engine.shutdown().await;
}
