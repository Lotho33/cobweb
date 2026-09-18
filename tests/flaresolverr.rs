//! M4: FlareSolverr both directions.
//!  - inbound: `POST /v1` runs the (mock) browser tier and answers FS-shaped
//!  - outbound: an unsolved challenge is delegated to an external FS (wiremock)
//!    and the browser tier is retried with the cookies it returned

#![cfg(feature = "flaresolverr")]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use cobweb::blocklist::Blocklist;
use cobweb::browser::mock::{MockEngine, SniffScript};
use cobweb::browser::BrowserEngine;
use cobweb::config::{BlocklistConfig, Config, SettingsConfig};
use cobweb::egress::EgressRegistry;
use cobweb::fastpath::WreqClient;
use cobweb::jar::Jar;
use cobweb::settings::RuntimeSettings;
use cobweb::state::AppState;

struct App {
    base: String,
    upstream: MockServer,
    jar_dir: tempfile::TempDir,
    http: wreq::Client,
}

impl App {
    async fn spawn(engine: Option<MockEngine>, fs_endpoint: Option<String>) -> Self {
        let upstream = MockServer::start().await;
        let jar_dir = tempfile::tempdir().unwrap();
        let fs_line = match fs_endpoint {
            Some(e) => format!("[flaresolverr]\nendpoint = \"{e}\"\n"),
            None => String::new(),
        };
        let cfg = Config::parse(&format!(
            "[server]\nport = 0\nallow_private_targets = true\n[jar]\npath = {:?}\n[egress.direct]\nproxy = \"\"\n{fs_line}",
            jar_dir.path()
        ))
        .unwrap();

        let egress = EgressRegistry::from_config(&cfg).unwrap();
        let jar = Jar::new(jar_dir.path().to_path_buf(), Duration::from_secs(2700), 3);
        let browser = engine.map(|e| Arc::new(e) as Arc<dyn BrowserEngine>);
        let settings = Arc::new(RuntimeSettings::new(SettingsConfig::default()));
        let state = AppState::new(
            cfg,
            egress,
            jar,
            Arc::new(WreqClient::new(true, settings.clone())),
            browser,
            Arc::new(Blocklist::new(BlocklistConfig::default())),
            settings,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = cobweb::serve_on(state, listener).await;
        });
        Self {
            base: format!("http://{addr}"),
            upstream,
            jar_dir,
            http: wreq::Client::new(),
        }
    }

    async fn v1(&self, body: Value) -> Value {
        self.http
            .post(format!("{}/v1", self.base))
            .json(&body)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    }

    fn jar_files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.jar_dir.path())
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(".json"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

// ─── inbound ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn inbound_request_get_returns_flaresolverr_shape() {
    let engine = MockEngine::default().nav_html("<html><body>real page</body></html>");
    let app = App::spawn(Some(engine), None).await;

    let out = app
        .v1(json!({ "cmd": "request.get", "url": "https://example.com/x", "maxTimeout": 20000 }))
        .await;

    assert_eq!(out["status"], json!("ok"), "{out}");
    assert_eq!(out["solution"]["status"], json!(200));
    assert!(out["solution"]["response"]
        .as_str()
        .unwrap()
        .contains("real page"));
    assert!(out["solution"]["userAgent"]
        .as_str()
        .unwrap()
        .contains("Chrome"));
    assert!(out["version"].as_str().unwrap().starts_with("cobweb-"));
    // the mock's storage cookie made it into the solution
    let names: Vec<_> = out["solution"]["cookies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"cf_clearance"));
}

#[tokio::test]
async fn inbound_request_get_on_challenge_is_an_error() {
    let engine = MockEngine::with_sniff(SniffScript::Challenge); // navigate() flags challenge
    let app = App::spawn(Some(engine), None).await;

    let out = app
        .v1(json!({ "cmd": "request.get", "url": "https://example.com/blocked" }))
        .await;
    assert_eq!(out["status"], json!("error"), "{out}");
    assert!(
        out["solution"].is_object(),
        "challenge still returns the page"
    );
}

#[tokio::test]
async fn inbound_without_a_browser_is_an_error() {
    let app = App::spawn(None, None).await;
    let out = app
        .v1(json!({ "cmd": "request.get", "url": "https://example.com/" }))
        .await;
    assert_eq!(out["status"], json!("error"));
    assert!(out["message"].as_str().unwrap().contains("chromium"));
}

#[tokio::test]
async fn inbound_sessions_lifecycle() {
    let app = App::spawn(Some(MockEngine::default()), None).await;

    let c = app
        .v1(json!({ "cmd": "sessions.create", "session": "acme" }))
        .await;
    assert_eq!(c["status"], json!("ok"));
    assert_eq!(c["session"], json!("acme"));

    let l = app.v1(json!({ "cmd": "sessions.list" })).await;
    assert_eq!(l["sessions"], json!(["acme"]));

    let d = app
        .v1(json!({ "cmd": "sessions.destroy", "session": "acme" }))
        .await;
    assert_eq!(d["status"], json!("ok"));

    let l = app.v1(json!({ "cmd": "sessions.list" })).await;
    assert_eq!(l["sessions"], json!([]));
}

// ─── outbound (tier 3b) ────────────────────────────────────────────────────

#[tokio::test]
async fn outbound_delegate_solves_then_browser_retry_wins() {
    // external FlareSolverr: returns a cf_clearance cookie.
    let fs = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "message": "",
            "solution": {
                "url": "https://vix.example/",
                "status": 200,
                "headers": {},
                "response": "<html>ok</html>",
                "userAgent": "Mozilla/5.0 FS",
                "cookies": [
                    { "name": "cf_clearance", "value": "from-flaresolverr", "domain": ".vix.example", "path": "/", "secure": true, "httpOnly": true }
                ]
            }
        })))
        .mount(&fs)
        .await;

    // browser tier: challenge on the first sniff, hit on the retry.
    let engine = MockEngine::with_sniffs(vec![
        SniffScript::Challenge,
        SniffScript::Hit {
            url: "https://cdn.vix.example/master.m3u8".into(),
            headers: vec![("referer".into(), "https://vix.example/".into())],
        },
    ]);
    let app = App::spawn(Some(engine), Some(fs.uri())).await;

    // fast path must escalate: serve a Cloudflare interstitial.
    Mock::given(method("GET"))
        .and(path("/e"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("server", "cloudflare")
                .set_body_string("<title>Just a moment...</title>"),
        )
        .mount(&app.upstream)
        .await;

    let (status, body) = {
        let resp = app
            .http
            .post(format!("{}/v1/resolve", app.base))
            .json(&json!({ "url": format!("{}/e", app.upstream.uri()), "mode": "auto" }))
            .send()
            .await
            .unwrap();
        (resp.status().as_u16(), resp.json::<Value>().await.unwrap())
    };

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["via_tier"], json!("flaresolverr"));
    assert!(body["stream_url"]
        .as_str()
        .unwrap()
        .ends_with("/master.m3u8"));

    // the delegate's cookie is now in the jar
    let files = app.jar_files();
    assert_eq!(files.len(), 1, "{files:?}");
    let jar = std::fs::read_to_string(app.jar_dir.path().join(&files[0])).unwrap();
    assert!(jar.contains("from-flaresolverr"), "jar: {jar}");
}
