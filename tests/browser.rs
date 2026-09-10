//! M2a: tier-3 (browser) wiring, driven by the in-memory `MockEngine` — no
//! Chromium. Proves the fast-path -> tier-3 escalation and the /v1/sniff,
//! /v1/eval handlers.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use cobweb::browser::mock::{MockEngine, SniffScript};
use cobweb::browser::BrowserEngine;
use cobweb::config::Config;
use cobweb::egress::EgressRegistry;
use cobweb::fastpath::WreqClient;
use cobweb::jar::Jar;
use cobweb::state::AppState;

struct App {
    base: String,
    upstream: MockServer,
    jar_dir: tempfile::TempDir,
    engine: Arc<MockEngine>,
    http: wreq::Client,
}

impl App {
    async fn spawn(engine: MockEngine) -> Self {
        let upstream = MockServer::start().await;
        let jar_dir = tempfile::tempdir().unwrap();
        let cfg = Config::parse(&format!(
            "[server]\nport = 0\n[jar]\npath = {:?}\n[egress.direct]\nproxy = \"\"\n",
            jar_dir.path()
        ))
        .unwrap();
        let egress = EgressRegistry::from_config(&cfg).unwrap();
        let jar = Jar::new(jar_dir.path().to_path_buf(), Duration::from_secs(2700), 3);
        let engine = Arc::new(engine);
        let state = AppState::new(
            cfg,
            egress,
            jar,
            Arc::new(WreqClient::new()),
            Some(engine.clone() as Arc<dyn BrowserEngine>),
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
            engine,
            http: wreq::Client::new(),
        }
    }

    /// Mount a plain (no-manifest) page at `/e` so the fast path always escalates.
    async fn plain_page(&self) -> String {
        Mock::given(method("GET"))
            .and(path("/e"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<html><body>spa shell</body></html>"),
            )
            .mount(&self.upstream)
            .await;
        format!("{}/e", self.upstream.uri())
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        (
            resp.status().as_u16(),
            resp.json::<Value>().await.unwrap_or(Value::Null),
        )
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap();
        (
            resp.status().as_u16(),
            resp.json::<Value>().await.unwrap_or(Value::Null),
        )
    }

    fn jar_files(&self) -> usize {
        std::fs::read_dir(self.jar_dir.path())
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
                    .count()
            })
            .unwrap_or(0)
    }
}

fn hit(url: &str) -> SniffScript {
    SniffScript::Hit {
        url: url.to_string(),
        headers: vec![
            ("user-agent".into(), "Mozilla/5.0 (X11) Chrome/147".into()),
            ("referer".into(), "https://example.com/movie/550".into()),
            ("x-requested-with".into(), "XMLHttpRequest".into()),
        ],
    }
}

#[tokio::test]
async fn fast_path_fails_then_browser_sniff_resolves() {
    let app = App::spawn(MockEngine::with_sniff(hit(
        "https://cdn.example/live/master.m3u8?t=1",
    )))
    .await;
    let url = app.plain_page().await;

    let (status, body) = app.post("/v1/resolve", json!({ "url": url })).await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["via_tier"], json!("browser"));
    assert_eq!(body["kind"], json!("hls"));
    assert!(body["stream_url"]
        .as_str()
        .unwrap()
        .ends_with("/live/master.m3u8?t=1"));
    // safelisted replay headers came through; hop-by-hop junk did not
    assert_eq!(
        body["headers"]["user-agent"],
        json!("Mozilla/5.0 (X11) Chrome/147")
    );
    assert_eq!(body["headers"]["x-requested-with"], json!("XMLHttpRequest"));

    assert_eq!(app.engine.acquired(), 1);
    assert_eq!(app.jar_files(), 1, "browser solve should persist the jar");
}

#[tokio::test]
async fn browser_challenge_bubbles_up_as_needs_manual_solve() {
    let app = App::spawn(MockEngine::with_sniff(SniffScript::Challenge)).await;
    let url = app.plain_page().await;

    let (status, body) = app.post("/v1/resolve", json!({ "url": url })).await;
    assert_eq!(status, 422, "body: {body}");
    assert_eq!(body["kind"], json!("needs_manual_solve"));
    assert_eq!(body["needs_manual_solve"], json!(true));
    assert_eq!(body["domain"], json!("127.0.0.1"));
}

#[tokio::test]
async fn browser_no_match_is_not_resolved() {
    let app = App::spawn(MockEngine::with_sniff(SniffScript::NoMatch)).await;
    let url = app.plain_page().await;

    let (status, body) = app.post("/v1/resolve", json!({ "url": url })).await;
    assert_eq!(status, 422, "body: {body}");
    assert_eq!(body["kind"], json!("not_resolved"));
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("after the browser sniff"));
}

#[tokio::test]
async fn fast_mode_never_touches_the_browser() {
    let app = App::spawn(MockEngine::with_sniff(hit("https://cdn.example/x.m3u8"))).await;
    let url = app.plain_page().await;

    let (status, body) = app
        .post("/v1/resolve", json!({ "url": url, "mode": "fast" }))
        .await;
    assert_eq!(status, 422, "body: {body}");
    assert_eq!(body["kind"], json!("not_resolved"));
    assert_eq!(app.engine.acquired(), 0);
}

#[tokio::test]
async fn sniff_endpoint_returns_intercepted_url_and_headers() {
    let app = App::spawn(MockEngine::with_sniff(hit(
        "https://cdn.example/s/index.m3u8",
    )))
    .await;
    let trigger = app.plain_page().await;

    let (status, body) = app
        .post(
            "/v1/sniff",
            json!({ "trigger_url": trigger, "url_pattern": "m3u8" }),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    assert!(body["intercepted_url"]
        .as_str()
        .unwrap()
        .ends_with("/s/index.m3u8"));
    assert_eq!(
        body["headers"]["referer"],
        json!("https://example.com/movie/550")
    );
}

#[tokio::test]
async fn eval_endpoint_returns_result_string() {
    let app =
        App::spawn(MockEngine::with_sniff(SniffScript::NoMatch).eval_result(json!("42"))).await;

    let (status, body) = app
        .post(
            "/v1/eval",
            json!({ "url": "https://example.com/movie/550", "js": "6*7" }),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["result"], json!("42"));
}

#[tokio::test]
async fn health_reports_the_mock_engine() {
    let app = App::spawn(MockEngine::default()).await;
    let (status, body) = app.get("/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["engine"], json!("mock"));
    assert_eq!(body["fast_engine"], json!("wreq"));
}

#[tokio::test]
async fn engine_unavailable_is_a_clean_error() {
    let app = App::spawn(MockEngine::unavailable()).await;
    let url = app.plain_page().await;

    let (status, body) = app.post("/v1/resolve", json!({ "url": url })).await;
    assert_eq!(status, 502, "body: {body}");
    assert_eq!(body["kind"], json!("browser"));
}
