//! `GET/PATCH /v1/blocklist`, `POST/PATCH/DELETE /v1/blocklist/sources`,
//! `POST /v1/blocklist/refresh` — the runtime CRUD API a dashboard (mycelium)
//! uses to manage tracker/ad block-lists, in place of editing `config.toml`.

use serde_json::{json, Value};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use cobweb::config::Config;
use cobweb::state::AppState;

struct App {
    base: String,
    upstream: MockServer,
    _state_dir: tempfile::TempDir,
    http: wreq::Client,
}

impl App {
    async fn spawn() -> Self {
        Self::spawn_with_api_key(None).await
    }

    async fn spawn_with_api_key(api_key: Option<&str>) -> Self {
        let upstream = MockServer::start().await;
        let state_dir = tempfile::tempdir().unwrap();
        let api_key_line = api_key
            .map(|k| format!("api_key = \"{k}\"\n"))
            .unwrap_or_default();
        let cfg = Config::parse(&format!(
            r#"
            [server]
            port = 0
            browser_engine = "none"
            allow_private_targets = true
            {api_key_line}
            [jar]
            path = {jar_path:?}
            [egress.direct]
            proxy = ""
            [blocklist]
            state_path = {state_path:?}
            "#,
            jar_path = state_dir.path().join("jar"),
            state_path = state_dir.path().join("state.json"),
        ))
        .unwrap();

        let state = AppState::from_config(cfg).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = cobweb::serve_on(state, listener).await;
        });
        Self {
            base: format!("http://{addr}"),
            upstream,
            _state_dir: state_dir,
            http: wreq::Client::new(),
        }
    }

    async fn mount_list(&self, path_str: &str, body: &str) -> String {
        Mock::given(method("GET"))
            .and(path(path_str))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&self.upstream)
            .await;
        format!("{}{path_str}", self.upstream.uri())
    }

    async fn post(&self, p: &str, body: Value, api_key: Option<&str>) -> (u16, Value) {
        let mut req = self.http.post(format!("{}{p}", self.base)).json(&body);
        if let Some(k) = api_key {
            req = req.header("x-api-key", k);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    async fn get(&self, p: &str) -> (u16, Value) {
        let resp = self
            .http
            .get(format!("{}{p}", self.base))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    async fn patch(&self, p: &str, body: Value) -> (u16, Value) {
        let resp = self
            .http
            .patch(format!("{}{p}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    async fn delete(&self, p: &str) -> (u16, Value) {
        let resp = self
            .http
            .delete(format!("{}{p}", self.base))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json::<Value>().await.unwrap_or(Value::Null))
    }
}

#[tokio::test]
async fn full_lifecycle_add_toggle_delete() {
    let app = App::spawn().await;
    let list_url = app
        .mount_list("/hosts.txt", "0.0.0.0 tracker.example.com\n")
        .await;

    // Freshly started: disabled, no sources.
    let (s, body) = app.get("/v1/blocklist").await;
    assert_eq!(s, 200);
    assert_eq!(body["enabled"], json!(false));
    assert_eq!(body["sources"].as_array().unwrap().len(), 0);

    // Add a source: fetched immediately, no error, one domain.
    let (s, added) = app
        .post("/v1/blocklist/sources", json!({ "url": list_url }), None)
        .await;
    assert_eq!(s, 200, "{added}");
    assert!(added["last_error"].is_null(), "{added}");
    assert_eq!(added["domain_count"], json!(1));
    let id = added["id"].as_str().unwrap().to_string();

    // Master switch still off => still no patterns applied.
    let (_, status) = app.get("/v1/blocklist").await;
    assert_eq!(status["pattern_count"], json!(0));

    // Flip the master switch on.
    let (s, status) = app.patch("/v1/blocklist", json!({ "enabled": true })).await;
    assert_eq!(s, 200);
    assert_eq!(status["enabled"], json!(true));
    assert_eq!(
        status["pattern_count"],
        json!(2),
        "one domain -> 2 glob patterns"
    );

    // Disable just this one source: patterns drop to zero without any new fetch.
    let (s, view) = app
        .patch(
            &format!("/v1/blocklist/sources/{id}"),
            json!({ "enabled": false }),
        )
        .await;
    assert_eq!(s, 200);
    assert_eq!(view["enabled"], json!(false));
    let (_, status) = app.get("/v1/blocklist").await;
    assert_eq!(status["pattern_count"], json!(0));

    // Re-enable it: patterns come back from the still-cached domain list.
    app.patch(
        &format!("/v1/blocklist/sources/{id}"),
        json!({ "enabled": true }),
    )
    .await;
    let (_, status) = app.get("/v1/blocklist").await;
    assert_eq!(status["pattern_count"], json!(2));

    // Remove it entirely.
    let (s, del) = app.delete(&format!("/v1/blocklist/sources/{id}")).await;
    assert_eq!(s, 200);
    assert_eq!(del["removed"], json!(true));
    let (_, status) = app.get("/v1/blocklist").await;
    assert_eq!(status["sources"].as_array().unwrap().len(), 0);
    assert_eq!(status["pattern_count"], json!(0));
}

#[tokio::test]
async fn add_source_with_unreachable_url_is_kept_with_an_error() {
    let app = App::spawn().await;
    let (s, added) = app
        .post(
            "/v1/blocklist/sources",
            json!({ "url": format!("{}/missing.txt", app.upstream.uri()) }),
            None,
        )
        .await;
    assert_eq!(s, 200);
    assert!(!added["last_error"].is_null());
    assert_eq!(added["domain_count"], json!(0));

    let (_, status) = app.get("/v1/blocklist").await;
    assert_eq!(
        status["sources"].as_array().unwrap().len(),
        1,
        "kept despite the failed fetch"
    );
}

#[tokio::test]
async fn toggle_unknown_source_id_is_bad_request() {
    let app = App::spawn().await;
    let (s, body) = app
        .patch("/v1/blocklist/sources/nope", json!({ "enabled": true }))
        .await;
    assert_eq!(s, 400, "{body}");
}

#[tokio::test]
async fn manual_refresh_endpoint_updates_domain_counts() {
    let app = App::spawn().await;
    let list_url = app
        .mount_list("/hosts.txt", "0.0.0.0 a.example.com\n")
        .await;
    app.post("/v1/blocklist/sources", json!({ "url": list_url }), None)
        .await;
    app.patch("/v1/blocklist", json!({ "enabled": true })).await;

    let (s, status) = app.post("/v1/blocklist/refresh", json!({}), None).await;
    assert_eq!(s, 200);
    assert_eq!(status["sources"][0]["domain_count"], json!(1));
}

#[tokio::test]
async fn blocklist_routes_require_the_configured_api_key() {
    let app = App::spawn_with_api_key(Some("s3cret")).await;

    let (s, _) = app.get("/v1/blocklist").await;
    assert_eq!(s, 401, "no key provided");

    let resp = app
        .http
        .get(format!("{}/v1/blocklist", app.base))
        .header("x-api-key", "s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}
