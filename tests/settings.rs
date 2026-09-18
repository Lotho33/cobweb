//! `GET/PATCH /v1/settings` — the runtime CRUD API a dashboard (mycelium)
//! uses to tune DNS servers + timeout/TTL knobs in place of editing
//! `config.toml`.

use serde_json::{json, Value};
use tokio::net::TcpListener;

use cobweb::config::Config;
use cobweb::state::AppState;

struct App {
    base: String,
    _state_dir: tempfile::TempDir,
    http: wreq::Client,
}

impl App {
    async fn spawn() -> Self {
        Self::spawn_with_api_key(None).await
    }

    async fn spawn_with_api_key(api_key: Option<&str>) -> Self {
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
            [settings]
            state_path = {state_path:?}
            "#,
            jar_path = state_dir.path().join("jar"),
            state_path = state_dir.path().join("settings.json"),
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
            _state_dir: state_dir,
            http: wreq::Client::new(),
        }
    }

    async fn get(&self) -> (u16, Value) {
        let resp = self
            .http
            .get(format!("{}/v1/settings", self.base))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json::<Value>().await.unwrap_or(Value::Null))
    }

    async fn patch(&self, body: Value) -> (u16, Value) {
        let resp = self
            .http
            .patch(format!("{}/v1/settings", self.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json::<Value>().await.unwrap_or(Value::Null))
    }
}

#[tokio::test]
async fn get_returns_the_documented_defaults() {
    let app = App::spawn().await;
    let (s, body) = app.get().await;
    assert_eq!(s, 200);
    assert_eq!(body["dns_servers"], json!(["1.1.1.1", "1.0.0.1"]));
    assert_eq!(body["nav_timeout_ms"], json!(30_000));
    assert_eq!(body["jar_default_ttl_secs"], json!(2700));
    assert_eq!(body["jar_fail_streak"], json!(3));
    assert_eq!(body["flaresolverr_session_ttl_secs"], json!(1800));
    assert_eq!(body["idle_shutdown_secs"], json!(900));
}

#[tokio::test]
async fn patch_updates_only_the_given_fields_and_persists() {
    let app = App::spawn().await;
    let (s, body) = app
        .patch(json!({ "nav_timeout_ms": 5000, "jar_fail_streak": 7 }))
        .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["nav_timeout_ms"], json!(5000));
    assert_eq!(body["jar_fail_streak"], json!(7));
    assert_eq!(
        body["jar_default_ttl_secs"],
        json!(2700),
        "untouched field kept"
    );

    let (_, refetched) = app.get().await;
    assert_eq!(refetched, body, "GET reflects the PATCH immediately");
}

#[tokio::test]
async fn patch_dns_servers_accepts_ips_and_rejects_a_hostname() {
    let app = App::spawn().await;
    let (s, body) = app.patch(json!({ "dns_servers": ["9.9.9.9"] })).await;
    assert_eq!(s, 200);
    assert_eq!(body["dns_servers"], json!(["9.9.9.9"]));

    let (s, body) = app
        .patch(json!({ "dns_servers": ["not-an-ip.example.com"] }))
        .await;
    assert_eq!(s, 400, "{body}");

    // Rejected patch must not have clobbered the last-good value.
    let (_, after) = app.get().await;
    assert_eq!(after["dns_servers"], json!(["9.9.9.9"]));
}

#[tokio::test]
async fn patch_empty_dns_servers_falls_back_to_system_resolver() {
    let app = App::spawn().await;
    let (s, body) = app.patch(json!({ "dns_servers": [] })).await;
    assert_eq!(s, 200);
    assert_eq!(body["dns_servers"], json!([]));
}

#[tokio::test]
async fn settings_routes_require_the_configured_api_key() {
    let app = App::spawn_with_api_key(Some("s3cret")).await;

    let (s, _) = app.get().await;
    assert_eq!(s, 401, "no key provided");

    let resp = app
        .http
        .get(format!("{}/v1/settings", app.base))
        .header("x-api-key", "s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}
