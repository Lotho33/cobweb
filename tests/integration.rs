//! End-to-end tests for M1: HTTP surface + fast-path pipeline + jar round-trip.
//! No browser, no network beyond a local `wiremock` upstream.

use std::path::Path;

use serde_json::{json, Value};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use cobweb::config::Config;
use cobweb::state::AppState;

struct TestApp {
    /// Base URL of the running cobweb instance.
    base: String,
    /// The mocked "embed provider".
    upstream: MockServer,
    jar_dir: tempfile::TempDir,
    http: wreq::Client,
}

impl TestApp {
    async fn spawn() -> Self {
        Self::spawn_inner(true).await
    }

    /// Like [`spawn`], but with the SSRF guard live (`allow_private_targets =
    /// false`), so the mock upstream on loopback is *not* reachable — used only
    /// by the guard tests.
    async fn spawn_guarded() -> Self {
        Self::spawn_inner(false).await
    }

    async fn spawn_inner(allow_private_targets: bool) -> Self {
        let upstream = MockServer::start().await;
        let jar_dir = tempfile::tempdir().unwrap();
        let cfg = Config::parse(&format!(
            r#"
            [server]
            port = 0
            browser_engine = "none"
            allow_private_targets = {allow_private_targets}
            [jar]
            path = {:?}
            [egress.direct]
            proxy = ""
            "#,
            jar_dir.path()
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
            jar_dir,
            http: wreq::Client::new(),
        }
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let v = resp.json::<Value>().await.unwrap_or(Value::Null);
        (status, v)
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let v = resp.json::<Value>().await.unwrap_or(Value::Null);
        (status, v)
    }

    async fn get_text(&self, path: &str) -> (u16, String) {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.text().await.unwrap_or_default())
    }

    async fn delete(&self, path: &str) -> (u16, Value) {
        let resp = self
            .http
            .delete(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let v = resp.json::<Value>().await.unwrap_or(Value::Null);
        (status, v)
    }

    /// POST that returns the raw response: (status, header lookup fn input as a
    /// map, body bytes).
    async fn post_raw(
        &self,
        path: &str,
        body: Value,
    ) -> (u16, std::collections::HashMap<String, String>, Vec<u8>) {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let bytes = resp.bytes().await.unwrap_or_default().to_vec();
        (status, headers, bytes)
    }

    fn jar_files(&self) -> Vec<String> {
        list_json_files(self.jar_dir.path())
    }
}

fn list_json_files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
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

#[tokio::test]
async fn health_reports_engine_none_and_wreq_fastpath() {
    let app = TestApp::spawn().await;
    let (status, body) = app.get("/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["ready"], json!(true));
    assert_eq!(body["engine"], json!("none"));
    assert_eq!(body["fast_engine"], json!("wreq"));
    assert!(body["egress_profiles"]
        .as_array()
        .unwrap()
        .contains(&json!("direct")));
}

#[tokio::test]
async fn resolve_finds_hls_on_fast_path_and_writes_jar() {
    let app = TestApp::spawn().await;
    let stream = format!("{}/hls/master.m3u8?token=abc", app.upstream.uri());
    let page = format!(
        r#"<html><head><script>
           var setup = {{"file":"{stream}","type":"hls"}};
        </script></head><body>player</body></html>"#
    );
    Mock::given(method("GET"))
        .and(path("/embed/movie/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page))
        .mount(&app.upstream)
        .await;

    let (status, body) = app
        .post(
            "/v1/resolve",
            json!({ "url": format!("{}/embed/movie/42", app.upstream.uri()) }),
        )
        .await;

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["kind"], json!("hls"));
    assert_eq!(body["via_tier"], json!("fastpath"));
    assert!(body["stream_url"]
        .as_str()
        .unwrap()
        .ends_with("/hls/master.m3u8?token=abc"));
    // headers is an object; referer should point back at the embed page.
    assert!(body["headers"]["referer"]
        .as_str()
        .unwrap()
        .contains("/embed/movie/42"));

    // jar entry persisted for (127.0.0.1, direct)
    let files = app.jar_files();
    assert_eq!(files.len(), 1, "expected one jar file, got {files:?}");
    assert!(files[0].starts_with("127.0.0.1__direct"));
}

#[tokio::test]
async fn resolve_on_cloudflare_challenge_asks_for_manual_solve() {
    let app = TestApp::spawn().await;
    Mock::given(method("GET"))
        .and(path("/embed/blocked"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("server", "cloudflare")
                .set_body_string(
                    "<title>Just a moment...</title><div class=\"cf-browser-verification\"></div>",
                ),
        )
        .mount(&app.upstream)
        .await;

    let (status, body) = app
        .post(
            "/v1/resolve",
            json!({ "url": format!("{}/embed/blocked", app.upstream.uri()) }),
        )
        .await;

    assert_eq!(status, 422, "body: {body}");
    assert_eq!(body["kind"], json!("needs_manual_solve"));
    assert_eq!(body["needs_manual_solve"], json!(true));
    assert_eq!(body["domain"], json!("127.0.0.1"));
}

#[tokio::test]
async fn resolve_fast_mode_without_a_stream_fails_fast() {
    let app = TestApp::spawn().await;
    Mock::given(method("GET"))
        .and(path("/embed/plain"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body>no stream here</body></html>"),
        )
        .mount(&app.upstream)
        .await;

    let (status, body) = app
        .post(
            "/v1/resolve",
            json!({ "url": format!("{}/embed/plain", app.upstream.uri()), "mode": "fast" }),
        )
        .await;

    assert_eq!(status, 422, "body: {body}");
    assert_eq!(body["kind"], json!("not_resolved"));
}

#[tokio::test]
async fn navigate_returns_html_and_final_url() {
    let app = TestApp::spawn().await;
    Mock::given(method("GET"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>hi</body></html>"))
        .mount(&app.upstream)
        .await;

    let (status, body) = app
        .post(
            "/v1/navigate",
            json!({ "url": format!("{}/page", app.upstream.uri()) }),
        )
        .await;

    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["html"], json!("<html><body>hi</body></html>"));
    assert!(body["final_url"].as_str().unwrap().ends_with("/page"));
}

#[tokio::test]
async fn unknown_named_egress_is_a_400() {
    let app = TestApp::spawn().await;
    let (status, body) = app
        .post(
            "/v1/resolve",
            json!({ "url": "https://example.com/x", "egress": "ghost" }),
        )
        .await;
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(body["kind"], json!("unknown_egress"));
}

#[tokio::test]
async fn jar_list_and_delete_roundtrip() {
    let app = TestApp::spawn().await;
    let stream = format!("{}/s/out.m3u8", app.upstream.uri());
    Mock::given(method("GET"))
        .and(path("/e"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!(r#"<script>source: "{stream}"</script>"#)),
        )
        .mount(&app.upstream)
        .await;

    let (s, _) = app
        .post(
            "/v1/resolve",
            json!({ "url": format!("{}/e", app.upstream.uri()) }),
        )
        .await;
    assert_eq!(s, 200);

    let (s, rows) = app.get("/v1/jar").await;
    assert_eq!(s, 200);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["domain"], json!("127.0.0.1"));
    assert_eq!(rows[0]["egress"], json!("direct"));
    assert_eq!(rows[0]["stale"], json!(false));

    let (s, body) = app.delete("/v1/jar/127.0.0.1?egress=direct").await;
    assert_eq!(s, 200, "body: {body}");
    assert_eq!(body["removed"], json!(true));
    assert!(app.jar_files().is_empty());
}

#[tokio::test]
async fn browser_endpoints_need_the_engine_when_it_is_off() {
    // This app runs browser_engine = "none".
    let app = TestApp::spawn().await;
    for (p, b) in [
        ("/v1/eval", json!({ "url": "https://x/", "js": "1" })),
        (
            "/v1/sniff",
            json!({ "trigger_url": "https://x/", "url_pattern": "*.m3u8" }),
        ),
    ] {
        let (status, body) = app.post(p, b).await;
        assert_eq!(status, 422, "{p} body: {body}");
        assert_eq!(body["kind"], json!("needs_browser"), "{p}");
    }
}

#[tokio::test]
async fn flaresolverr_route_errors_without_a_browser() {
    let app = TestApp::spawn().await;
    let (status, body) = app
        .post("/v1", json!({ "cmd": "request.get", "url": "https://x/" }))
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], json!("error"));
    assert!(body["version"].as_str().unwrap().starts_with("cobweb-"));
}

#[tokio::test]
async fn metrics_endpoint_counts_a_fast_path_resolve() {
    let app = TestApp::spawn().await;
    let stream = format!("{}/hls/master.m3u8", app.upstream.uri());
    Mock::given(method("GET"))
        .and(path("/embed/m"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!(r#"<script>file: "{stream}"</script>"#)),
        )
        .mount(&app.upstream)
        .await;

    // before: nothing resolved yet.
    let (s, body) = app.get_text("/metrics").await;
    assert_eq!(s, 200);
    assert!(body.contains("cobweb_resolve_ok_total 0"), "body:\n{body}");
    assert!(body.contains("cobweb_uptime_seconds"));

    let (s, _) = app
        .post(
            "/v1/resolve",
            json!({ "url": format!("{}/embed/m", app.upstream.uri()) }),
        )
        .await;
    assert_eq!(s, 200);

    let (s, body) = app.get_text("/metrics").await;
    assert_eq!(s, 200);
    assert!(body.contains("cobweb_resolve_total 1"), "body:\n{body}");
    assert!(body.contains("cobweb_resolve_ok_total 1"), "body:\n{body}");
    assert!(
        body.contains("cobweb_resolve_via_total{tier=\"fastpath\"} 1"),
        "body:\n{body}"
    );
    assert!(
        body.contains("cobweb_domain_ok_total{domain=\"127.0.0.1\"} 1"),
        "body:\n{body}"
    );
    assert!(body.contains("cobweb_jar_domains 1"), "body:\n{body}");
}

#[tokio::test]
async fn fetch_proxies_body_and_status_and_forwards_allowlisted_headers() {
    let app = TestApp::spawn().await;

    Mock::given(method("GET"))
        .and(path("/seg/1.ts"))
        .and(wiremock::matchers::header(
            "referer",
            "https://player.example/",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "video/mp2t")
                .insert_header("cache-control", "public, max-age=60")
                .set_body_bytes(b"\x47\x40\x00\x10TSDATA".to_vec()),
        )
        .mount(&app.upstream)
        .await;

    let (status, headers, body) = app
        .post_raw(
            "/v1/fetch",
            json!({
                "url": format!("{}/seg/1.ts", app.upstream.uri()),
                "headers": { "Referer": "https://player.example/", "Host": "evil" },
            }),
        )
        .await;

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("video/mp2t")
    );
    assert_eq!(
        headers.get("cache-control").map(String::as_str),
        Some("public, max-age=60")
    );
    assert!(headers.contains_key("x-cobweb-final-url"));
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("*")
    );
    assert_eq!(&body, b"\x47\x40\x00\x10TSDATA");
}

#[tokio::test]
async fn fetch_mirrors_upstream_error_status() {
    let app = TestApp::spawn().await;
    Mock::given(method("GET"))
        .and(path("/gone"))
        .respond_with(ResponseTemplate::new(404).set_body_string("nope"))
        .mount(&app.upstream)
        .await;

    let (status, _headers, body) = app
        .post_raw(
            "/v1/fetch",
            json!({ "url": format!("{}/gone", app.upstream.uri()) }),
        )
        .await;
    assert_eq!(status, 404);
    assert_eq!(&body, b"nope");
}

#[tokio::test]
async fn fetch_rejects_unknown_named_egress() {
    let app = TestApp::spawn().await;
    let (status, _h, _b) = app
        .post_raw(
            "/v1/fetch",
            json!({ "url": format!("{}/x", app.upstream.uri()), "egress": "nope" }),
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn ssrf_guard_blocks_loopback_and_metadata_targets() {
    // Guard live: the loopback mock upstream is off-limits …
    let app = TestApp::spawn_guarded().await;

    for path in ["/v1/resolve", "/v1/navigate"] {
        let (status, body) = app
            .post(path, json!({ "url": format!("{}/x", app.upstream.uri()) }))
            .await;
        assert_eq!(status, 403, "{path} body: {body}");
        assert_eq!(body["kind"], json!("blocked"), "{path}");
    }

    // … and the cloud-metadata address is refused regardless of egress.
    let (status, body) = app
        .post(
            "/v1/resolve",
            json!({ "url": "http://169.254.169.254/latest/meta-data/" }),
        )
        .await;
    assert_eq!(status, 403, "body: {body}");
    assert_eq!(body["kind"], json!("blocked"));

    // /v1/fetch too.
    let (status, _h, _b) = app
        .post_raw(
            "/v1/fetch",
            json!({ "url": format!("{}/x", app.upstream.uri()) }),
        )
        .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn ssrf_guard_off_allows_private_targets() {
    // The default test harness runs with allow_private_targets = true, so a
    // loopback upstream resolves fine (covered by the other tests). This just
    // pins that the metadata IP is the one thing still blocked.
    let app = TestApp::spawn().await;
    let (status, body) = app
        .post("/v1/navigate", json!({ "url": "http://169.254.169.254/" }))
        .await;
    assert_eq!(status, 403, "body: {body}");
    assert_eq!(body["kind"], json!("blocked"));
}

// A redirect to an IP *literal* never reaches the DNS-level SSRF guard (wreq
// doesn't resolve literals): the redirect policy must refuse it. The metadata
// address is refused even with allow_private_targets = true, which is what
// lets this run hermetically against a loopback mock.
#[tokio::test]
async fn redirect_to_a_blocked_ip_literal_is_refused() {
    use std::time::Duration;
    let app = TestApp::spawn().await;
    Mock::given(method("GET"))
        .and(path("/hop"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
        )
        .mount(&app.upstream)
        .await;

    let url = format!("{}/hop", app.upstream.uri());
    let fetch = tokio::time::timeout(
        Duration::from_secs(10),
        app.post_raw("/v1/fetch", json!({ "url": url })),
    )
    .await
    .expect("/v1/fetch must fail fast, not try to connect to the metadata IP");
    assert_eq!(fetch.0, 502, "body: {}", String::from_utf8_lossy(&fetch.2));
    let body = String::from_utf8_lossy(&fetch.2).to_string();
    assert!(body.contains("refusing redirect"), "body: {body}");

    let (status, body) = tokio::time::timeout(
        Duration::from_secs(10),
        app.post("/v1/navigate", json!({ "url": url })),
    )
    .await
    .expect("/v1/navigate must fail fast too");
    assert!(
        status >= 400,
        "navigate followed the redirect: {status} {body}"
    );
    assert!(
        body.to_string().contains("refusing redirect"),
        "body: {body}"
    );
}

// The policy must not break ordinary redirects.
#[tokio::test]
async fn ordinary_redirects_are_still_followed() {
    let app = TestApp::spawn().await;
    Mock::given(method("GET"))
        .and(path("/old"))
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("location", format!("{}/new", app.upstream.uri())),
        )
        .mount(&app.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/new"))
        .respond_with(ResponseTemplate::new(200).set_body_string("moved here"))
        .mount(&app.upstream)
        .await;

    let (status, _h, body) = app
        .post_raw(
            "/v1/fetch",
            json!({ "url": format!("{}/old", app.upstream.uri()) }),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(&body, b"moved here");
}

// Upstream failures must not echo the URL's query (CDN tokens) back to the
// caller — nor let wreq append the full URI on its own.
#[tokio::test]
async fn upstream_errors_do_not_leak_the_query_string() {
    let app = TestApp::spawn().await;
    // Nothing listens here: connection refused → upstream error.
    let url = "http://127.0.0.1:9/seg.ts?token=SECRET123&exp=1";
    let (status, _h, body) = app.post_raw("/v1/fetch", json!({ "url": url })).await;
    let body = String::from_utf8_lossy(&body).to_string();
    assert_eq!(status, 502, "body: {body}");
    assert!(!body.contains("SECRET123"), "token leaked: {body}");
    assert!(
        body.contains("/seg.ts"),
        "path should still be there for debugging: {body}"
    );
}

// DNS-rebinding guard: with no api_key, a request carrying a foreign
// registrable-looking Host (what a rebinding page necessarily sends) is
// refused, while IP/localhost/service-name Hosts keep working.
#[tokio::test]
async fn foreign_host_header_is_refused_without_an_api_key() {
    let app = TestApp::spawn().await;
    let get = |host: &'static str| {
        app.http
            .get(format!("{}/v1/jar", app.base))
            .header("host", host)
            .send()
    };
    assert_eq!(
        get("attacker.example.com:8191")
            .await
            .unwrap()
            .status()
            .as_u16(),
        421
    );
    assert_eq!(get("localhost:8191").await.unwrap().status().as_u16(), 200);
    assert_eq!(get("cobweb:8191").await.unwrap().status().as_u16(), 200);
    // Default Host (127.0.0.1:<port>) — every other test relies on this.
    let ok = app
        .http
        .get(format!("{}/v1/jar", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200);
}

// Regression: `wreq` connects to the *proxy* through the client's DNS
// resolver, i.e. the SSRF `GuardedResolver`. An operator-configured profile
// whose proxy lives at a private/loopback address (the usual
// `socks5://mullvad:1080` Compose service name) was therefore refused as a
// "private target" under the default `allow_private_targets = false`, making
// every named proxy profile unusable on the fast path.
#[tokio::test]
async fn named_egress_proxy_on_a_private_host_is_usable() {
    // A plain-HTTP forward proxy is just an HTTP server that receives
    // absolute-form request targets — wiremock matches on the path.
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_string("via proxy"))
        .mount(&proxy)
        .await;
    let jar_dir = tempfile::tempdir().unwrap();
    let cfg = Config::parse(&format!(
        r#"
        [server]
        port = 0
        browser_engine = "none"
        allow_private_targets = false
        [jar]
        path = {:?}
        [egress.direct]
        proxy = ""
        [egress.lan]
        proxy = "http://localhost:{}"
        "#,
        jar_dir.path(),
        proxy.address().port()
    ))
    .unwrap();
    let state = AppState::from_config(cfg).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = cobweb::serve_on(state, listener).await;
    });

    let resp = wreq::Client::new()
        .post(format!("http://{addr}/v1/navigate"))
        .json(&json!({ "url": "http://stream.example.test/page", "egress": "lan" }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["html"], "via proxy");
}

async fn spawn_with(extra_server: &str) -> (String, tempfile::TempDir) {
    let jar_dir = tempfile::tempdir().unwrap();
    let cfg = Config::parse(&format!(
        r#"
        [server]
        port = 0
        browser_engine = "none"
        {extra_server}
        [jar]
        path = {:?}
        [egress.direct]
        proxy = ""
        "#,
        jar_dir.path()
    ))
    .unwrap();
    let state = AppState::from_config(cfg).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = cobweb::serve_on(state, listener).await;
    });
    (format!("http://{addr}"), jar_dir)
}

// With an api_key, the unauthenticated /health (liveness probes) only says
// ready/engine/version — mycelium reads exactly those two fields and sends
// the key anyway, so it still gets the full view.
#[tokio::test]
async fn health_hides_operational_detail_without_the_key() {
    let (base, _d) = spawn_with(r#"api_key = "k-0123456789abcdef0123456789""#).await;
    let http = wreq::Client::new();
    let anon: Value = http
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(anon["ready"], true);
    assert!(anon.get("engine").is_some() && anon.get("version").is_some());
    assert!(anon.get("egress_profiles").is_none(), "{anon}");
    let full: Value = http
        .get(format!("{base}/health"))
        .header("x-api-key", "k-0123456789abcdef0123456789")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(full["egress_profiles"], json!(["direct"]));
}

// mycelium hands /v1/fetch a raw `proxy_url` on loopback (wireproxy / WARP
// sharing its network namespace). `allow_private_proxies` permits that
// without opening private *targets*; without it the proxy is refused.
#[tokio::test]
async fn raw_loopback_proxy_url_needs_allow_private_proxies() {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/seg.ts"))
        .respond_with(ResponseTemplate::new(200).set_body_string("SEG"))
        .mount(&proxy)
        .await;
    let proxy_url = format!("http://127.0.0.1:{}", proxy.address().port());
    let body = json!({ "url": "http://cdn.example.test/seg.ts", "proxy_url": proxy_url });
    let http = wreq::Client::new();

    let (strict, _d1) = spawn_with("allow_private_targets = false").await;
    let r = http
        .post(format!("{strict}/v1/fetch"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);

    let (relaxed, _d2) =
        spawn_with("allow_private_targets = false\nallow_private_proxies = true").await;
    let r = http
        .post(format!("{relaxed}/v1/fetch"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(r.text().await.unwrap(), "SEG");

    // ...while private *targets* stay refused on that same instance.
    let r = http
        .post(format!("{relaxed}/v1/fetch"))
        .json(&json!({ "url": format!("http://127.0.0.1:{}/seg.ts", proxy.address().port()) }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);
}
