//! M5a: the yt-dlp subprocess path, driven by a fake `yt-dlp` script.

#![cfg(all(feature = "ytdlp", unix))]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::net::TcpListener;

use cobweb::blocklist::Blocklist;
use cobweb::config::{BlocklistConfig, Config, SettingsConfig};
use cobweb::egress::EgressRegistry;
use cobweb::fastpath::WreqClient;
use cobweb::jar::Jar;
use cobweb::settings::RuntimeSettings;
use cobweb::state::AppState;

/// Write an executable fake `yt-dlp` that prints `body` on stdout.
fn fake_ytdlp(dir: &std::path::Path, body: &str, exit: i32) -> std::path::PathBuf {
    let p = dir.join("yt-dlp");
    std::fs::write(
        &p,
        format!("#!/bin/sh\nprintf '%s\\n' \"{body}\"\nexit {exit}\n"),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

async fn spawn(bin: &std::path::Path) -> (String, tempfile::TempDir) {
    let jar_dir = tempfile::tempdir().unwrap();
    let cfg = Config::parse(&format!(
        r#"
        [server]
        allow_private_targets = true
        [jar]
        path = {:?}
        [egress.direct]
        proxy = ""
        [ytdlp]
        enabled = true
        bin = {:?}
        hosts = ["youtube.com", "youtu.be"]
        "#,
        jar_dir.path(),
        bin,
    ))
    .unwrap();
    let egress = EgressRegistry::from_config(&cfg).unwrap();
    let jar = Jar::new(jar_dir.path().to_path_buf(), Duration::from_secs(2700), 3);
    let settings = Arc::new(RuntimeSettings::new(SettingsConfig::default()));
    let state = AppState::new(
        cfg,
        egress,
        jar,
        Arc::new(WreqClient::new(true, settings.clone())),
        None,
        Arc::new(Blocklist::new(BlocklistConfig::default())),
        settings,
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = cobweb::serve_on(state, listener).await;
    });
    (format!("http://{addr}"), jar_dir)
}

async fn resolve(base: &str, url: &str) -> (u16, Value) {
    let resp = wreq::Client::new()
        .post(format!("{base}/v1/resolve"))
        .json(&json!({ "url": url, "mode": "auto" }))
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.json::<Value>().await.unwrap())
}

#[tokio::test]
async fn matched_host_goes_through_ytdlp() {
    let d = tempfile::tempdir().unwrap();
    let bin = fake_ytdlp(
        d.path(),
        "https://r1---sn-x.googlevideo.com/videoplayback?foo=bar",
        0,
    );
    let (base, _jar) = spawn(&bin).await;

    let (status, body) = resolve(&base, "https://www.youtube.com/watch?v=dQw4w9WgXcQ").await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(body["via_tier"], json!("ytdlp"));
    assert!(body["stream_url"]
        .as_str()
        .unwrap()
        .contains("videoplayback"));
    assert_eq!(body["kind"], json!("progressive"));
}

#[tokio::test]
async fn unmatched_host_skips_ytdlp() {
    let d = tempfile::tempdir().unwrap();
    let bin = fake_ytdlp(d.path(), "https://should/not/run.m3u8", 0);
    let (base, _jar) = spawn(&bin).await;

    // 127.0.0.1:1 isn't in `hosts` -> normal pipeline -> fast path -> 502 (refused),
    // never yt-dlp.
    let (status, body) = resolve(&base, "http://127.0.0.1:1/x").await;
    assert_ne!(body["via_tier"], json!("ytdlp"), "body: {body}");
    assert!(status >= 400, "body: {body}");
}

#[tokio::test]
async fn ytdlp_failure_is_reported() {
    let d = tempfile::tempdir().unwrap();
    let bin = fake_ytdlp(d.path(), "ERROR: unavailable", 1);
    let (base, _jar) = spawn(&bin).await;

    let (status, body) = resolve(&base, "https://youtu.be/xyz").await;
    assert_eq!(status, 422, "body: {body}");
    assert_eq!(body["kind"], json!("not_resolved"));
    assert!(body["error"].as_str().unwrap().contains("yt-dlp"));
}
