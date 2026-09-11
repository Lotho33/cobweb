//! FlareSolverr-compatible surface (DESIGN.md §6.2 / §11 inbound).
//!
//! `POST /v1` with `{cmd, url, session?, maxTimeout?, proxy?}`. `request.*` runs
//! the tier-3 browser and answers in FlareSolverr's `solution` shape verbatim;
//! `sessions.*` map onto jar entries keyed by the session name (`<name>__fs`).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;

/// egress-key slot for FlareSolverr session jar files (`<name>__fs.json`).
#[cfg(feature = "flaresolverr")]
const FS_KEY: &str = "fs";

#[derive(Debug, Deserialize)]
pub struct V1Request {
    #[serde(default)]
    pub cmd: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default, rename = "maxTimeout")]
    pub max_timeout: Option<u64>,
    #[serde(default)]
    pub proxy: Option<FsProxy>,
}

#[derive(Debug, Deserialize)]
pub struct FsProxy {
    #[serde(default)]
    pub url: Option<String>,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn envelope(status: &str, message: &str, started: u128, extra: Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("status".into(), json!(status));
    m.insert("message".into(), json!(message));
    m.insert("startTimestamp".into(), json!(started));
    m.insert("endTimestamp".into(), json!(now_ms()));
    m.insert(
        "version".into(),
        json!(concat!("cobweb-", env!("CARGO_PKG_VERSION"))),
    );
    if let Value::Object(e) = extra {
        m.extend(e);
    }
    Value::Object(m)
}

pub async fn handle(State(st): State<AppState>, Json(req): Json<V1Request>) -> Json<Value> {
    let started = now_ms();
    let out = dispatch(&st, req, started).await;
    Json(out)
}

#[cfg(not(feature = "flaresolverr"))]
async fn dispatch(_st: &AppState, req: V1Request, started: u128) -> Value {
    envelope(
        "error",
        &format!(
            "cmd `{}` unavailable: built without the `flaresolverr` feature",
            req.cmd
        ),
        started,
        json!({}),
    )
}

#[cfg(feature = "flaresolverr")]
async fn dispatch(st: &AppState, req: V1Request, started: u128) -> Value {
    match req.cmd.as_str() {
        "request.get" => request_get(st, req, started).await,
        "request.post" => envelope(
            "error",
            "request.post is not implemented (use request.get)",
            started,
            json!({}),
        ),
        "sessions.create" => sessions_create(st, req, started).await,
        "sessions.list" => sessions_list(st, started).await,
        "sessions.destroy" => sessions_destroy(st, req, started).await,
        other => envelope(
            "error",
            &format!("unknown cmd `{other}`"),
            started,
            json!({}),
        ),
    }
}

#[cfg(feature = "flaresolverr")]
async fn request_get(st: &AppState, req: V1Request, started: u128) -> Value {
    use crate::browser::{ContextOptions, WaitFor};
    use crate::jar::JarEntry;
    use crate::pipeline::registrable_domain;
    use std::time::Duration;
    use url::Url;

    let Some(url_s) = req.url.as_deref() else {
        return envelope("error", "missing `url`", started, json!({}));
    };
    let Ok(url) = Url::parse(url_s) else {
        return envelope("error", &format!("bad url: {url_s}"), started, json!({}));
    };
    let Some(engine) = st.browser.as_ref() else {
        return envelope(
            "error",
            "browser_engine = \"chromium\" is required for request.*",
            started,
            json!({}),
        );
    };
    if let Err(e) = engine.ensure_ready().await {
        return envelope(
            "error",
            &format!("browser not ready: {e}"),
            started,
            json!({}),
        );
    }

    let proxy_url = req.proxy.as_ref().and_then(|p| p.url.clone());
    let egress = match st.egress.resolve(None, proxy_url.as_deref()) {
        Ok(e) => e,
        Err(e) => return envelope("error", &e.to_string(), started, json!({})),
    };
    if let Err(e) = st.egress.ensure_available(&egress).await {
        return envelope("error", &e.to_string(), started, json!({}));
    }
    if let Err(e) = crate::ssrf::guard_url(
        &url,
        egress.is_direct(),
        st.config.server.allow_private_targets,
    )
    .await
    {
        return envelope("error", &e.to_string(), started, json!({}));
    }

    let domain =
        registrable_domain(&url).unwrap_or_else(|_| url.host_str().unwrap_or("").to_string());
    let (jar_domain, jar_egress) = match &req.session {
        Some(name) => (name.clone(), FS_KEY.to_string()),
        None => (domain.clone(), egress.jar_key()),
    };
    let seed = st.jar.load_key(&jar_domain, &jar_egress).await;

    let timeout = Duration::from_millis(req.max_timeout.unwrap_or(60_000).clamp(5_000, 180_000));
    let opts = ContextOptions {
        egress: (*egress).clone(),
        seed: seed.as_ref().map(|j| j.storage_state.clone()),
        user_agent: seed
            .as_ref()
            .map(|j| j.user_agent.clone())
            .filter(|s| !s.is_empty()),
        accept_language: seed
            .as_ref()
            .map(|j| j.accept_language.clone())
            .filter(|s| !s.is_empty()),
        block_resources: false,
    };

    let mut ctx = match engine.acquire(opts).await {
        Ok(c) => c,
        Err(e) => return envelope("error", &format!("acquire: {e}"), started, json!({})),
    };
    let page = match ctx.navigate(&url, WaitFor::NetworkIdle, timeout).await {
        Ok(p) => p,
        Err(e) => {
            ctx.close().await;
            return envelope("error", &format!("navigate: {e}"), started, json!({}));
        }
    };
    let state = ctx.storage_state().await.unwrap_or_default();
    let user_agent = ctx.user_agent();
    ctx.close().await;

    // Persist the (possibly improved) cookie state.
    let ttl = st.jar.default_ttl().as_secs();
    let mut entry =
        seed.unwrap_or_else(|| JarEntry::new(jar_domain.clone(), jar_egress.clone(), ttl));
    entry.domain = jar_domain;
    entry.egress = jar_egress;
    entry.storage_state = state.clone();
    if !user_agent.is_empty() {
        entry.user_agent = user_agent.clone();
    }
    let _ = st.jar.note_success(entry).await;

    let solution = json!({
        "url": page.final_url.to_string(),
        "status": 200,
        "headers": {},
        "response": page.html,
        "cookies": state.cookies,
        "userAgent": user_agent,
    });

    if page.challenge {
        envelope(
            "error",
            "landed on a challenge and could not solve it",
            started,
            json!({ "solution": solution }),
        )
    } else {
        envelope("ok", "", started, json!({ "solution": solution }))
    }
}

#[cfg(feature = "flaresolverr")]
async fn sessions_create(st: &AppState, req: V1Request, started: u128) -> Value {
    use crate::jar::JarEntry;
    let name = req.session.unwrap_or_else(|| format!("fs{}", now_ms()));
    let ttl = st.jar.default_ttl().as_secs();
    let entry = JarEntry::new(name.clone(), FS_KEY.to_string(), ttl);
    if let Err(e) = st.jar.save(&entry).await {
        return envelope("error", &format!("create session: {e}"), started, json!({}));
    }
    envelope(
        "ok",
        "Session created successfully",
        started,
        json!({ "session": name }),
    )
}

#[cfg(feature = "flaresolverr")]
async fn sessions_list(st: &AppState, started: u128) -> Value {
    let names: Vec<String> = st
        .jar
        .list()
        .await
        .into_iter()
        .filter(|s| s.egress == FS_KEY)
        .map(|s| s.domain)
        .collect();
    envelope("ok", "", started, json!({ "sessions": names }))
}

#[cfg(feature = "flaresolverr")]
async fn sessions_destroy(st: &AppState, req: V1Request, started: u128) -> Value {
    let Some(name) = req.session else {
        return envelope("error", "missing `session`", started, json!({}));
    };
    match st.jar.delete(&name, FS_KEY).await {
        Ok(_) => envelope("ok", "The session has been removed.", started, json!({})),
        Err(e) => envelope("error", &e.to_string(), started, json!({})),
    }
}
