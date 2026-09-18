# cobweb — design document

> **Status:** implemented and shipping (v1.1.x). Reflects the built system;
> §14 records the open questions from the design phase and how they were
> resolved. Renamed from the `hypha` codename.
>
> **The `vnc` feature (tier 4, manual Cloudflare/Turnstile solving over
> noVNC — M3 below) was removed entirely, not just defaulted off.** cobweb
> is meant to be a plain headless extractor, not a tool engineered to defeat
> a site's anti-bot protection by hand; that capability doesn't belong here.
> Automated Cloudflare bypass, for operators who want it, is tier 3b — point
> `[flaresolverr].endpoint` at your own separately-run FlareSolverr instance
> (§11), which needed no changes and was always independent of `vnc`. Every
> section below that still describes `vnc`/Xvfb/x11vnc/noVNC/tier 4/M3 is
> **historical** — it explains a design decision that shipped and was later
> reverted, kept for context rather than rewritten line by line. The current
> HTTP API (§6.1) and Cargo features (§7) reflect the code as it stands now.

cobweb is a standalone, self-hosted headless-browser fetch sidecar for
[mycelium](https://github.com/Lotho33/mycelium). Given a page an operator is
authorised to access, it resolves the HLS/DASH stream URL behind the player,
and keeps a persistent per-domain cookie jar so a session established once is
reused by later automated calls. See `DISCLAIMER.md` for acceptable use.

It is written in **Rust**. The only non-Rust moving part is the Chromium binary it
drives over CDP (and, optionally, an external FlareSolverr instance a power user
can bolt on — see §11).

---

## 1. Goals / non-goals

### Goals

- **Low maintenance.** Quarterly engine bumps, not weekly patches. Achieved by
  *scoping out* the things that need constant work (see non-goals) and leaning on a
  network-interception sniff that doesn't parse site-specific JS.
- **Light.** ~10 MB idle. The browser is the last resort, not the default path.
  Most requests resolve over an impersonated HTTP client with reused cookies and
  never launch a browser.
- **One browser, not two.** A single headed-under-Xvfb Chromium serves both
  automated sniffing and manual challenge-solving. VNC attaches to the *same*
  display on demand. (The legacy sidecar ran a second full browser for the VNC
  session — an implementation wart, not a requirement, and it doubled the RAM
  ceiling.)
- **Modular egress.** No always-on global tunnel. Named egress profiles
  (`direct`, `mullvad`, `warp`, …); each plugin/domain picks one. Route only what
  needs routing, through the right exit.
- **Compatible with the existing mycelium browser client.** mycelium-core's
  `internal/managers/browser_client.go` keeps working unchanged: same
  `/v1/navigate`, `/v1/eval`, `/v1/sniff`, `/v1/session/*`, `/health`, `/vnc/`
  contract, same `proxy_url` field.
- **FlareSolverr-compatible, both directions.** Speaks FlareSolverr's `POST /v1`
  API so FlareSolverr clients can use cobweb; and can *delegate to* an external
  FlareSolverr as a heavy challenge-solving backend for users who have the RAM.

### Non-goals

- **Not a universal anti-bot solver.** No DataDome / PerimeterX / Kasada work, no
  chasing Cloudflare enterprise ML scoring. Sites that need that go in the
  "solve via VNC each session" bucket or the "unsupported" bucket. This is the
  single most important line in the document — it's what keeps maintenance bounded.
- **No site-specific extractors.** YouTube signature deciphering, SABR/UMP, PO
  tokens — all of that is delegated to `yt-dlp` as an optional subprocess (§10).
  cobweb never reimplements any of it.
- **Not a media proxy.** cobweb returns a stream URL (+ the headers/cookies needed
  to fetch it). Segment/playlist proxying stays in mycelium's existing HLS proxy.
- **No stealth theatre.** Behavioural humanisation, mouse-jiggle, etc. are off by
  default — they cost CPU and do nothing for an HLS sniff.

---

## 2. Resolution pipeline

The core idea: **tiered resolution, browser is the last resort.**

```
resolve(url, egress, mode) ──────────────────────────────────────────────┐
                                                                         │
 1. JAR LOOKUP                                                            │
    valid, non-stale storage_state for (registrable_domain, egress)?     │
    └─ feeds tier 2 and tier 3 with cookies                              │
                                                                         │
 2. FAST-PATH  (cobweb-fastpath: wreq, browser-impersonated TLS+H2,       │
                jar cookies attached, sent via egress proxy)             │
    ├─ response contains the stream URL (known XHR / regex on the        │
    │  player HTML) ........................................ RESOLVED (~10 MB)
    ├─ 403 / Cloudflare "Just a moment" / cf challenge HTML .. escalate → 3
    ├─ needs JS to compute the URL ......................... escalate → 3
    └─ mode == "fast" and not resolved .................... FAIL (no browser)
                                                                         │
 3. BROWSER SNIFF  (cobweb-browser: one context in the shared Chromium,   │
                    resource-blocking on, jar loaded, egress proxy set)  │
    ├─ a request matching url_pattern (default *.m3u8,*.mpd) is seen     │
    │  within timeout ................ RESOLVED, write jar (~200 MB transient)
    ├─ landed on a Cloudflare challenge page ............... escalate → 3b/4
    └─ timeout, no match ................................. FAIL           │
                                                                         │
 3b. FLARESOLVERR DELEGATE  (only if [flaresolverr].endpoint configured) │
    forward the URL to the external FlareSolverr, take back its cookies, │
    merge into jar, retry tier 3 once .................... RESOLVED / → 4 │
                                                                         │
 4. MANUAL VNC SOLVE  (cobweb-vnc: x11vnc attaches to the SAME Xvfb        │
    display the sniff context is already on; surfaced in the dashboard)  │
    admin solves the challenge in the live context; on close the jar is  │
    written; tier 3 is retried automatically ............. RESOLVED       │
```

`mode` values:

| `mode`    | behaviour |
|-----------|-----------|
| `fast`    | tier 2 only. Fails fast if a browser would be needed. For plugins that know their source is clean. |
| `auto` (default) | full pipeline, tiers 2 → 3 → (3b) → stop before 4. Tier 4 is never entered automatically — it needs a human — but the caller gets a `needs_manual_solve` outcome with the domain + egress so the dashboard can offer the button. |
| `browser` | skip tier 2, go straight to tier 3. For sources where the fast-path is known to be pointless. |

---

## 3. Single-browser design

One Chromium process. Launched **once**, lazily (first tier-3 request), **headed
inside an Xvfb virtual display**, torn down after an idle timeout.

- Headed-under-Xvfb costs ~30–40 MB for the X server over pure headless, shared
  across every context. In exchange the *same* browser can be shown over VNC — no
  second engine.
- Automated sniffs run as **browser contexts** inside it, capped at
  `max_contexts`. Each context is seeded on acquire with the target domain's
  `storage_state` from the jar and the egress proxy; on release its
  `storage_state` is written back.
- When a context lands on a challenge page, `x11vnc` is spawned and pointed at the
  **existing** Xvfb display; noVNC is served; the dashboard shows the live feed;
  the admin solves it in that very context. `x11vnc` idle-attached is ~10–15 MB
  and is killed when the session closes.
- **One manual session at a time** by design (`session/start` returns 409 if
  one is open). Its id is discoverable via `GET /v1/session/current` so a
  dashboard refresh can recover it. A session older than 20 min is assumed
  abandoned (admin closed the tab without calling `close`) and `session/start`
  reclaims the slot instead of 409-ing forever.

Result: the "VNC tax" is ~50 MB, not a 400 MB second browser. RAM ceiling drops
from ~2 GB to ~700–900 MB peak (§9).

### Stealth posture for the single Chromium

Deliberately modest — enough for the managed-challenge tier, no arms race:

- **Stock Chromium, driven by a CDP client that never sends `Runtime.enable`.**
  See "CDP client strategy" below — this is the one stealth decision that
  actually decides whether Cloudflare's *managed* challenge passes.
- Launch **headed under Xvfb** — never `--headless` / "new headless", that mode
  is itself a detection signal — with `--disable-blink-features=AutomationControlled`
  and the usual no-first-run / no-default-browser-check flags.
- Inject `navigator.webdriver = false` and a consistent UA / UA-CH set via
  `Page.addScriptToEvaluateOnNewDocument` + `Network.setUserAgentOverride` (both
  work without `Runtime.enable`).
- Consistent, real-looking `User-Agent` + `Accept-Language` + viewport, pinned per
  jar entry so the solve and the later automated calls are indistinguishable.
- Everything through the same egress as the eventual automated calls — a challenge
  solved on a different IP is worthless (mycelium already enforces this for its
  WARP session; cobweb keeps the rule).

### CDP client strategy

**The problem.** Every mainstream automation library (Puppeteer, Playwright,
chromiumoxide) sends `Runtime.enable` on each frame so that `evaluate()` can learn
the frame's execution-context id from the `Runtime.executionContextCreated` event.
But once `Runtime.enable` has been sent, Chrome changes an *observable* behaviour:
`console.*` calls get serialized for the CDP client, and that serialization reads
the `.stack` getter of any object passed in. A challenge page plants a getter on
`Error.prototype.stack`, calls `console.debug(new Error())`, and checks whether it
fired. Fired → a CDP client is attached → bot. Cloudflare Turnstile and DataDome
run exactly this probe. chromiumoxide trips it: `FrameManager::init_commands()`
calls `Runtime.enable` unconditionally and there is no config flag to stop it.

**The fix.** Don't send `Runtime.enable`. When JS must run in a frame, call
`Page.createIsolatedWorld` — the response *contains* a fresh context id, no events
needed — and evaluate in that isolated world. Chrome never flips the console
behaviour, so the probe never fires. (Cost: isolated-world JS can't read the
page's own `window` globals. Irrelevant for a stream sniff; only matters for
site-specific closure poking, a non-goal.)

**cobweb's decision.** The tier-3 sniff *never calls `evaluate()`* — it navigates
and watches `Fetch`/`Network` for a `*.m3u8` match. So the leak is entirely
avoidable by not using the offending path. cobweb ships a **small hand-rolled CDP
client** (`browser/cdp.rs`, ~400–600 LOC over `tokio-tungstenite`:
request/response by `id`, events by `method`) covering the ~10 methods the sniff
needs, plus `Page.createIsolatedWorld` eval for `/v1/eval` and `/v1/navigate`.
It is the *smaller* dependency, keeps the hot path fully under our control, and
fits the "the sniff is a stable surface" maintenance thesis. `chromiumoxide` was
evaluated as a fallback behind the `BrowserEngine` trait (§8) in case the
hand-rolled layer proved insufficient; it never did, no adapter was written, and
the `chromiumoxide` cargo feature/dependency has since been removed. The trait
remains the seam a future fallback engine would slot into.

> **Not an option: _patchright_.** It is a fork of the Playwright **library**
> (Python/Node/.NET) that applies these patches client-side; it is not a patched
> Chromium binary and is not usable from Rust. There is no "patchright Chromium"
> to drive. The Rust stealth crates (`eoka`, `chaser-oxide`) were evaluated;
> `chaser-oxide` bundles behavioural humanisation this doc rejects as a non-goal,
> `eoka` is young (0.5). A purpose-built layer won on footprint and control.

---

## 4. Egress profiles (modular VPN)

Config declares named profiles; every tier takes an egress name.

```toml
[egress.direct]
proxy = ""                         # no proxy

[egress.mullvad]
proxy = "socks5://127.0.0.1:1080"

[egress.warp]
proxy = "socks5://warp:1080"

[egress.proton]
proxy = "socks5://proton:1080"
```

- A request names an egress (`"egress": "mullvad"`) **or** passes a raw
  `proxy_url` (back-compat with mycelium's current client — that keeps working
  with zero changes).
- **Fail-closed:** if a request names an egress that is configured but whose proxy
  is unreachable, the request errors — it never silently falls back to `direct`.
  (Matches mycelium's `requires_vpn` semantics.) `direct` is the only profile that
  is allowed to have no proxy.
- Egress choice belongs to mycelium (per plugin / per domain). cobweb just needs
  the name → proxy map so it can also pick the right one for the manual VNC solve.

### On the WARP problem

The current setup routes *everything* through WARP's free tier, and the plugin
manifests already record the cost: *"example.com mostra una challenge Turnstile che
quasi mai si risolve via IP WARP"*. WARP free = well-known, saturated,
bot-flagged ranges. Recommended profiles:

| profile | privacy | anti-bot | note |
|---|---|---|---|
| `mullvad` / `proton` (paid) | good | mid | datacenter range, less saturated than WARP free; fine *with* jar + VNC |
| WARP with dedicated egress (Zero Trust) | good | good | keeps the WARP arch, IP is yours |
| residential proxy | good | best | costs more, pool ethics |
| `direct` | none | n/a | for sources with no protection and no privacy concern |

Free tiers of any VPN: don't. Small shared pools, universally blocklisted (this is
why Proton free kept getting blocked).

---

## 5. Cookie jar

Per **registrable domain** (`example.com`, not `cdn.example.com` and not
`www.example.com` separately), keyed also by **egress** — a `cf_clearance` is bound
to the exit IP, so a jar entry solved via `mullvad` is not valid via `warp`.

On-disk layout:

```
<jar.path>/
  example.com__mullvad.json
  example.net__mullvad.json
  ...
```

Each file:

```jsonc
{
  "schema_version": 1,
  "domain": "example.com",
  "egress": "mullvad",
  "storage_state": {
    "cookies": [ /* CDP Network.Cookie shape: name,value,domain,path,expires,... */ ],
    "origins": []                             // localStorage/sessionStorage — empty in v1
  },
  "user_agent": "Mozilla/5.0 ...",           // pinned; reused by fastpath + browser
  "accept_language": "it-IT,it;q=0.9,en;q=0.8",
  "fingerprint_id": "chrome-147-linux",      // which impersonation profile (wreq-util)
  "created":  "2026-08-27T10:00:00Z",
  "last_ok":  "2026-08-27T10:42:00Z",        // last time a fastpath/sniff succeeded
  "ttl_hint_secs": 2700                        // from Set-Cookie Max-Age of cf_clearance, or default
}
```

The `storage_state` object is exactly Playwright's `storageState` shape, so the
type is `StorageState { cookies: Vec<Cookie>, #[serde(default)] origins: Vec<OriginState> }`.
v1 only ever writes `cookies`; adding localStorage later just populates `origins`
— no format break, `schema_version` stays `1`.

**Staleness** (jar entry considered dead, tier 2 will escalate straight to
tier 3): `now > created + ttl_hint_secs` **OR** the last `N` (default 3)
fast-path attempts using it returned 403 / challenge. A dead entry is kept on
disk (not deleted) so the dashboard can show "example.com — needs re-solve".

---

## 6. HTTP API

Listens on `:8191` (configurable). Two surfaces.

### 6.1 Native — cobweb-compatible + extensions

Existing cobweb contract (mycelium's `browser_client.go` expects these verbatim):

| Method + path | body | response |
|---|---|---|
| `GET /health` | — | `{ready, engine, contexts_in_use, jar_domains}` |
| `POST /v1/navigate` | `{url, wait_for?, timeout_ms?, proxy_url?, egress?}` | `{html, final_url}` |
| `POST /v1/eval` | `{url, js, timeout_ms?, proxy_url?, egress?}` | `{result}` |
| `POST /v1/sniff` | `{trigger_url, url_pattern, timeout_ms?, proxy_url?, egress?}` | `{intercepted_url, headers}` |

(`/v1/session/*` and `/vnc/*` — the tier-4 manual-solve surface — no longer
exist; see the note at the top of this document.)

New:

| Method + path | body | response | purpose |
|---|---|---|---|
| `POST /v1/resolve` | `{url, egress?, mode?, url_pattern?, timeout_ms?, block_resources?}` | `{stream_url, kind, headers, cookies, via_tier, needs_manual_solve?, domain?}` | the high-level "give me the stream" entry — runs the whole pipeline |
| `POST /v1/fetch` | `{url, egress?/proxy_url?, headers?{}, use_jar?}` | streamed body, upstream status mirrored, `x-cobweb-final-url` header | impersonated **streaming GET proxy** — mycelium's HLS proxy relays every upstream fetch through this so one `wreq`/BoringSSL fingerprint is used everywhere. No buffering / sniffing; connect + read-inactivity timeouts only (no total — would truncate a long download). Drops `content-length`/`content-encoding` (wreq decompresses inline). |
| `GET  /v1/jar` | — | `[{domain, egress, stale, last_ok, ttl_hint_secs}]` | dashboard jar view |
| `DELETE /v1/jar/{domain}?egress=` | — | `{ok}` | force re-solve |
| `GET  /metrics` | — | Prometheus text | pass-rate per domain, challenge-type histogram, RAM, contexts |

`kind` ∈ `hls` | `dash` | `progressive`. `via_tier` ∈ `fastpath` | `browser` |
`flaresolverr` | `manual`.

### 6.2 FlareSolverr-compatible

`POST /v1` (note: no `/vN` — FlareSolverr's actual path):

```jsonc
// request
{ "cmd": "request.get", "url": "https://...", "session": "opt", "maxTimeout": 60000, "proxy": {"url":"socks5://..."} }
// cmd ∈ request.get | request.post | sessions.create | sessions.list | sessions.destroy
```

```jsonc
// response — FlareSolverr shape, verbatim so existing clients parse it
{
  "status": "ok",
  "message": "",
  "solution": {
    "url": "https://...", "status": 200,
    "headers": {...}, "response": "<html>...",
    "cookies": [ {name,value,domain,...} ],
    "userAgent": "Mozilla/5.0 ..."
  },
  "startTimestamp": 0, "endTimestamp": 0, "version": "cobweb-0.x"
}
```

Internally every `request.*` runs tier 3 (browser) — that's what FlareSolverr
clients expect. `sessions.*` map onto jar entries keyed by the FlareSolverr
session name instead of `(domain, egress)`.

### 6.3 Request safety — SSRF guard (`src/ssrf.rs`)

The API takes a caller-supplied URL and fetches it. `ssrf::guard_url` runs at
every entry point (`/v1/resolve`, `/v1/navigate`, `/v1/fetch`, `/v1/sniff`,
`/v1/eval`, inbound `/v1`, `/v1/session/start`) before anything connects:

- **scheme** must be `http`/`https`;
- a **literal** non-global IP or `localhost` in the URL is refused on any egress;
- on the **direct** egress the host is resolved and refused if *any* A/AAAA is
  non-global (rebinding lure). A proxied egress resolves at the proxy — the
  operator owns that exit — so only the literal check applies there.

On the fast path the same predicate is the `wreq` DNS resolver
(`ssrf::GuardedResolver`), so it re-runs on every redirect hop and pins the
connection to the vetted address (no TOCTOU re-resolve).

Two tiers of "bad": **hard-blocked** (`0.0.0.0/8`, `169.254.169.254`, multicast,
broadcast, documentation, benchmarking, reserved) is always refused;
**private** (loopback, RFC1918, rest of link-local, CGNAT `100.64/10`, IPv6 ULA
`fc00::/7`, `fe80::/10`) is refused unless `[server].allow_private_targets =
true` — the escape hatch for an operator who deliberately points cobweb at a LAN
media server.

The CDP browser context sets **no** `proxyBypassList`: when an egress proxy is
configured, loopback/private targets ride it too instead of leaking out direct.

**Residual (M-follow-up):** subresource / JS-initiated fetches *inside* Chromium
(notably `/v1/eval`) are not individually re-checked against resolved IPs —
full coverage needs `Fetch`-domain interception with an async allowlist. The
caller-supplied navigation URL and top-level redirects are covered.

---

## 7. Crate layout

**Single binary crate to start.** Modules are split-ready — promote one to its own
crate in a workspace only when something else needs to depend on it. (A first Rust
project does not need workspace ceremony on day one.)

```
cobweb/
├── Cargo.toml
├── DESIGN.md                 ← this file
├── config.example.toml
├── Dockerfile
├── vendor/novnc/             ← git submodule, pinned tag
└── src/
    ├── main.rs               ← clap args, load config, build AppState, serve
    ├── config.rs             ← serde + toml, EgressRegistry
    ├── api/
    │   ├── mod.rs            ← axum Router, shared error type → HTTP
    │   ├── native.rs         ← §6.1 handlers
    │   ├── flaresolverr.rs   ← §6.2 handlers + shape mapping
    │   └── dto.rs            ← request/response structs (serde)
    ├── pipeline.rs           ← the Tier trait, the resolve() orchestrator
    ├── fastpath.rs           ← rquest client, per-egress pools, stream-URL sniffers
    ├── browser/
    │   ├── mod.rs            ← BrowserPool, lazy launch, idle shutdown
    │   ├── engine.rs         ← BrowserEngine / BrowserContext traits (the swap seam, §3/§8)
    │   ├── cdp.rs            ← hand-rolled CDP client over tokio-tungstenite;
    │   │                        no Runtime.enable; isolated-world eval — the ONLY engine
    │   │                        (a chromiumoxide fallback was evaluated, never built; see §3)
    │   ├── context.rs        ← ContextGuard (Drop = save storage_state + close)
    │   ├── sniff.rs          ← Fetch/Network interception, url_pattern match
    │   └── stealth.rs        ← webdriver/UA patches (addScriptToEvaluateOnNewDocument), resource blocking
    ├── jar.rs                ← load/save, staleness, (domain,egress) keying
    ├── egress.rs             ← Egress { name, proxy: Option<Url> }, resolve + healthcheck
    ├── vnc/                  ← #[cfg(feature = "vnc")]
    │   ├── mod.rs            ← Xvfb + x11vnc process mgmt, session state (one at a time)
    │   ├── ws.rs             ← tokio-tungstenite bridge admin↔x11vnc
    │   └── static.rs         ← serve vendor/novnc
    ├── flaresolverr_client.rs← #[cfg(feature = "flaresolverr")] outbound delegate (tier 3b)
    └── ytdlp.rs              ← #[cfg(feature = "ytdlp")] subprocess wrapper
```

### Key dependencies

| crate | role |
|---|---|
| `tokio` | async runtime |
| `axum` + `tower-http` | HTTP server, middleware (auth passthrough, tracing, limits) |
| `wreq` + `wreq-util` | HTTP client with **browser TLS/HTTP2 impersonation**; the tier-2 engine, behind the `FastClient` trait. Maintained successor of `rquest` / `reqwest-impersonate` (v0.16 / v0.2 as of 2026-08). TLS backend is `btls` (BoringSSL) built from source → **build needs `cmake` + `clang`**. `impit` (Apify) is the named fallback. |
| `tokio-tungstenite` | transport for the hand-rolled **CDP client** (§3) |
| `serde` / `serde_json` / `toml` | config + DTOs + jar files |
| `url` | egress + target URL parsing |
| `tracing` / `tracing-subscriber` | structured logs |
| `thiserror` / `anyhow` | error types (lib) / context (bin) |
| `clap` | CLI |
| `metrics` / `metrics-exporter-prometheus` | `/metrics` |

### Cargo features

```toml
[features]
default = ["flaresolverr"]
flaresolverr  = []   # outbound delegate tier 3b + inbound /v1 API
ytdlp         = []   # yt-dlp subprocess path — NOT default (heavy, fast-moving binary)
```

`--no-default-features` → a pure fast-path + headless-sniff extractor, no
FlareSolverr integration at all. `browser_engine = "none"` in config goes
further: tier 3 disabled at runtime too, process stays ~10 MB.

---

## 8. Core types (sketch)

```rust
// pipeline.rs
pub struct ResolveCtx<'a> {
    pub url: Url,
    pub registrable_domain: String,
    pub egress: &'a Egress,
    pub mode: Mode,                 // Fast | Auto | Browser
    pub url_pattern: GlobSet,       // default: *.m3u8, *.mpd
    pub timeout: Duration,
    pub block_resources: bool,
    pub jar_state: Option<StorageState>,
}

pub enum TierOutcome {
    Resolved(StreamResult),        // { stream_url, kind, headers, cookies }
    Escalate(EscalateReason),      // Challenge | NeedsJs | NotFound
    Failed(CobwebError),
}

#[async_trait]
pub trait Tier {
    fn name(&self) -> &'static str;
    async fn try_resolve(&self, ctx: &ResolveCtx<'_>) -> TierOutcome;
}

// the orchestrator: run tiers in order, thread jar_state through,
// persist on success, return needs_manual_solve on Challenge when mode == Auto.
pub async fn resolve(state: &AppState, req: ResolveRequest) -> Result<ResolveResponse>;
```

```rust
// jar.rs
pub struct Jar { root: PathBuf, default_ttl: Duration }

impl Jar {
    pub async fn load(&self, domain: &str, egress: &str) -> Option<JarEntry>;
    pub async fn save(&self, domain: &str, egress: &str, e: JarEntry) -> Result<()>;
    pub fn is_stale(&self, e: &JarEntry) -> bool;      // ttl OR recent-403 streak
    pub async fn note_failure(&self, domain: &str, egress: &str);  // bump 403 streak
    pub async fn list(&self) -> Vec<JarSummary>;        // dashboard
}
```

```rust
// browser/engine.rs — the swap seam (§3). Only impl = browser/cdp.rs (hand-rolled,
// no Runtime.enable). A chromiumoxide-backed fallback was evaluated (§3) but never
// built; this trait is the seam a future one would slot into.
#[async_trait]
pub trait BrowserEngine: Send + Sync {
    async fn launch(&self, cfg: &BrowserCfg) -> Result<()>;      // lazy; spawns Xvfb + Chromium
    async fn new_context(&self, egress: &Egress, seed: Option<StorageState>)
        -> Result<Box<dyn BrowserContext>>;
    async fn shutdown(&self);
}

#[async_trait]
pub trait BrowserContext: Send {
    async fn navigate(&mut self, url: &Url, wait: WaitFor, t: Duration) -> Result<PageLoad>;
    /// watch Fetch/Network for a url_pattern hit — MUST NOT send Runtime.enable
    async fn sniff(&mut self, pat: &GlobSet, t: Duration) -> Result<SniffHit>;
    /// run js in a fresh Page.createIsolatedWorld, never the page's main world
    async fn eval(&mut self, js: &str, t: Duration) -> Result<serde_json::Value>;
    async fn storage_state(&self) -> Result<StorageState>;
    async fn close(self: Box<Self>);
}
```

```rust
// browser/mod.rs
pub struct BrowserPool { /* OnceCell<Box<dyn BrowserEngine>>, Semaphore(max_contexts), idle timer */ }

impl BrowserPool {
    /// Lazily launches the single Chromium (headed, under $DISPLAY from Xvfb) on
    /// first call. Blocks on the semaphore if max_contexts are busy.
    pub async fn acquire(&self, egress: &Egress, seed: Option<StorageState>)
        -> Result<ContextGuard>;   // ContextGuard wraps Box<dyn BrowserContext>
}

// ContextGuard::drop  ->  spawn( storage_state dump -> Jar::save ; context.close() )
```

```rust
// egress.rs
pub struct Egress { pub name: String, pub proxy: Option<Url> }
pub struct EgressRegistry(HashMap<String, Egress>);

impl EgressRegistry {
    pub fn resolve(&self, name_or_raw: &str) -> Result<Cow<'_, Egress>>; // named OR raw proxy_url
    pub async fn healthcheck(&self, e: &Egress) -> bool;                 // fail-closed gate
}
```

---

## 9. RAM profile

| state | RAM (measured, debug build; release ~30–40% lower) |
|---|---|
| idle — browser lazy, not launched (`browser_engine="none"` or just no tier-3 traffic yet) | **~20 MB** |
| request resolved on the fast-path (reused cookies, no browser) | ~20 MB |
| Xvfb warm (`1920×1080×24`) but Chromium not launched | +~85 MB |
| browser active, headed under Xvfb, 1 context sniffing a real player (jwplayer + hls.js + iframe renderer) | **~500–600 MB PSS** (summed RSS over-reports ~1 GB: 8 renderers share the ~200 MB binary + V8 snapshots) |
| manual VNC solve in progress (same browser + x11vnc + Turnstile iframe renderer spikes) | **peak ~700 MB – 1.1 GB** |
| external FlareSolverr delegate (tier 3b) — *its* RAM, in its own container | +300–700 MB (opt-in) |

Headed rendering costs more than the earlier headless estimate. `mem_limit:
2048m` still holds with `max_contexts: 2` (~1–1.3 GB peak for two concurrent
sniffs). Tuning levers if it gets tight: ship `--release`,
`--renderer-process-limit=4`, and block known ad/tracker hosts (streaming
players pull `spbgc.com`, `bef77.com`, … before the popup blocker bites).

Compare cobweb's documented ceiling of ~2 GB (two concurrent WebKit engines). The
`mem_limit: 2048m` in mycelium's compose stays a safe cap with lots of headroom.

Disk: Rust binary ~10–20 MB, Chromium ~180 MB, noVNC ~2 MB, fonts. Image
~400–450 MB with `vnc`, ~280 MB without.

---

## 10. yt-dlp path (optional)

For URLs whose host matches a configurable list, `cobweb` shells out instead of
touching its own pipeline:

```toml
[ytdlp]
enabled = true
bin = "yt-dlp"
hosts = ["youtube.com", "youtu.be", "vimeo.com", "dailymotion.com"]
```

`yt-dlp -g --no-warnings --cookies <tmp jar export> <url>` → the direct URL(s).
cobweb exports the relevant jar entry to Netscape cookie format for `--cookies`.
This inherits yt-dlp's ~1800 extractors, signature handling, DASH muxing, PO-token
plugin interface — none of which cobweb maintains. If `yt-dlp` isn't on PATH the
feature is simply inert.

---

## 11. FlareSolverr integration — both directions

### Inbound (cobweb *is* a FlareSolverr)

§6.2. Any tool that speaks FlareSolverr's `POST /v1` can point at cobweb. Zero
extra infrastructure for those users; they get cobweb's jar + lean fast-path for
free and the browser only when a `request.*` needs it.

### Outbound (cobweb *uses* a FlareSolverr) — the "I have a server and RAM" path

```toml
[flaresolverr]
endpoint = "http://flaresolverr:8191"   # unset -> tier 3b skipped
session_ttl_mins = 30
```

When cobweb's own tier-3 browser lands on a challenge it can't pass, and this is
set, it inserts **tier 3b**: forward the URL to the external FlareSolverr (which
runs its own heavier undetected-chromedriver / nodriver Chromium), take back
`solution.cookies` + `userAgent`, merge them into the jar keyed by
`(domain, egress)`, and retry tier 3 once. From then on the fast-path rides those
cookies until they go stale — so even a heavy FlareSolverr solve is amortised
across many cheap requests.

This keeps the heavy interactive-solve path out of the default footprint: lean
by default, opt in to the external backend, cobweb orchestrates and caches its
result so one solve is amortised across many cheap requests.

Order at the challenge branch: **tier 3b (if configured) → else tier 4 (manual
VNC, if `vnc` feature + a human available) → else fail with `needs_manual_solve`.**

---

## 12. mycelium-core integration

### Phase 0 — drop-in swap (no mycelium changes)

Point `COBWEB_ADDR` at this service. It implements the same `/v1/*`, `/health`,
`/vnc/`, session contract and honours the `proxy_url` field. `docker-compose.yml`:
set the `cobweb` service `image:` to `cobweb:latest`, keep everything else (ports
8191, the `data/cobweb` volume, `COBWEB_MAX_CONTEXTS`, …). The deprecated
`HYPHA_CONFIG` / `HYPHA_NOVNC` env names are still read for one release.

`internal/managers/browser_client.go`, `internal/api/vpn_session.go`,
`web/static/admin.js` VNC session UI — all keep working untouched.

**Verified against the mycelium sources (2026-08):** `browser_client.go` talks to
cobweb over **plain HTTP/JSON only** — `/health`, `/v1/navigate`, `/v1/eval`
(`{result: "<string>"}`), `/v1/sniff` (`{intercepted_url, headers}`),
`/v1/session/*`. `/health` is read for `ready` + `engine` only. The `cobweb:50052`
gRPC port (`COBWEB_GRPC_ADDR`) is *only* forwarded to native plugins as
`MYCELIUM_BROWSER_ADDR` / `__browser_ws`; no current plugin dials it (the Lua
`mycelium.browser.*` API goes through the HTTP client). **cobweb therefore ships
HTTP-only; a cobweb-compatible gRPC service is a deferred, currently-unused
compatibility item** (revisit only if a native plugin ever needs it).

### Phase 1 — modular egress

- `docker-compose.yml`: add `mullvad` / `proton` sidecars (wireguard containers)
  next to `warp`, each exposing a local SOCKS5.
- cobweb `config.toml`: declare the matching `[egress.*]` profiles.
- mycelium: replace the single `engine.LuaPlugins.GetProxyAddr()` with
  `GetEgressFor(pluginID)` → returns an egress **name**; plumb that name (not a
  raw proxy URL) into the `browser_client.go` calls and the HLS-proxy path.
  Manifest gains `egress: mullvad` (superset of today's `requires_vpn` /
  `vpn_optional` — `requires_vpn: true` ≈ `egress: <default-vpn>` + fail-closed).
- Admin dashboard: per-plugin egress dropdown, populated from cobweb's
  `GET /health` (or a new `GET /v1/egress`) profile list.

### Phase 2 — jar visibility

- Dashboard panel lists cobweb's jar (`GET /v1/jar`): domain, egress, stale?,
  last_ok.
- "Re-solve" button per row → `POST /v1/session/start {url: "https://<domain>",
  egress: "<that egress>"}` → the existing noVNC flow.
- A stale entry on a `requires_vpn` domain can raise a dashboard notice
  ("example.com clearance expired — re-solve to restore fast playback").

---

## 13. Maintenance philosophy

What makes this *not* a weekly treadmill:

- **The sniff doesn't parse sites.** It watches network traffic for `*.m3u8`. An
  embed provider changing its player layout doesn't break it.
- **Scoped-out targets.** No DataDome/PerimeterX, no YouTube internals. Those are
  the parts of every scraper project that rot.
- **Engine bumps are deliberate and rare.** Pin the Chromium build; bump
  quarterly-ish or when a challenge class regresses. `flaresolverr.endpoint` and
  tier 4 are the pressure-release valves so a regression is degraded UX, not an
  outage.
- **yt-dlp maintains itself.** The one fast-moving target is delegated to a
  project whose whole job is tracking it.
- **Jar + egress do the heavy lifting**, not cleverness in the browser. Solve
  once, ride the cookie, keep the exit IP consistent.

---

## 14. Open questions / risks

### Resolved (§14.1)

- **CDP detection via `Runtime.enable` — RESOLVED.** Confirmed by source:
  chromiumoxide's `FrameManager::init_commands()` sends `Runtime.enable` per
  frame, no opt-out. Decision: ship a hand-rolled CDP client (`browser/cdp.rs`)
  for tier 3 + `Page.createIsolatedWorld` eval instead. A chromiumoxide-backed
  fallback behind the `BrowserEngine` trait was considered but never built (the
  hand-rolled client never proved insufficient) — the `chromiumoxide` cargo
  feature/dependency has since been removed; the trait remains the seam a
  future fallback would use. See §3 "CDP client strategy". *patchright* is a
  Playwright fork, not a Chromium build — not
  applicable to Rust.
- **Xvfb: always-warm vs lazy — RESOLVED: lazy.** Xvfb and Chromium share one
  lifetime: spawn together on the first tier-3 request, tear down together on one
  idle timer (`browser.idle_timeout_secs`, default 300–600 s). The ~1–2 s Xvfb
  spin-up is noise next to Chromium launch + first navigation + challenge
  round-trip. `browser.prewarm = true` for latency-sensitive deployments. First
  cold manual VNC solve eats the full cold start — acceptable (a human is already
  waiting).
- **HTTP client crate — RESOLVED: `wreq`, behind a trait.** `rquest` is
  deprecated (repo → `rquest-deprecated`); the maintained successor by the same
  author is `wreq` + `wreq-util` (BoringSSL impersonation, ~monthly releases,
  device profiles current to ~Chrome 147). The lineage has rebranded twice in
  ~2 years, so the tier-2 client sits behind a `FastClient` trait; `impit`
  (Apify — HTTP/3, but needs `--cfg reqwest_unstable` + patched `rustls`/`h2`) is
  the named fallback. Pin the exact version; read the changelog on every bump.
- **Jar format — RESOLVED: cookies only in v1, growable type.** On-disk shape is
  `StorageState { schema_version: 1, cookies: Vec<Cookie>, origins: Vec<OriginState> }`
  with `origins` `#[serde(default)]` and empty in v1 — exactly Playwright's
  `storageState`. `Cookie` = CDP `Network.Cookie` shape. Adding localStorage
  later just populates `origins` — no format break. Netscape export for yt-dlp is
  a separate serializer off the same `cookies` vec.

### Still open (§14.2)

- **Egress healthcheck semantics.** What exactly is "up"? TCP connect to the proxy
  + one known-good HTTPS GET through it, cached for ~30 s. Fail-closed on miss.
- **HTTP/3 impersonation** — not in v1; the emerging frontier, revisit.
- **Single manual session** — kept as a constraint (matches cobweb, bounds RAM).
  Revisit only if multi-admin becomes real.
- **Licensing / positioning.** Self-hosted infrastructure for authorised access
  (see `DISCLAIMER.md`). MIT. Document the scope honestly; don't market it as an
  anti-bot tool.

---

## 15. Milestones

| # | deliverable | proves |
|---|---|---|
| **M1** | core server + `config.rs` + `egress.rs` + `jar.rs` + `fastpath.rs` (`wreq` behind the `FastClient` trait); `POST /v1/resolve` and `/v1/navigate` fast-path only; `browser_engine="none"` | Rust HTTP + `wreq` impersonation + jar round-trip end to end |
| **M2** | `browser/` (hand-rolled `cdp.rs` — no `Runtime.enable`; single lazy Chromium; context pool; resource blocking); `/v1/sniff`; tier 3 in the pipeline. *OK to prototype with the `chromiumoxide` fallback engine to land M2 fast, but `cdp.rs` must be the default before M3.* | the sniff works, stays leak-free, RAM stays in the §9 envelope |
| **M3** | `vnc/` (Xvfb + x11vnc + noVNC bridge); `/v1/session/*`; tier 4 + `needs_manual_solve` | dashboard can solve a live Turnstile and the jar picks it up |
| **M4** | FlareSolverr inbound `/v1` + outbound delegate (tier 3b) | drop-in for FlareSolverr clients; heavy-backend opt-in |
| **M5** | `Dockerfile` (multi-stage, `vnc` feature toggle), `yt-dlp` path, `/metrics`; swap into mycelium's compose as the `cobweb` replacement | the whole thing runs where cobweb did |

---

## 16. Dockerfile (shape)

```dockerfile
# ---- build ----
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# FEATURES overridable: e.g. --build-arg FEATURES="" for a fast-path-only image,
# or FEATURES="flaresolverr,ytdlp" + --build-arg WITH_YTDLP=1 to add yt-dlp.
ARG FEATURES="flaresolverr"
RUN cargo build --release --locked --no-default-features --features "$FEATURES" \
 && strip target/release/cobweb

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium fonts-liberation ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/cobweb /usr/local/bin/cobweb
RUN useradd -m -u 10001 cobweb
USER cobweb
ENV COBWEB_CONFIG=/config/config.toml
EXPOSE 8191
ENTRYPOINT ["tini", "--", "cobweb"]
```

`tini` reaps Chromium's process tree on teardown.

---

## 17. Naming

Published as **cobweb**, renamed from the `hypha` codename used during design.
The binary, crate, Docker image, `COBWEB_*` env vars and the `cobweb_*` metric
prefix all share the name; `HYPHA_CONFIG` / `HYPHA_NOVNC` are honoured as
deprecated aliases for one release.
