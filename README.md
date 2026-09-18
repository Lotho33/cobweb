# cobweb

A small, self-hosted **headless-browser fetch sidecar**. Given a web page an
operator is authorised to access, cobweb resolves the playable HLS/DASH stream
URL behind the player and hands it back with the headers/cookies needed to fetch
it — so a media player can stream it directly.

It is the companion service for [mycelium](https://github.com/Lotho33/mycelium),
which calls it over plain HTTP. It can also be used on its own.

> **Please read [DISCLAIMER.md](DISCLAIMER.md).** cobweb ships no content
> sources and no site-specific scrapers. Use it only against services you are
> entitled to access.

> Renamed from `hypha`. The old `HYPHA_CONFIG` / `HYPHA_NOVNC` env vars are
> still honoured for one release; Prometheus metrics are now `cobweb_*`.

## How it works

Requests go through tiers, cheapest first:

1. **Fast path** — an impersonated HTTP GET (`wreq` / BoringSSL) with the
   per-domain cookie jar attached. If the player HTML already contains the
   manifest URL, that's the whole request: ~10 MB resident, no browser.
2. **Browser sniff** — a single headless Chromium, driven over the DevTools
   protocol, watches the network for the `*.m3u8` / `*.mpd` the page
   requests. Used only when the fast path can't see the URL.
3. **FlareSolverr delegate** *(optional)* — hand a hard page to an external,
   separately-run FlareSolverr instance and retry the sniff with the cookies
   it returns. Point `[flaresolverr].endpoint` at it; unset by default.

If every tier fails on a challenge, cobweb returns a structured
`needs_manual_solve` error — it has no interactive solve capability of its
own (dropped entirely; it isn't cobweb's job to defeat a site's anti-bot
protection by hand). A caller can react to that however it wants, e.g. by
pointing at a FlareSolverr instance.

Supporting pieces:

- **Persistent cookie jar** — one file per `(registrable domain, egress)`, so a
  session established once is reused by later automated calls until it expires.
- **Modular egress** — named VPN/proxy profiles chosen per request; no always-on
  global tunnel. Fail-closed if the chosen proxy is unreachable.
- **FlareSolverr-compatible API** — cobweb also *speaks* the FlareSolverr v1
  API, so it can be dropped in where one is already expected.

See **[DESIGN.md](DESIGN.md)** for the full rationale.

## Configuration

Copy `config.example.toml`, set `COBWEB_CONFIG` to its path. Every knob is
documented inline. Note that `[server].bind` defaults to `127.0.0.1`: the API is
unauthenticated, so only bind a routable address behind a trusted reverse proxy
or a private container network.

## Building / testing

No host toolchain needed — everything runs in `rust:1-bookworm` via podman
(see the `Makefile`):

```sh
make test     # cargo test   (in-container)
make check    # cargo clippy --all-targets
make run      # cargo run -- --config config.dev.toml   → http://localhost:8191
```

Or open the folder in the devcontainer (`.devcontainer/`).

### Smoke test

```sh
curl -s localhost:8191/health | jq
curl -s localhost:8191/v1/resolve \
  -H 'content-type: application/json' \
  -d '{"url":"https://<a-page-you-can-access>","mode":"auto"}' | jq
```

## Features (Cargo)

| feature | default | what |
|---|:---:|---|
| `flaresolverr` | ✅ | inbound FS-compatible API + outbound delegate |
| `ytdlp` | — | opt-in: shell out to a `yt-dlp` binary for hosts it handles |

## License

MIT — see [LICENSE](LICENSE). Third-party components and their licenses are
listed in [NOTICE](NOTICE).
