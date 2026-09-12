use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use cobweb::config::Config;
use cobweb::state::AppState;

#[derive(Parser, Debug)]
#[command(
    name = "cobweb",
    version,
    about = "self-hosted headless-browser fetch sidecar"
)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, env = "COBWEB_CONFIG", default_value = "config.toml")]
    config: PathBuf,

    /// Parse the config, print a summary, and exit.
    #[arg(long)]
    check: bool,
}

fn main() -> ExitCode {
    // A sidecar serves a handful of concurrent requests plus one Chromium; the
    // default (#CPU worker threads) is wasteful on a many-core host. 2 keeps the
    // CDP reader responsive while a sniff is parked in `.await` and a /v1/fetch
    // streams, without ~15-20 MB of extra thread stacks. Override with
    // COBWEB_WORKER_THREADS.
    let workers = std::env::var("COBWEB_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(2);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(run())
}

async fn run() -> ExitCode {
    // Deprecated pre-rename env var: honour HYPHA_CONFIG when COBWEB_CONFIG is
    // unset so existing deployments keep working. Remove after one release.
    if std::env::var_os("COBWEB_CONFIG").is_none() {
        if let Some(v) = std::env::var_os("HYPHA_CONFIG") {
            eprintln!("cobweb: HYPHA_CONFIG is deprecated, use COBWEB_CONFIG");
            std::env::set_var("COBWEB_CONFIG", v);
        }
    }

    let cli = Cli::parse();

    let cfg = match Config::load(&cli.config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cobweb: {e}");
            return ExitCode::FAILURE;
        }
    };

    init_tracing(&cfg.log.level);

    if cli.check {
        println!("config OK: {}", cli.config.display());
        println!("  listen           : {}", cfg.server.listen_addr());
        println!("  browser_engine   : {:?}", cfg.server.browser_engine);
        println!("  jar.path         : {}", cfg.jar.path.display());
        println!(
            "  egress profiles  : {}",
            cfg.egress.keys().cloned().collect::<Vec<_>>().join(", ")
        );
        println!(
            "  flaresolverr     : {}",
            cfg.flaresolverr.endpoint.as_deref().unwrap_or("(disabled)")
        );
        return ExitCode::SUCCESS;
    }

    let addr = cfg.server.listen_addr();
    let has_api_key = cfg.server.effective_api_key().is_some();
    if !addr.ip().is_loopback() && !has_api_key {
        tracing::warn!(
            %addr,
            "binding a non-loopback address with NO [server].api_key configured: the API \
             is UNAUTHENTICATED and can run arbitrary JS in a browser / fetch arbitrary \
             URLs / read the cookie jar. Set [server].api_key, or only do this behind a \
             trusted reverse proxy or a private container network."
        );
    } else if !addr.ip().is_loopback() {
        tracing::info!(%addr, "binding a non-loopback address; [server].api_key is set");
    }
    let state = match AppState::from_config(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cobweb: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = state.jar.ensure_dir().await {
        tracing::warn!(error = %e, "could not create jar directory (will retry on first write)");
    }

    if state.config.browser.prewarm {
        if let Some(b) = &state.browser {
            tracing::info!("prewarm: launching Chromium now");
            if let Err(e) = b.ensure_ready().await {
                tracing::warn!(error = %e, "prewarm failed; will retry lazily");
            }
        }
    }

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cobweb: cannot bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        %addr,
        engine = state.fast.engine(),
        browser = ?state.config.server.browser_engine,
        egress = ?state.egress.names(),
        "cobweb listening"
    );

    let browser = state.browser.clone();
    let result = cobweb::serve_on_until(state, listener, shutdown_signal()).await;

    // Tear down Chromium + Xvfb so nothing is orphaned.
    if let Some(b) = browser {
        b.shutdown().await;
    }

    match result {
        Ok(()) => {
            tracing::info!("shutdown complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "server exited with error");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(level: &str) {
    // RUST_LOG wins if set; otherwise use the config level for the `cobweb` crate
    // and `warn` for everything else.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("warn,cobweb={level},tower_http=info")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("signal received, shutting down");
}
