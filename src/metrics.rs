//! Minimal Prometheus text exposition — hand-rolled to keep the dep tree small
//! (deviates from DESIGN.md §7's `metrics` crate; the metric set here is tiny).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::pipeline::ViaTier;
use crate::util::BoundedMap;

/// Cap on distinct domains tracked for the per-domain counters. The label key
/// is whatever `registrable_domain()` produces for a caller-supplied URL —
/// this API has no authentication by default (see `[server].api_key`), so an
/// unbounded map here is both a slow memory leak on a long-running process and
/// an unbounded `/metrics` response size for anyone who can reach the API.
const DOMAIN_CAP: usize = 4096;

pub struct Metrics {
    pub resolve_total: AtomicU64,
    pub resolve_ok: AtomicU64,
    pub resolve_needs_manual: AtomicU64,
    pub resolve_error: AtomicU64,
    pub challenges: AtomicU64,
    /// resolved count per `via_tier` label.
    via: [AtomicU64; 5],
    /// per registrable-domain: (attempts, ok, challenges). Capped — see
    /// [`DOMAIN_CAP`].
    per_domain: Mutex<BoundedMap<String, [u64; 3]>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            resolve_total: AtomicU64::default(),
            resolve_ok: AtomicU64::default(),
            resolve_needs_manual: AtomicU64::default(),
            resolve_error: AtomicU64::default(),
            challenges: AtomicU64::default(),
            via: Default::default(),
            per_domain: Mutex::new(BoundedMap::new(DOMAIN_CAP)),
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve_ok(&self, domain: &str, via: ViaTier) {
        self.resolve_total.fetch_add(1, Ordering::Relaxed);
        self.resolve_ok.fetch_add(1, Ordering::Relaxed);
        self.via[via_idx(via)].fetch_add(1, Ordering::Relaxed);
        self.bump_domain(domain, |d| {
            d[0] += 1;
            d[1] += 1;
        });
    }

    pub fn resolve_needs_manual(&self, domain: &str) {
        self.resolve_total.fetch_add(1, Ordering::Relaxed);
        self.resolve_needs_manual.fetch_add(1, Ordering::Relaxed);
        self.challenges.fetch_add(1, Ordering::Relaxed);
        self.bump_domain(domain, |d| {
            d[0] += 1;
            d[2] += 1;
        });
    }

    pub fn resolve_error(&self, domain: &str) {
        self.resolve_total.fetch_add(1, Ordering::Relaxed);
        self.resolve_error.fetch_add(1, Ordering::Relaxed);
        self.bump_domain(domain, |d| d[0] += 1);
    }

    /// A challenge was hit (fast path or browser) even if it was later solved.
    pub fn challenge_hit(&self) {
        self.challenges.fetch_add(1, Ordering::Relaxed);
    }

    fn bump_domain(&self, domain: &str, f: impl FnOnce(&mut [u64; 3])) {
        let mut g = self.per_domain.lock().unwrap_or_else(|e| e.into_inner());
        // Look up first: at steady state the domain is already present, so
        // avoid allocating a key `String` on every resolve.
        if let Some(v) = g.get_mut(domain) {
            f(v);
        } else {
            let mut v = [0u64; 3];
            f(&mut v);
            g.insert(domain.to_string(), v);
        }
    }

    /// Prometheus text format.
    pub fn render(&self, contexts_in_use: usize, jar_domains: usize, uptime_secs: u64) -> String {
        let mut o = String::with_capacity(1024);
        let g = |o: &mut String, name: &str, help: &str, kind: &str, val: u64| {
            let _ = writeln!(
                o,
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {val}"
            );
        };
        g(
            &mut o,
            "cobweb_resolve_total",
            "resolve() calls",
            "counter",
            self.resolve_total.load(Ordering::Relaxed),
        );
        g(
            &mut o,
            "cobweb_resolve_ok_total",
            "resolve() successes",
            "counter",
            self.resolve_ok.load(Ordering::Relaxed),
        );
        g(
            &mut o,
            "cobweb_resolve_needs_manual_total",
            "resolve() ending in needs_manual_solve",
            "counter",
            self.resolve_needs_manual.load(Ordering::Relaxed),
        );
        g(
            &mut o,
            "cobweb_resolve_error_total",
            "resolve() errors",
            "counter",
            self.resolve_error.load(Ordering::Relaxed),
        );
        g(
            &mut o,
            "cobweb_challenges_total",
            "challenge pages encountered",
            "counter",
            self.challenges.load(Ordering::Relaxed),
        );

        let _ = writeln!(o, "# HELP cobweb_resolve_via_total resolve() successes by tier\n# TYPE cobweb_resolve_via_total counter");
        for (i, name) in ["fastpath", "browser", "flaresolverr", "manual", "ytdlp"]
            .iter()
            .enumerate()
        {
            let _ = writeln!(
                o,
                "cobweb_resolve_via_total{{tier=\"{name}\"}} {}",
                self.via[i].load(Ordering::Relaxed)
            );
        }

        {
            let dom = self.per_domain.lock().unwrap_or_else(|e| e.into_inner());
            let _ = writeln!(o, "# HELP cobweb_domain_attempts_total resolve() attempts by domain\n# TYPE cobweb_domain_attempts_total counter");
            for (d, v) in dom.iter() {
                let d = esc(d);
                let _ = writeln!(o, "cobweb_domain_attempts_total{{domain=\"{d}\"}} {}", v[0]);
                let _ = writeln!(o, "cobweb_domain_ok_total{{domain=\"{d}\"}} {}", v[1]);
                let _ = writeln!(
                    o,
                    "cobweb_domain_challenges_total{{domain=\"{d}\"}} {}",
                    v[2]
                );
            }
        }

        g(
            &mut o,
            "cobweb_browser_contexts_in_use",
            "live browser contexts",
            "gauge",
            contexts_in_use as u64,
        );
        g(
            &mut o,
            "cobweb_jar_domains",
            "jar files on disk",
            "gauge",
            jar_domains as u64,
        );
        g(
            &mut o,
            "cobweb_uptime_seconds",
            "process uptime",
            "gauge",
            uptime_secs,
        );
        if let Some(kb) = rss_kb() {
            g(
                &mut o,
                "cobweb_process_resident_bytes",
                "VmRSS",
                "gauge",
                kb * 1024,
            );
        }
        o
    }
}

fn via_idx(v: ViaTier) -> usize {
    match v {
        ViaTier::Fastpath => 0,
        ViaTier::Browser => 1,
        ViaTier::Flaresolverr => 2,
        ViaTier::Manual => 3,
        ViaTier::Ytdlp => 4,
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|l| {
        l.strip_prefix("VmRSS:")
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    })
}
