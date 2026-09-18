//! Small helpers shared across `browser/*` and other modules that used to be
//! reimplemented per-module (`which`, `free_port`, a bounded stderr drain) plus
//! a capped map for counters keyed by caller-influenced strings (domains, raw
//! `proxy_url`s) so a long-running process — or an unauthenticated caller
//! feeding it many distinct keys — can't grow a `HashMap` (and `/metrics`'s
//! output) without bound.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::error::{CobwebError, Result};

/// Scan `$PATH` for an executable file named `name`. If `name` already
/// contains a `/` it is treated as an explicit (absolute or relative) path
/// instead of a bare name.
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

/// Bind an ephemeral loopback port and hand back the number, for a subprocess
/// we're about to launch with `--port=<n>` (or equivalent). There is an
/// inherent TOCTOU window between this and the subprocess's own bind — bounded
/// on a host that isn't itself running an adversarial process racing us for
/// ports, which matches this sidecar's single-tenant deployment model.
pub fn free_port() -> std::io::Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Drain a child process's stdout/stderr into a bounded, shared buffer (so a
/// launch failure can report why) without ever growing unboundedly on a
/// chatty/long-lived process. Spawn one of these per stream to drain.
pub async fn drain_bounded<R: tokio::io::AsyncRead + Unpin>(
    mut rd: R,
    sink: Arc<Mutex<String>>,
    cap: usize,
) {
    use tokio::io::AsyncReadExt;
    let mut chunk = [0u8; 4096];
    loop {
        let n = match rd.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut g = sink.lock().unwrap_or_else(|e| e.into_inner());
        g.push_str(&String::from_utf8_lossy(&chunk[..n]));
        if g.len() > cap {
            let cut = g.len() - cap;
            g.drain(..cut);
        }
    }
}

/// `url` with its query string and fragment stripped, for logging. Stream/
/// player URLs routinely carry one-time authorization tokens in the query
/// string, and cobweb's default `[log].level` is `info` — logging the full
/// URL at that level (as opposed to `trace`, reserved for the rare full-URL
/// debug dump) would put those tokens in whatever aggregates the log output.
pub fn redact_url_query(url: &url::Url) -> String {
    let mut u = url.clone();
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

/// A high-entropy random token, hex-encoded (`bytes * 2` hex chars). Reads
/// `/dev/urandom` directly rather than pulling in a `rand` crate dependency
/// for the couple of infrequent, human-paced call sites that need one (e.g.
/// `blocklist.rs`'s source ids). The blocking read is a handful of bytes
/// from a device file, so it runs inline rather than via `spawn_blocking`.
pub fn random_token(bytes: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if !ok {
        // Should not happen on any Linux target cobweb ships for; falls back
        // to a weaker (but not attacker-guessable in practice without very
        // fine-grained timing knowledge) token instead of failing outright.
        tracing::warn!("/dev/urandom unavailable; falling back to a clock-seeded token");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((nanos >> ((i % 16) * 8)) & 0xff) as u8;
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time byte comparison for secrets compared against untrusted
/// network input (e.g. an API key) — a naive `==` that
/// short-circuits on the first mismatching byte is a timing side-channel in
/// principle. No `subtle`-crate dependency needed for one string compare.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Atomic write-tmp-then-rename + `chmod 0600` for a small persisted JSON
/// document — the pattern `Jar::save_locked` (`src/jar/mod.rs`),
/// [`crate::blocklist::Blocklist`], and [`crate::settings::RuntimeSettings`]
/// all use for their own state, so a concurrent reader never sees a
/// half-written file and the contents aren't world-readable.
pub async fn persist_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| CobwebError::Other(anyhow::anyhow!("serialise {}: {e}", path.display())))?;
    tokio::fs::write(&tmp, &json).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await
        {
            tracing::warn!(path = %tmp.display(), error = %e, "could not restrict state file permissions");
        }
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// A `HashMap` capped at `cap` entries, evicting the oldest-inserted key
/// (FIFO — not a true LRU, but cheap and enough to bound growth) once full.
/// Use this instead of a bare `HashMap` anywhere the key space is influenced
/// by an unauthenticated caller (a resolved domain, a raw `proxy_url`) so a
/// long-running process — or someone hammering the API with distinct
/// values — can't grow the map (and whatever renders it, e.g. `/metrics`)
/// without bound.
pub struct BoundedMap<K, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
    cap: usize,
}

impl<K: Hash + Eq + Clone, V> BoundedMap<K, V> {
    pub fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    // `get`/`get_mut`/`remove` borrow like `std::collections::HashMap`'s do
    // (`K: Borrow<Q>`) so a `BoundedMap<String, _>` can be looked up with a
    // plain `&str`, matching how callers already used the `HashMap` this
    // replaced.
    pub fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(k)
    }

    pub fn get_mut<Q>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_mut(k)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, K, V> {
        self.map.iter()
    }

    /// Insert (or overwrite) `k`. Evicts the oldest key first when at capacity
    /// and `k` is not already present.
    pub fn insert(&mut self, k: K, v: V) {
        if !self.map.contains_key(&k) {
            if self.map.len() >= self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
            self.order.push_back(k.clone());
        }
        self.map.insert(k, v);
    }

    pub fn remove<Q>(&mut self, k: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.order.retain(|x| x.borrow() != k);
        self.map.remove(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_map_evicts_oldest_first() {
        let mut m: BoundedMap<String, u32> = BoundedMap::new(2);
        m.insert("a".into(), 1);
        m.insert("b".into(), 2);
        m.insert("c".into(), 3); // evicts "a"
        assert_eq!(m.len(), 2);
        assert!(m.get(&"a".to_string()).is_none());
        assert_eq!(m.get(&"b".to_string()), Some(&2));
        assert_eq!(m.get(&"c".to_string()), Some(&3));
    }

    #[test]
    fn bounded_map_reinsert_does_not_evict() {
        let mut m: BoundedMap<String, u32> = BoundedMap::new(2);
        m.insert("a".into(), 1);
        m.insert("b".into(), 2);
        m.insert("a".into(), 10); // overwrite, not a new key
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&"a".to_string()), Some(&10));
        assert_eq!(m.get(&"b".to_string()), Some(&2));
    }

    #[test]
    fn redact_url_query_strips_query_and_fragment() {
        let u = url::Url::parse("https://cdn.example.com/hls/master.m3u8?token=SECRET&x=1#frag")
            .unwrap();
        let r = redact_url_query(&u);
        assert_eq!(r, "https://cdn.example.com/hls/master.m3u8");
        assert!(!r.contains("SECRET"));
    }

    #[test]
    fn random_token_is_the_right_length_and_varies() {
        let a = random_token(16);
        let b = random_token(16);
        assert_eq!(a.len(), 32); // 16 bytes -> 32 hex chars
        assert_ne!(a, b, "two draws should not collide");
    }

    #[test]
    fn constant_time_eq_matches_str_eq_semantics() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn which_finds_env_path_or_returns_none() {
        // "sh" should exist on any Unix CI/dev box; absence just means the
        // assertion is skipped rather than failing an unrelated environment.
        if let Some(p) = which("sh") {
            assert!(p.is_file());
        }
        assert!(which("definitely-not-a-real-binary-xyz").is_none());
    }
}
