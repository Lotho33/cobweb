//! Persistent cookie jar (DESIGN.md §5).
//!
//! One JSON file per `(registrable_domain, egress)` under `<jar.path>/`.
//! A Cloudflare `cf_clearance` is bound to the exit IP, so the egress is part
//! of the key. Entries are never deleted on staleness — a dead entry stays on
//! disk so the dashboard can show "needs re-solve".

pub mod cookie;

pub use cookie::{Cookie, LocalStorageEntry, OriginState, StorageState};

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::egress::Egress;
use crate::error::{CobwebError, Result};

pub const SCHEMA_VERSION: u32 = 1;

/// One on-disk jar file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JarEntry {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub domain: String,
    pub egress: String,
    #[serde(default)]
    pub storage_state: StorageState,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub accept_language: String,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub last_ok: Option<DateTime<Utc>>,
    /// From the `Set-Cookie` `Max-Age` of `cf_clearance`, else the configured default.
    pub ttl_hint_secs: u64,
    /// Consecutive fast-path attempts that came back 403 / challenge. Persisted
    /// so a restart doesn't forget a dying entry.
    #[serde(default)]
    pub fail_streak: u32,
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

impl JarEntry {
    pub fn new(domain: impl Into<String>, egress: impl Into<String>, ttl_hint_secs: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            domain: domain.into(),
            egress: egress.into(),
            storage_state: StorageState::default(),
            user_agent: String::new(),
            accept_language: String::new(),
            created: Utc::now(),
            last_ok: None,
            ttl_hint_secs,
            fail_streak: 0,
        }
    }

    fn expiry(&self) -> DateTime<Utc> {
        self.created + chrono::Duration::seconds(self.ttl_hint_secs as i64)
    }
}

/// Lightweight row for `GET /v1/jar`.
#[derive(Debug, Clone, Serialize)]
pub struct JarSummary {
    pub domain: String,
    pub egress: String,
    pub stale: bool,
    pub created: DateTime<Utc>,
    /// created + ttl_hint_secs — the dashboard shows a "re-solve by" countdown.
    pub expires_at: DateTime<Utc>,
    pub last_ok: Option<DateTime<Utc>>,
    pub ttl_hint_secs: u64,
    pub fail_streak: u32,
    pub cookie_count: usize,
}

pub struct Jar {
    root: PathBuf,
    default_ttl: Duration,
    fail_streak_limit: u32,
    /// Coarse lock serialising read-modify-write cycles (`note_*`). Jar writes
    /// are infrequent; a per-key lock map can come later if it ever matters.
    write_lock: Mutex<()>,
    /// Set once the jar dir is known to exist, so every write doesn't re-run
    /// `create_dir_all`.
    dir_ready: AtomicBool,
}

impl Jar {
    pub fn new(root: impl Into<PathBuf>, default_ttl: Duration, fail_streak_limit: u32) -> Self {
        Self {
            root: root.into(),
            default_ttl,
            fail_streak_limit: fail_streak_limit.max(1),
            write_lock: Mutex::new(()),
            dir_ready: AtomicBool::new(false),
        }
    }

    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    pub async fn ensure_dir(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.root).await?;
        self.dir_ready.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn file_for(&self, domain: &str, egress_key: &str) -> PathBuf {
        // domain is a registrable domain (already lowercase, no slashes);
        // egress_key is sanitised by `Egress::jar_key`. Still guard against
        // path separators defensively.
        let safe_domain = sanitize(domain);
        let safe_egress = sanitize(egress_key);
        self.root.join(format!("{safe_domain}__{safe_egress}.json"))
    }

    pub async fn load(&self, domain: &str, egress: &Egress) -> Option<JarEntry> {
        self.load_by_key(domain, &egress.jar_key()).await
    }

    /// Load by an explicit `(domain, egress-key)` — used for FlareSolverr
    /// sessions, which key on a caller-chosen name rather than an egress.
    pub async fn load_key(&self, domain: &str, egress_key: &str) -> Option<JarEntry> {
        self.load_by_key(domain, egress_key).await
    }

    async fn load_by_key(&self, domain: &str, egress_key: &str) -> Option<JarEntry> {
        let path = self.file_for(domain, egress_key);
        let bytes = tokio::fs::read(&path).await.ok()?;
        match serde_json::from_slice::<JarEntry>(&bytes) {
            Ok(entry) => Some(entry),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "corrupt jar file, ignoring");
                None
            }
        }
    }

    pub async fn save(&self, entry: &JarEntry) -> Result<()> {
        let _g = self.write_lock.lock().await;
        self.save_locked(entry).await
    }

    async fn save_locked(&self, entry: &JarEntry) -> Result<()> {
        if !self.dir_ready.load(Ordering::Relaxed) {
            self.ensure_dir().await?;
        }
        let path = self.file_for(&entry.domain, &entry.egress);
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(entry)
            .map_err(|e| CobwebError::Other(anyhow::anyhow!("serialise jar entry: {e}")))?;
        tokio::fs::write(&tmp, &json).await.map_err(|e| {
            CobwebError::Other(anyhow::anyhow!(
                "jar write {}/{}: {e}",
                entry.domain,
                entry.egress
            ))
        })?;
        // The jar holds live session cookies (cf_clearance and friends) in
        // plaintext; restrict the file to the owner so another local
        // user/process sharing the host or a volume can't read them off disk.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await
            {
                tracing::warn!(path = %tmp.display(), error = %e, "jar: could not restrict file permissions");
            }
        }
        // Atomic replace so a concurrent reader never sees a half-written file.
        tokio::fs::rename(&tmp, &path).await.map_err(|e| {
            CobwebError::Other(anyhow::anyhow!(
                "jar rename {}/{}: {e}",
                entry.domain,
                entry.egress
            ))
        })?;
        Ok(())
    }

    /// `now > created + ttl_hint_secs` OR the fail streak has hit the limit.
    pub fn is_stale(&self, entry: &JarEntry) -> bool {
        Utc::now() >= entry.expiry() || entry.fail_streak >= self.fail_streak_limit
    }

    /// A valid, non-stale entry to seed tiers 2/3 with, or `None`.
    pub async fn get_fresh(&self, domain: &str, egress: &Egress) -> Option<JarEntry> {
        let entry = self.load(domain, egress).await?;
        if self.is_stale(&entry) {
            tracing::debug!(domain, egress = %entry.egress, "jar entry is stale");
            None
        } else {
            Some(entry)
        }
    }

    /// Bump the 403 streak for an entry (creating nothing if none exists).
    pub async fn note_failure(&self, domain: &str, egress: &Egress) {
        let _g = self.write_lock.lock().await;
        let key = egress.jar_key();
        let Some(mut entry) = self.load_by_key(domain, &key).await else {
            return;
        };
        entry.fail_streak = entry.fail_streak.saturating_add(1);
        if let Err(e) = self.save_locked(&entry).await {
            tracing::warn!(domain, error = %e, "note_failure: save failed");
        }
    }

    /// Record a successful use: reset the streak, stamp `last_ok`, and persist
    /// the (possibly updated) storage state.
    ///
    /// `entry` is normally built from a jar "seed" the caller read *before*
    /// running a tier — which can take seconds (a browser sniff, an external
    /// FlareSolverr delegate). Two concurrent resolves for the same
    /// `(domain, egress)` (a popular stream requested by more than one client
    /// at once) can therefore each start from the same seed and race to write
    /// back: naively trusting `entry` as ground truth would let whichever call
    /// finishes second silently overwrite the cookies the first one just
    /// persisted. Re-reading the freshest on-disk entry under the write lock
    /// and merging the caller's cookies on top of *that* (instead of the
    /// caller's own, possibly stale, snapshot) closes that lost-update window.
    pub async fn note_success(&self, mut entry: JarEntry) -> Result<()> {
        let _g = self.write_lock.lock().await;
        let incoming_cookies = std::mem::take(&mut entry.storage_state.cookies);
        if let Some(current) = self.load_by_key(&entry.domain, &entry.egress).await {
            entry.storage_state = current.storage_state;
            if entry.user_agent.is_empty() {
                entry.user_agent = current.user_agent;
            }
            if entry.accept_language.is_empty() {
                entry.accept_language = current.accept_language;
            }
        }
        entry.storage_state.merge_from(incoming_cookies);
        entry.fail_streak = 0;
        entry.last_ok = Some(Utc::now());
        if entry.schema_version == 0 {
            entry.schema_version = SCHEMA_VERSION;
        }
        self.save_locked(&entry).await
    }

    pub async fn delete(&self, domain: &str, egress_key: &str) -> Result<bool> {
        let _g = self.write_lock.lock().await;
        let path = self.file_for(domain, egress_key);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn list(&self) -> Vec<JarSummary> {
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            Err(_) => return out, // dir not created yet => empty jar
        };
        while let Ok(Some(ent)) = rd.next_entry().await {
            let path = ent.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(&path).await else {
                continue;
            };
            let Ok(entry) = serde_json::from_slice::<JarEntry>(&bytes) else {
                continue;
            };
            out.push(JarSummary {
                stale: self.is_stale(&entry),
                created: entry.created,
                expires_at: entry.expiry(),
                domain: entry.domain,
                egress: entry.egress,
                last_ok: entry.last_ok,
                ttl_hint_secs: entry.ttl_hint_secs,
                fail_streak: entry.fail_streak,
                cookie_count: entry.storage_state.cookies.len(),
            });
        }
        out.sort_by(|a, b| {
            a.domain
                .cmp(&b.domain)
                .then_with(|| a.egress.cmp(&b.egress))
        });
        out
    }

    /// Number of jar files on disk. Only `read_dir` — no read/parse — for the
    /// hot `/health` and `/metrics` counters (`list()` reads and parses every
    /// file and is only for `GET /v1/jar`).
    pub async fn count(&self) -> usize {
        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            Err(_) => return 0,
        };
        let mut n = 0;
        while let Ok(Some(ent)) = rd.next_entry().await {
            if ent.path().extension().and_then(|s| s.to_str()) == Some("json") {
                n += 1;
            }
        }
        n
    }
}

/// Shareable handle.
pub type SharedJar = Arc<Jar>;

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
            _ => '-',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::Egress;
    use url::Url;

    fn tmp_jar() -> (tempfile::TempDir, Jar) {
        let dir = tempfile::tempdir().unwrap();
        let jar = Jar::new(dir.path().to_path_buf(), Duration::from_secs(2700), 3);
        (dir, jar)
    }

    fn mullvad() -> Egress {
        Egress {
            name: "mullvad".into(),
            proxy: Some(Url::parse("socks5://mullvad:1080").unwrap()),
        }
    }

    #[tokio::test]
    async fn round_trips_an_entry() {
        let (_d, jar) = tmp_jar();
        let mut e = JarEntry::new("example.com", "mullvad", 2700);
        e.storage_state =
            StorageState::from_cookies(vec![Cookie::new("cf_clearance", "xyz", ".example.com")]);
        e.user_agent = "Mozilla/5.0".into();
        jar.save(&e).await.unwrap();

        let back = jar.load("example.com", &mullvad()).await.unwrap();
        assert_eq!(back.storage_state.cookies[0].value, "xyz");
        assert_eq!(back.user_agent, "Mozilla/5.0");
        assert_eq!(back.schema_version, SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn staleness_by_ttl() {
        let (_d, jar) = tmp_jar();
        let mut e = JarEntry::new("x.to", "direct", 2700);
        assert!(!jar.is_stale(&e));
        e.created = Utc::now() - chrono::Duration::hours(2); // > 45 min ttl
        assert!(jar.is_stale(&e));
    }

    #[tokio::test]
    async fn staleness_by_fail_streak() {
        let (_d, jar) = tmp_jar();
        let e = JarEntry {
            fail_streak: 3,
            ..JarEntry::new("x.to", "direct", 2700)
        };
        assert!(jar.is_stale(&e));
    }

    #[tokio::test]
    async fn note_failure_then_success() {
        let (_d, jar) = tmp_jar();
        let e = JarEntry::new("x.to", "mullvad", 2700);
        jar.save(&e).await.unwrap();

        jar.note_failure("x.to", &mullvad()).await;
        jar.note_failure("x.to", &mullvad()).await;
        let mid = jar.load("x.to", &mullvad()).await.unwrap();
        assert_eq!(mid.fail_streak, 2);

        jar.note_success(mid).await.unwrap();
        let after = jar.load("x.to", &mullvad()).await.unwrap();
        assert_eq!(after.fail_streak, 0);
        assert!(after.last_ok.is_some());
    }

    #[tokio::test]
    async fn get_fresh_skips_stale() {
        let (_d, jar) = tmp_jar();
        let mut e = JarEntry::new("x.to", "mullvad", 2700);
        e.created = Utc::now() - chrono::Duration::hours(2);
        jar.save(&e).await.unwrap();
        assert!(jar.get_fresh("x.to", &mullvad()).await.is_none());
    }

    #[tokio::test]
    async fn list_and_delete() {
        let (_d, jar) = tmp_jar();
        jar.save(&JarEntry::new("a.to", "direct", 2700))
            .await
            .unwrap();
        jar.save(&JarEntry::new("b.to", "mullvad", 2700))
            .await
            .unwrap();
        let rows = jar.list().await;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].domain, "a.to");

        assert!(jar.delete("a.to", "direct").await.unwrap());
        assert!(!jar.delete("a.to", "direct").await.unwrap());
        assert_eq!(jar.list().await.len(), 1);
    }

    #[tokio::test]
    async fn note_success_does_not_lose_a_concurrent_writers_cookie() {
        // Simulates two resolves for the same (domain, egress) that both read
        // the same seed before their tier ran, then finish out of order: A's
        // `note_success` must not be clobbered by B's, even though B's
        // in-memory `entry` was built from a snapshot that predates A's write.
        let (_d, jar) = tmp_jar();
        let seed = JarEntry::new("race.to", "direct", 2700);
        jar.save(&seed).await.unwrap();

        let mut a = seed.clone();
        a.storage_state = StorageState::from_cookies(vec![Cookie::new("a", "1", "race.to")]);
        jar.note_success(a).await.unwrap();

        // b was built from the *original* seed (no cookie "a"), as if its tier
        // had started before a's finished.
        let mut b = seed.clone();
        b.storage_state = StorageState::from_cookies(vec![Cookie::new("b", "2", "race.to")]);
        jar.note_success(b).await.unwrap();

        let after = jar.load("race.to", &Egress::direct()).await.unwrap();
        let names: Vec<&str> = after
            .storage_state
            .cookies
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert!(
            names.contains(&"a"),
            "lost cookie `a` to a concurrent write"
        );
        assert!(names.contains(&"b"));
    }

    #[tokio::test]
    async fn missing_entry_loads_as_none() {
        let (_d, jar) = tmp_jar();
        assert!(jar.load("nope.to", &mullvad()).await.is_none());
    }

    // `sanitize()` is the only barrier against a hostile `domain` / egress-key
    // (a FlareSolverr `session` name is caller-chosen, see api/flaresolverr.rs)
    // escaping the jar directory via `../` or an absolute path. It had zero
    // dedicated tests despite being security-relevant.
    #[test]
    fn sanitize_neutralises_path_traversal_and_separators() {
        // `.` is in the keep-set (ordinary domains contain it), so only the
        // `/` separators are neutralised — `..` survives as text, it just
        // can no longer act as a path component on its own (see
        // `hostile_domain_cannot_escape_the_jar_directory` below for why that
        // still can't escape the jar root).
        assert_eq!(sanitize("../../etc/passwd"), "..-..-etc-passwd");
        assert_eq!(sanitize("/etc/passwd"), "-etc-passwd");
        assert_eq!(sanitize("a/b\\c"), "a-b-c");
        assert_eq!(sanitize(".."), "..");
        assert_eq!(sanitize(""), "");
        // Ordinary registrable domains / egress keys pass through unchanged.
        assert_eq!(sanitize("example.com"), "example.com");
        assert_eq!(sanitize("proxy-10.0.0.1-1080"), "proxy-10.0.0.1-1080");
    }

    #[tokio::test]
    async fn hostile_domain_cannot_escape_the_jar_directory() {
        let (dir, jar) = tmp_jar();
        let evil = JarEntry::new("../../../../tmp/pwned", "direct", 2700);
        jar.save(&evil).await.unwrap();
        // The written file must land *inside* the jar root, not at the
        // traversed path.
        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        let mut found_inside = false;
        while let Some(e) = entries.next_entry().await.unwrap() {
            if e.path().extension().and_then(|s| s.to_str()) == Some("json") {
                found_inside = true;
            }
        }
        assert!(found_inside, "jar file was not written inside the jar root");
        assert!(!PathBuf::from("/tmp/pwned").exists());
    }
}
