// lvim-keyring-native/server: request dispatch + the live agent state.
//
// Holds ONE optional unlocked `Session` (the decrypted body + the derived key) —
// `None` means locked. Every `secret.*` call needs it; `vault.*` manages it. A
// wrong-password unlock increments a consecutive-failure counter and sleeps a
// growing delay before answering (cheap online-guessing friction; the real
// defense against an offline attack on a stolen file is Argon2id). An idle timer
// (driven from main) locks after inactivity. Lock/unlock transitions BROADCAST a
// `vault.state {locked}` notification to every connected client, so a second
// editor's statusline tracks reality.
//
// The KDF-heavy calls (create/unlock/rotate) run on a blocking task (see
// `handle`), so a 64 MiB Argon2id derive never stalls the async reactor.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value as Json};
use tokio::sync::mpsc::UnboundedSender;

use crate::crypto::KdfParams;
use crate::rpc::{self, Request};
use crate::vault::{self, Entry, Session};

/// The sentinel error a locked `secret.*` call returns; the Lua client maps it to
/// the unlock prompt. Kept exact so the mapping is a string compare, not a guess.
const LOCKED: &str = "locked";

/// Static configuration handed to the daemon at startup.
pub struct Config {
    pub vault_path: PathBuf,
    /// KDF params applied at create/rotate (an existing vault keeps its header's params).
    pub kdf: KdfParams,
    /// Idle auto-lock timeout; ZERO = never auto-lock.
    pub lock_timeout: Duration,
    /// How long the daemon lingers after the last client disconnects (0 = exit at once).
    pub linger: Duration,
    /// Persist: keep the daemon alive after the last editor disconnects (opt-in), so terminal git
    /// can still resolve HTTPS credentials with no editor open. Idle auto-lock still applies, so the
    /// exposure window is bounded; the agent exits only on SIGTERM.
    pub persist: bool,
}

/// The daemon. Cloneable Arc handle shared by every connection + the idle timer.
#[derive(Clone)]
pub struct Server {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    cfg: Config,
    /// The unlocked session, or None when locked.
    session: Mutex<Option<Session>>,
    /// Consecutive unlock failures → the backoff delay.
    fail_count: Mutex<u32>,
    /// Last request time, for the idle auto-lock.
    last_activity: Mutex<Instant>,
    /// Connected clients' output channels, for broadcast notifications.
    clients: Mutex<HashMap<u64, UnboundedSender<String>>>,
    next_client: AtomicU64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Server {
    pub fn new(cfg: Config) -> Self {
        Server {
            inner: std::sync::Arc::new(Inner {
                cfg,
                session: Mutex::new(None),
                fail_count: Mutex::new(0),
                last_activity: Mutex::new(Instant::now()),
                clients: Mutex::new(HashMap::new()),
                next_client: AtomicU64::new(1),
            }),
        }
    }

    // ── client registry + broadcast ──────────────────────────────────────────

    /// Register a connected client's output channel; returns its id (used to unregister).
    pub fn register_client(&self, tx: UnboundedSender<String>) -> u64 {
        let id = self.inner.next_client.fetch_add(1, Ordering::Relaxed);
        self.inner.clients.lock().unwrap().insert(id, tx);
        id
    }

    /// Drop a client. Returns the number of clients that REMAIN connected.
    pub fn unregister_client(&self, id: u64) -> usize {
        let mut c = self.inner.clients.lock().unwrap();
        c.remove(&id);
        c.len()
    }

    pub fn linger(&self) -> Duration {
        self.inner.cfg.linger
    }

    pub fn persist(&self) -> bool {
        self.inner.cfg.persist
    }

    pub fn client_count(&self) -> usize {
        self.inner.clients.lock().unwrap().len()
    }

    fn broadcast(&self, line: String) {
        for tx in self.inner.clients.lock().unwrap().values() {
            let _ = tx.send(line.clone());
        }
    }

    fn broadcast_state(&self, locked: bool) {
        self.broadcast(rpc::notification("vault.state", json!({ "locked": locked })));
    }

    // ── lock state ───────────────────────────────────────────────────────────

    fn touch(&self) {
        *self.inner.last_activity.lock().unwrap() = Instant::now();
    }

    fn is_locked(&self) -> bool {
        self.inner.session.lock().unwrap().is_none()
    }

    /// Lock now: drop (zeroizing) the session if there was one. Returns whether it
    /// WAS unlocked, so the caller only broadcasts on a real transition.
    pub fn lock(&self) -> bool {
        let was = self.inner.session.lock().unwrap().take();
        was.is_some() // dropping `was` here zeroizes the body + key
    }

    /// The idle timer's tick: if unlocked and idle past the timeout, lock + broadcast.
    /// Returns the seconds until the NEXT check should run.
    pub fn autolock_tick(&self) -> u64 {
        let timeout = self.inner.cfg.lock_timeout;
        if timeout.is_zero() || self.is_locked() {
            return 1;
        }
        let idle = self.inner.last_activity.lock().unwrap().elapsed();
        if idle >= timeout {
            if self.lock() {
                self.broadcast_state(true);
            }
            1
        } else {
            (timeout - idle).as_secs().max(1)
        }
    }

    // ── request handling ─────────────────────────────────────────────────────

    /// Handle one request on connection `tx`. The dispatch runs on a blocking task
    /// so the KDF-heavy calls do not stall the reactor.
    pub async fn handle(&self, req: Request, tx: &UnboundedSender<String>) {
        let id = req.id;
        let this = self.clone();
        let method = req.method;
        let params = req.params;
        let result = tokio::task::spawn_blocking(move || this.dispatch(&method, params))
            .await
            .unwrap_or_else(|e| Err(anyhow!("internal task error: {e}")));
        let line = match result {
            Ok(v) => rpc::response_ok(id, v),
            Err(e) => rpc::response_err(id, &e.to_string()),
        };
        let _ = tx.send(line);
    }

    fn dispatch(&self, method: &str, params: Json) -> Result<Json> {
        self.touch();
        match method {
            "rpc.hello" => self.hello(),
            "vault.create" => self.create(params),
            "vault.unlock" => self.unlock(params),
            "vault.lock" => self.do_lock(),
            "vault.status" => Ok(self.status()),
            "vault.rotate" => self.rotate(params),
            "secret.get" => self.secret_get(params),
            "secret.set" => self.secret_set(params),
            "secret.delete" => self.secret_delete(params),
            "secret.rename" => self.secret_rename(params),
            "secret.list" => self.secret_list(),
            "secret.generate" => self.secret_generate(params),
            "secret.totp" => self.secret_totp(params),
            other => Err(anyhow!("unknown method '{other}'")),
        }
    }

    // ── handshake / status ───────────────────────────────────────────────────

    fn hello(&self) -> Result<Json> {
        let mut v = json!({
            "proto": rpc::PROTO,
            "locked": self.is_locked(),
            "vault_exists": vault::exists(&self.inner.cfg.vault_path),
        });
        if let Some(list) = self.summaries() {
            v["entries"] = list;
        }
        Ok(v)
    }

    fn status(&self) -> Json {
        let mut v = json!({
            "locked": self.is_locked(),
            "vault_exists": vault::exists(&self.inner.cfg.vault_path),
        });
        if let Some(list) = self.summaries() {
            v["entries"] = list;
        }
        if !self.inner.cfg.lock_timeout.is_zero() && !self.is_locked() {
            let idle = self.inner.last_activity.lock().unwrap().elapsed();
            let remaining = self.inner.cfg.lock_timeout.saturating_sub(idle).as_secs();
            v["autolock_in_s"] = json!(remaining);
        }
        v
    }

    /// The value-free entry summaries, or None while locked.
    fn summaries(&self) -> Option<Json> {
        let guard = self.inner.session.lock().unwrap();
        let s = guard.as_ref()?;
        let list: Vec<Json> = s
            .body
            .entries
            .iter()
            .map(|(name, e)| {
                json!({
                    "name": name,
                    "meta": entry_meta(e),
                    "created": e.created,
                    "updated": e.updated,
                })
            })
            .collect();
        Some(json!(list))
    }

    // ── vault lifecycle ──────────────────────────────────────────────────────

    fn create(&self, params: Json) -> Result<Json> {
        let p: PasswordParam = serde_json::from_value(params)?;
        let session = vault::create(&self.inner.cfg.vault_path, p.password.as_bytes(), self.inner.cfg.kdf)?;
        *self.inner.session.lock().unwrap() = Some(session);
        *self.inner.fail_count.lock().unwrap() = 0;
        self.broadcast_state(false);
        Ok(json!({}))
    }

    fn unlock(&self, params: Json) -> Result<Json> {
        let p: PasswordParam = serde_json::from_value(params)?;
        match vault::unlock(&self.inner.cfg.vault_path, p.password.as_bytes()) {
            Ok(session) => {
                *self.inner.session.lock().unwrap() = Some(session);
                *self.inner.fail_count.lock().unwrap() = 0;
                self.broadcast_state(false);
                Ok(json!({ "entries": self.summaries().unwrap_or(json!([])) }))
            }
            Err(e) => {
                // Growing backoff on consecutive failures: 1,2,4,8,16s cap.
                let n = {
                    let mut fc = self.inner.fail_count.lock().unwrap();
                    *fc = fc.saturating_add(1);
                    *fc
                };
                let delay = 1u64 << (n - 1).min(4); // 1,2,4,8,16
                std::thread::sleep(Duration::from_secs(delay));
                Err(e)
            }
        }
    }

    fn do_lock(&self) -> Result<Json> {
        if self.lock() {
            self.broadcast_state(true);
        }
        Ok(json!({}))
    }

    fn rotate(&self, params: Json) -> Result<Json> {
        let p: RotateParam = serde_json::from_value(params)?;
        let session = vault::rotate(
            &self.inner.cfg.vault_path,
            p.old_password.as_bytes(),
            p.new_password.as_bytes(),
            self.inner.cfg.kdf,
        )?;
        *self.inner.session.lock().unwrap() = Some(session);
        *self.inner.fail_count.lock().unwrap() = 0;
        self.broadcast_state(false);
        Ok(json!({}))
    }

    // ── secret operations (require unlock) ───────────────────────────────────

    /// Run `f` against the unlocked session, then persist. `"locked"` if locked.
    fn with_session<R>(&self, f: impl FnOnce(&mut Session) -> Result<R>) -> Result<R> {
        let mut guard = self.inner.session.lock().unwrap();
        let session = guard.as_mut().ok_or_else(|| anyhow!(LOCKED))?;
        let r = f(session)?;
        vault::save(&self.inner.cfg.vault_path, session)?;
        Ok(r)
    }

    /// Read-only access to the unlocked session (no save). `"locked"` if locked.
    fn read_session<R>(&self, f: impl FnOnce(&Session) -> Result<R>) -> Result<R> {
        let guard = self.inner.session.lock().unwrap();
        let session = guard.as_ref().ok_or_else(|| anyhow!(LOCKED))?;
        f(session)
    }

    fn secret_get(&self, params: Json) -> Result<Json> {
        let p: NameParam = serde_json::from_value(params)?;
        self.read_session(|s| {
            let e = s
                .body
                .entries
                .get(&p.name)
                .ok_or_else(|| anyhow!("no secret named '{}'", p.name))?;
            Ok(json!({ "value": e.value, "meta": entry_meta(e) }))
        })
    }

    fn secret_set(&self, params: Json) -> Result<Json> {
        let p: SetParam = serde_json::from_value(params)?;
        if p.name.trim().is_empty() {
            bail!("secret name cannot be empty");
        }
        self.with_session(|s| {
            let ts = now_secs();
            match s.body.entries.get_mut(&p.name) {
                Some(e) => {
                    // A meta-only update omits `value` — leave the stored value untouched.
                    if let Some(v) = p.value {
                        e.value = v;
                    }
                    if let Some(m) = &p.meta {
                        apply_meta(e, m);
                    }
                    e.updated = ts;
                }
                None => {
                    let value = p.value.ok_or_else(|| anyhow!("a new secret needs a value"))?;
                    let mut e = Entry {
                        value,
                        user: None,
                        url: None,
                        notes: None,
                        tags: Vec::new(),
                        totp: false,
                        created: ts,
                        updated: ts,
                    };
                    if let Some(m) = &p.meta {
                        apply_meta(&mut e, m);
                    }
                    s.body.entries.insert(p.name.clone(), e);
                }
            }
            Ok(())
        })?;
        Ok(json!({}))
    }

    fn secret_delete(&self, params: Json) -> Result<Json> {
        let p: NameParam = serde_json::from_value(params)?;
        self.with_session(|s| {
            if s.body.entries.remove(&p.name).is_none() {
                bail!("no secret named '{}'", p.name);
            }
            Ok(())
        })?;
        Ok(json!({}))
    }

    fn secret_rename(&self, params: Json) -> Result<Json> {
        let p: RenameParam = serde_json::from_value(params)?;
        if p.to.trim().is_empty() {
            bail!("new name cannot be empty");
        }
        self.with_session(|s| {
            if s.body.entries.contains_key(&p.to) {
                bail!("a secret named '{}' already exists", p.to);
            }
            let e = s
                .body
                .entries
                .remove(&p.from)
                .ok_or_else(|| anyhow!("no secret named '{}'", p.from))?;
            s.body.entries.insert(p.to, e);
            Ok(())
        })?;
        Ok(json!({}))
    }

    fn secret_list(&self) -> Result<Json> {
        let list = self.summaries().ok_or_else(|| anyhow!(LOCKED))?;
        Ok(json!({ "entries": list }))
    }

    fn secret_generate(&self, params: Json) -> Result<Json> {
        let p: GenerateParam = serde_json::from_value(params).unwrap_or_default();
        let value = generate_password(p.length.unwrap_or(24), p.symbols.unwrap_or(true));
        if let Some(name) = p.store_as.filter(|n| !n.trim().is_empty()) {
            // Storing requires an unlocked vault; a bare generate does not.
            self.with_session(|s| {
                let ts = now_secs();
                s.body.entries.insert(
                    name,
                    Entry {
                        value: value.clone(),
                        user: None,
                        url: None,
                        notes: None,
                        tags: Vec::new(),
                        totp: false,
                        created: ts,
                        updated: ts,
                    },
                );
                Ok(())
            })?;
        }
        Ok(json!({ "value": value }))
    }

    /// The CURRENT TOTP code for an entry whose value is a base32 secret. The secret never leaves the
    /// daemon — only the 6 digits + the seconds remaining in this step cross to the client.
    fn secret_totp(&self, params: Json) -> Result<Json> {
        let p: NameParam = serde_json::from_value(params)?;
        self.read_session(|s| {
            let e = s
                .body
                .entries
                .get(&p.name)
                .ok_or_else(|| anyhow!("no secret named '{}'", p.name))?;
            const PERIOD: u64 = 30;
            const DIGITS: u32 = 6;
            let now = now_secs();
            let code = crate::totp::code(&e.value, now, PERIOD, DIGITS)?;
            Ok(json!({ "code": code, "remaining": PERIOD - (now % PERIOD), "period": PERIOD }))
        })
    }
}

// ── request param shapes ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PasswordParam {
    password: String,
}

#[derive(Deserialize)]
struct RotateParam {
    old_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct NameParam {
    name: String,
}

#[derive(Deserialize)]
struct RenameParam {
    from: String,
    to: String,
}

#[derive(Deserialize)]
struct SetParam {
    name: String,
    /// Omitted for a meta-only update (the existing value is kept).
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    meta: Option<MetaIn>,
}

#[derive(Deserialize, Default)]
struct GenerateParam {
    length: Option<usize>,
    symbols: Option<bool>,
    store_as: Option<String>,
}

/// Metadata a `set` may carry. Absent fields are left unchanged on an update.
#[derive(Deserialize)]
struct MetaIn {
    user: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    tags: Option<Vec<String>>,
    totp: Option<bool>,
}

fn apply_meta(e: &mut Entry, m: &MetaIn) {
    if let Some(u) = &m.user {
        e.user = Some(u.clone()).filter(|s| !s.is_empty());
    }
    if let Some(u) = &m.url {
        e.url = Some(u.clone()).filter(|s| !s.is_empty());
    }
    if let Some(n) = &m.notes {
        e.notes = Some(n.clone()).filter(|s| !s.is_empty());
    }
    if let Some(t) = &m.tags {
        e.tags = t.clone();
    }
    if let Some(t) = m.totp {
        e.totp = t;
    }
}

/// The value-free metadata view of an entry (never includes `value`).
fn entry_meta(e: &Entry) -> Json {
    json!({
        "user": e.user,
        "url": e.url,
        "notes": e.notes,
        "tags": e.tags,
        "totp": e.totp,
        "created": e.created,
        "updated": e.updated,
    })
}

/// A random password of `length` chars. Alphanumerics always; punctuation when
/// `symbols`. Uniform selection over the chosen alphabet via rejection-free
/// modulo on fresh OS randomness (the alphabet is well under 256, bias is
/// negligible, and this is not key material — it is a value the user will store).
fn generate_password(length: usize, symbols: bool) -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const SYM: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";
    let mut alphabet = ALNUM.to_vec();
    if symbols {
        alphabet.extend_from_slice(SYM);
    }
    let n = length.clamp(1, 512);
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| alphabet[(*b as usize) % alphabet.len()] as char)
        .collect()
}
