// lvim-keyring-native/vault: the on-disk format + the unlocked session.
//
// One sealed file IS the whole vault: a small binary HEADER (magic, version, KDF
// params, salt, nonce) followed by the XChaCha20-Poly1305 ciphertext of a JSON
// entry map. WHOLE-file encryption, not per-entry: per-entry would let `list`
// work while locked, but that leaks the most interesting metadata (names, count,
// sizes, timestamps) to anyone who can read the file, and buys nothing — the
// daemon holds the decrypted map in RAM while unlocked anyway, and the file is
// kilobytes. One blob also makes tamper-detection and atomic rotation trivial.
//
// The KDF params live in the header (read back at unlock), so an OLD vault keeps
// opening with the params it was written with; `config.kdf` governs only
// create/rotate. The header (through the salt) is the AEAD's Associated Data, so
// downgrading a param or swapping the salt is an authentication failure, not a
// silent weakening.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KdfParams, Key32, NONCE_LEN, SALT_LEN};

const MAGIC: [u8; 4] = *b"LVKR";
const VERSION: u8 = 0x01;
const KDF_ARGON2ID: u8 = 0x01;
/// magic(4) + version(1) + kdf(1) + m_cost(4) + t_cost(4) + p_cost(4) + salt(16) — the AAD span.
const AAD_LEN: usize = 4 + 1 + 1 + 4 + 4 + 4 + SALT_LEN;
/// The AAD span + the nonce(24) — the full header preceding the body.
const HEADER_LEN: usize = AAD_LEN + NONCE_LEN;

/// One stored secret. `value` is the credential itself — its `Debug` is REDACTED
/// so a whole entry (or the body) can be logged without ever printing the secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub updated: u64,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("value", &"<redacted>")
            .field("user", &self.user)
            .field("url", &self.url)
            .field("tags", &self.tags)
            .field("created", &self.created)
            .field("updated", &self.updated)
            .finish()
    }
}

/// The decrypted body — the whole entry map. Exists only inside the daemon while
/// unlocked; `zeroize()` wipes every secret value before it is dropped on lock.
#[derive(Default, Serialize, Deserialize)]
pub struct Body {
    #[serde(default)]
    pub entries: BTreeMap<String, Entry>,
}

impl Body {
    /// Wipe every secret value in place (called on lock, before the map is dropped).
    pub fn zeroize(&mut self) {
        for e in self.entries.values_mut() {
            e.value.zeroize();
            if let Some(n) = e.notes.as_mut() {
                n.zeroize();
            }
        }
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An unlocked vault: the decrypted body plus everything needed to RE-seal it
/// (the derived key, and the salt/params it was derived under) without re-asking
/// the password. Not `Debug` — it holds the key.
pub struct Session {
    pub body: Body,
    key: Key32,
    salt: [u8; SALT_LEN],
    params: KdfParams,
}

impl Session {
    /// The KDF params this session was unlocked under — used by the round-trip test
    /// to assert params are read from the header, not re-supplied.
    #[cfg(test)]
    pub fn params(&self) -> KdfParams {
        self.params
    }
}

/// Whether a vault file exists at `path`.
pub fn exists(path: &Path) -> bool {
    path.is_file()
}

/// Build the AAD (the header through the salt) for the AEAD.
fn aad(params: KdfParams, salt: &[u8; SALT_LEN]) -> [u8; AAD_LEN] {
    let mut a = [0u8; AAD_LEN];
    a[0..4].copy_from_slice(&MAGIC);
    a[4] = VERSION;
    a[5] = KDF_ARGON2ID;
    a[6..10].copy_from_slice(&params.m_cost.to_le_bytes());
    a[10..14].copy_from_slice(&params.t_cost.to_le_bytes());
    a[14..18].copy_from_slice(&params.p_cost.to_le_bytes());
    a[18..34].copy_from_slice(salt);
    a
}

/// Parsed header fields.
struct Header {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

/// Split a raw vault file into its header fields and the ciphertext body.
fn parse(raw: &[u8]) -> Result<(Header, &[u8])> {
    if raw.len() < HEADER_LEN {
        bail!("vault file is truncated");
    }
    if raw[0..4] != MAGIC {
        bail!("not a keyring vault file (bad magic)");
    }
    if raw[4] != VERSION {
        bail!("unsupported vault version {}", raw[4]);
    }
    if raw[5] != KDF_ARGON2ID {
        bail!("unsupported KDF id {}", raw[5]);
    }
    let m_cost = u32::from_le_bytes(raw[6..10].try_into().unwrap());
    let t_cost = u32::from_le_bytes(raw[10..14].try_into().unwrap());
    let p_cost = u32::from_le_bytes(raw[14..18].try_into().unwrap());
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw[18..34]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&raw[AAD_LEN..HEADER_LEN]);
    let header = Header {
        params: KdfParams { m_cost, t_cost, p_cost },
        salt,
        nonce,
    };
    Ok((header, &raw[HEADER_LEN..]))
}

/// Serialize `body`, seal it under `key`, and write header+ciphertext to `path`
/// ATOMICALLY: write a temp file, fsync it, keep the current file as `.bak`, then
/// rename the temp over the real file (a rename is atomic on the same filesystem,
/// so a reader/crash never sees a half-written vault). A fresh random nonce every
/// write.
fn write(path: &Path, body: &Body, key: &Key32, salt: &[u8; SALT_LEN], params: KdfParams) -> Result<()> {
    let json: Zeroizing<Vec<u8>> = Zeroizing::new(serde_json::to_vec(body).map_err(|e| anyhow!("serialize: {e}"))?);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let a = aad(params, salt);
    let ciphertext = crypto::seal(key, &nonce, &a, &json)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&a); // magic..salt
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| anyhow!("create vault dir: {e}"))?;
        set_dir_private(dir);
    }

    let tmp = tmp_path(path);
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| anyhow!("open temp vault: {e}"))?;
        set_file_private(&f);
        f.write_all(&out).map_err(|e| anyhow!("write temp vault: {e}"))?;
        f.sync_all().map_err(|e| anyhow!("fsync temp vault: {e}"))?;
    }

    // Keep the current file as a one-deep rollback before replacing it.
    if path.is_file() {
        let bak = bak_path(path);
        let _ = fs::copy(path, &bak);
    }
    fs::rename(&tmp, path).map_err(|e| anyhow!("replace vault: {e}"))?;
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

fn bak_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".bak");
    PathBuf::from(s)
}

/// Create a NEW vault at `path` (must not exist) with `password`/`params`.
pub fn create(path: &Path, password: &[u8], params: KdfParams) -> Result<Session> {
    if exists(path) {
        bail!("a vault already exists at {}", path.display());
    }
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = crypto::derive_key(password, &salt, params)?;
    let body = Body::default();
    write(path, &body, &key, &salt, params)?;
    Ok(Session {
        body,
        key,
        salt,
        params,
    })
}

/// Unlock the vault at `path` with `password`. A wrong password (or a corrupt /
/// tampered file) surfaces as the AEAD failure from `crypto::open`.
pub fn unlock(path: &Path, password: &[u8]) -> Result<Session> {
    let raw = fs::read(path).map_err(|e| anyhow!("read vault: {e}"))?;
    let (header, ciphertext) = parse(&raw)?;
    let key = crypto::derive_key(password, &header.salt, header.params)?;
    let a = aad(header.params, &header.salt);
    let plain = crypto::open(&key, &header.nonce, &a, ciphertext)?;
    let body: Body = serde_json::from_slice(&plain).map_err(|e| anyhow!("vault body is not valid: {e}"))?;
    Ok(Session {
        body,
        key,
        salt: header.salt,
        params: header.params,
    })
}

/// Persist a live session (fresh nonce, keeps `.bak`). Reuses the session's key —
/// same salt/params, so no re-derivation.
pub fn save(path: &Path, session: &Session) -> Result<()> {
    write(path, &session.body, &session.key, &session.salt, session.params)
}

/// Change the master password (and/or KDF params): verify `old_password`,
/// re-derive under a FRESH salt + `new_params`, re-encrypt, atomic write. The same
/// path doubles as a KDF-parameter upgrade.
pub fn rotate(path: &Path, old_password: &[u8], new_password: &[u8], new_params: KdfParams) -> Result<Session> {
    let current = unlock(path, old_password)?; // authenticates the old password
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = crypto::derive_key(new_password, &salt, new_params)?;
    // Carry the entries from the old session into the new one.
    let body = Body {
        entries: current_entries(current),
    };
    write(path, &body, &key, &salt, new_params)?;
    Ok(Session {
        body,
        key,
        salt,
        params: new_params,
    })
}

/// Take the entries out of a session (consuming it), leaving its Body to drop-zeroize empty.
fn current_entries(mut s: Session) -> BTreeMap<String, Entry> {
    std::mem::take(&mut s.body.entries)
}

// ── permissions (best-effort; unix) ──────────────────────────────────────────

#[cfg(unix)]
fn set_dir_private(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(unix)]
fn set_file_private(f: &fs::File) {
    use std::os::unix::fs::PermissionsExt;
    let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_dir_private(_dir: &Path) {}
#[cfg(not(unix))]
fn set_file_private(_f: &fs::File) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_vault(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        p.push(format!("lvim-keyring-test-{tag}-{pid}.vault"));
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(bak_path(&p));
        p
    }

    fn fast() -> KdfParams {
        // Small params keep the tests fast — the format/logic is what is under test, not the KDF cost.
        KdfParams {
            m_cost: 32,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn create_set_unlock_round_trip() {
        let path = tmp_vault("roundtrip");
        let mut s = create(&path, b"master", fast()).unwrap();
        s.body.entries.insert(
            "forge/github.com".into(),
            Entry {
                value: "ghp_secret".into(),
                user: Some("me".into()),
                url: None,
                notes: None,
                tags: vec![],
                created: 1,
                updated: 1,
            },
        );
        save(&path, &s).unwrap();

        let s2 = unlock(&path, b"master").unwrap();
        assert_eq!(s2.body.entries.get("forge/github.com").unwrap().value, "ghp_secret");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(bak_path(&path));
    }

    #[test]
    fn wrong_password_fails() {
        let path = tmp_vault("wrongpw");
        create(&path, b"right", fast()).unwrap();
        assert!(unlock(&path, b"wrong").is_err());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(bak_path(&path));
    }

    #[test]
    fn params_are_read_from_header() {
        let path = tmp_vault("params");
        create(
            &path,
            b"pw",
            KdfParams {
                m_cost: 40,
                t_cost: 2,
                p_cost: 1,
            },
        )
        .unwrap();
        // Unlock must succeed WITHOUT being told the params — they come from the header.
        let s = unlock(&path, b"pw").unwrap();
        assert_eq!(
            s.params(),
            KdfParams {
                m_cost: 40,
                t_cost: 2,
                p_cost: 1
            }
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(bak_path(&path));
    }

    #[test]
    fn header_tamper_fails_auth() {
        let path = tmp_vault("tamper");
        create(&path, b"pw", fast()).unwrap();
        let mut raw = fs::read(&path).unwrap();
        raw[6] ^= 0x01; // flip a KDF-param byte (inside the AAD span)
        fs::write(&path, &raw).unwrap();
        assert!(unlock(&path, b"pw").is_err());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(bak_path(&path));
    }

    #[test]
    fn rotate_changes_password_and_keeps_entries() {
        let path = tmp_vault("rotate");
        let mut s = create(&path, b"old", fast()).unwrap();
        s.body.entries.insert(
            "db/test".into(),
            Entry {
                value: "pw1".into(),
                user: None,
                url: None,
                notes: None,
                tags: vec![],
                created: 1,
                updated: 1,
            },
        );
        save(&path, &s).unwrap();

        rotate(&path, b"old", b"new", fast()).unwrap();
        assert!(unlock(&path, b"old").is_err(), "old password must no longer work");
        let s2 = unlock(&path, b"new").unwrap();
        assert_eq!(s2.body.entries.get("db/test").unwrap().value, "pw1");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(bak_path(&path));
    }

    #[test]
    fn bak_holds_previous_write() {
        let path = tmp_vault("bak");
        let mut s = create(&path, b"pw", fast()).unwrap();
        s.body.entries.insert(
            "a".into(),
            Entry {
                value: "v1".into(),
                user: None,
                url: None,
                notes: None,
                tags: vec![],
                created: 1,
                updated: 1,
            },
        );
        save(&path, &s).unwrap(); // first write with the entry (now real has v1, no bak yet or bak=empty)
        s.body.entries.get_mut("a").unwrap().value = "v2".into();
        save(&path, &s).unwrap(); // second write → .bak now holds the v1 file

        let bak = bak_path(&path);
        assert!(bak.is_file(), "a .bak must exist after the second write");
        // The .bak is a full, openable vault of the PREVIOUS state.
        let raw = fs::read(&bak).unwrap();
        let (header, ct) = parse(&raw).unwrap();
        let key = crypto::derive_key(b"pw", &header.salt, header.params).unwrap();
        let plain = crypto::open(&key, &header.nonce, &aad(header.params, &header.salt), ct).unwrap();
        let body: Body = serde_json::from_slice(&plain).unwrap();
        assert_eq!(body.entries.get("a").unwrap().value, "v1");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&bak);
    }
}
