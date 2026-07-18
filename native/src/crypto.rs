// lvim-keyring-native/crypto: the primitives — Argon2id KDF + XChaCha20-Poly1305 AEAD.
//
// The master password NEVER becomes the encryption key directly: `derive_key`
// runs it through Argon2id (memory-hard, tunable) with a per-vault salt to a
// 32-byte key. That key seals/opens the vault body with XChaCha20-Poly1305 — a
// 24-byte nonce, so fresh RANDOM nonces are collision-safe without a counter, and
// an AEAD so tampering (bit-flips, a swapped salt, a downgraded KDF param) fails
// authentication rather than silently weakening the vault: the whole file header
// is passed as the AEAD's Associated Data.
//
// Everything key-shaped is `Zeroizing`, so the derived key and any plaintext
// buffer are wiped from memory on drop (on lock, on rotate, on daemon exit) — the
// point of doing crypto out-of-process is undone if the key lingers in RAM.

use std::ops::Deref;

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

/// Bytes of the derived key / the AEAD key.
pub const KEY_LEN: usize = 32;
/// Bytes of the KDF salt (per vault, fresh at create/rotate).
pub const SALT_LEN: usize = 16;
/// Bytes of the AEAD nonce (fresh on EVERY write — XChaCha's 24 bytes make random safe).
pub const NONCE_LEN: usize = 24;

/// Argon2id cost parameters. Stored in the vault header (little-endian) so an old
/// vault keeps opening with the params it was written with, while `config.kdf`
/// governs only new create/rotate writes. Defaults follow OWASP's Argon2id
/// guidance (64 MiB, 3 passes, 4 lanes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost (iterations / passes).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost: 64 * 1024, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    /// Reject nonsensical / dangerous params (a zero would panic Argon2 or defeat it).
    fn validate(&self) -> Result<()> {
        if self.m_cost < 8 || self.t_cost < 1 || self.p_cost < 1 {
            return Err(anyhow!("invalid KDF parameters"));
        }
        Ok(())
    }
}

/// The derived 32-byte vault key. It lives in a HEAP box with a stable address so the page holding
/// it can be `mlock`ed — kept out of swap / hibernation for the key's lifetime — and it is both
/// zeroized AND munlocked on drop (on lock, on rotate, on exit). The lock is exactly `KEY_LEN` bytes,
/// far under any `RLIMIT_MEMLOCK`, so it never fights the 64 MiB Argon2 allocation (which is why this
/// is a per-key lock, not `mlockall`). `Deref` to `[u8; KEY_LEN]` so `seal`/`open` take it unchanged.
pub struct Key32 {
    inner: Box<[u8; KEY_LEN]>,
}

impl Key32 {
    /// A zeroed, mlocked key buffer (filled by the KDF).
    fn zeroed() -> Self {
        let inner = Box::new([0u8; KEY_LEN]);
        lock_pages(inner.as_ptr(), KEY_LEN);
        Key32 { inner }
    }
}

impl Deref for Key32 {
    type Target = [u8; KEY_LEN];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for Key32 {
    fn drop(&mut self) {
        self.inner.zeroize();
        unlock_pages(self.inner.as_ptr(), KEY_LEN);
    }
}

/// mlock `len` bytes at `ptr` — best-effort (a failure just means the key may reach swap; it never
/// breaks the daemon). Linux/unix only.
fn lock_pages(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len);
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}

fn unlock_pages(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}

/// Derive the 32-byte vault key from `password` + `salt` under `params`.
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key32> {
    params.validate()?;
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut key = Key32::zeroed();
    argon2
        .hash_password_into(password, salt, key.inner.as_mut_slice())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Seal `plaintext` under `key`/`nonce`, authenticating `aad`. Returns ciphertext+tag.
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| anyhow!("encryption failed"))
}

/// Open `ciphertext` (ciphertext+tag) under `key`/`nonce`, verifying `aad`. A wrong
/// key, a tampered body, or altered AAD (a downgraded header) all fail here — this
/// AEAD verification IS the wrong-password / corruption check; there is no separate
/// verifier to maintain or brute-force.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("wrong master password (or the vault file is corrupt)"))?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key32 {
        derive_key(b"hunter2", &[7u8; SALT_LEN], KdfParams::default()).unwrap()
    }

    #[test]
    fn derive_is_deterministic() {
        let a = derive_key(b"pw", &[1u8; SALT_LEN], KdfParams::default()).unwrap();
        let b = derive_key(b"pw", &[1u8; SALT_LEN], KdfParams::default()).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn derive_varies_with_salt_and_password() {
        let base = derive_key(b"pw", &[1u8; SALT_LEN], KdfParams::default()).unwrap();
        let other_salt = derive_key(b"pw", &[2u8; SALT_LEN], KdfParams::default()).unwrap();
        let other_pw = derive_key(b"px", &[1u8; SALT_LEN], KdfParams::default()).unwrap();
        assert_ne!(base.as_slice(), other_salt.as_slice());
        assert_ne!(base.as_slice(), other_pw.as_slice());
    }

    #[test]
    fn seal_open_round_trip() {
        let k = key();
        let nonce = [3u8; NONCE_LEN];
        let ct = seal(&k, &nonce, b"header", b"the secret").unwrap();
        let pt = open(&k, &nonce, b"header", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"the secret");
    }

    #[test]
    fn wrong_key_fails() {
        let nonce = [3u8; NONCE_LEN];
        let ct = seal(&key(), &nonce, b"h", b"secret").unwrap();
        let wrong = derive_key(b"nope", &[7u8; SALT_LEN], KdfParams::default()).unwrap();
        assert!(open(&wrong, &nonce, b"h", &ct).is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let k = key();
        let nonce = [3u8; NONCE_LEN];
        let ct = seal(&k, &nonce, b"header-A", b"secret").unwrap();
        // A different header (e.g. a downgraded KDF param) must not authenticate.
        assert!(open(&k, &nonce, b"header-B", &ct).is_err());
    }

    #[test]
    fn tampered_body_fails() {
        let k = key();
        let nonce = [3u8; NONCE_LEN];
        let mut ct = seal(&k, &nonce, b"h", b"secret").unwrap();
        ct[0] ^= 0xff;
        assert!(open(&k, &nonce, b"h", &ct).is_err());
    }

    #[test]
    fn zero_params_rejected() {
        assert!(derive_key(
            b"pw",
            &[1u8; SALT_LEN],
            KdfParams {
                m_cost: 0,
                t_cost: 3,
                p_cost: 4
            }
        )
        .is_err());
    }
}
