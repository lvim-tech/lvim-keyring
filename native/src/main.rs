// lvim-keyring-daemon: the per-user secrets agent.
//
// Neovim's Lua connects to (or spawns) this binary and speaks newline-delimited
// JSON (see rpc.rs) over a per-user UNIX SOCKET — not stdio — because the wallet
// has TWO client kinds: the owning editor AND a sibling process (lvim-db-daemon
// resolving a `{{ vault "…" }}` template). A shared socket is the ssh-agent seam
// that makes that second client a trivial one-shot connection and gives a shared
// unlock across editor instances. A `--stdio` mode (one session on stdin/stdout,
// identical dispatch) exists purely for scripted verification.
//
// The master key and the decrypted entries live ONLY in this process's RAM, wiped
// on lock/exit; `PR_SET_DUMPABLE(0)` blocks core dumps and non-root ptrace of the
// unlocked key.

mod credential;
mod crypto;
mod rpc;
mod server;
mod totp;
mod vault;

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::crypto::KdfParams;
use crate::rpc::Request;
use crate::server::{Config, Server};

fn main() {
    harden();
    let args: Vec<String> = std::env::args().collect();

    // The git-credential helper is a short-lived subcommand (blocking std sockets); it must run
    // BEFORE any tokio runtime is built, and never starts the agent.
    if args.get(1).map(String::as_str) == Some("git-credential") {
        std::process::exit(credential::run(args.get(2).map(String::as_str).unwrap_or("")));
    }

    // Mode selection from argv; everything else comes from the environment the Lua
    // side sets at spawn (with standalone defaults so the daemon is usable alone).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    match args.get(1).map(String::as_str) {
        Some("--stdio") => rt.block_on(serve_stdio(Server::new(config_from_env(None)))),
        Some("--socket") => {
            let path = match args.get(2) {
                Some(p) => PathBuf::from(p),
                None => {
                    eprintln!("lvim-keyring-daemon: --socket needs a path");
                    std::process::exit(2);
                }
            };
            rt.block_on(serve_socket(Server::new(config_from_env(Some(path.clone()))), path));
        }
        _ => {
            eprintln!("usage: lvim-keyring-daemon (--socket <path> | --stdio)");
            std::process::exit(2);
        }
    }
}

/// Block core dumps + non-root ptrace of this process, so the unlocked key cannot
/// be scraped from a core file or an attached debugger. Linux-only; a no-op else.
fn harden() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

/// Build the daemon config from the environment (the Lua side sets these at spawn),
/// with standalone defaults. `socket_override` is the `--socket` path, kept only for
/// symmetry — the socket path itself is not part of Config.
fn config_from_env(_socket_override: Option<PathBuf>) -> Config {
    let vault_path = std::env::var_os("LVIM_KEYRING_VAULT")
        .map(PathBuf::from)
        .unwrap_or_else(default_vault_path);
    let kdf = KdfParams {
        m_cost: env_u32("LVIM_KEYRING_KDF_M", KdfParams::default().m_cost),
        t_cost: env_u32("LVIM_KEYRING_KDF_T", KdfParams::default().t_cost),
        p_cost: env_u32("LVIM_KEYRING_KDF_P", KdfParams::default().p_cost),
    };
    let lock_timeout = Duration::from_secs(env_u64("LVIM_KEYRING_LOCK_TIMEOUT", 15 * 60));
    let linger = Duration::from_secs(env_u64("LVIM_KEYRING_LINGER", 0));
    let persist = std::env::var("LVIM_KEYRING_PERSIST").ok().as_deref() == Some("1");
    Config {
        vault_path,
        kdf,
        lock_timeout,
        linger,
        persist,
    }
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

/// The default vault path when the environment does not name one (a standalone daemon). Mirrors
/// Neovim's `stdpath("data")` = `$XDG_DATA_HOME/nvim` (else `~/.local/share/nvim`), so a standalone
/// daemon agrees with the editor-spawned one. The editor always passes `LVIM_KEYRING_VAULT`, so this
/// is only the last-resort fallback.
fn default_vault_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".local/share")
    });
    base.join("nvim").join("lvim-keyring").join("keyring.vault")
}

// ── stdio transport (verification) ───────────────────────────────────────────

async fn serve_stdio(server: Server) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let client_id = server.register_client(tx.clone());
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(line) = rx.recv().await {
            if stdout.write_all(line.as_bytes()).await.is_err() || stdout.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if let Ok(req) = serde_json::from_str::<Request>(&line) {
            let server = server.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                server.handle(req, &tx).await;
            });
        }
    }
    // EOF (stdin closed) → drop our writer channel AND the registered client clone,
    // so the writer task's receiver runs dry and the process can exit cleanly.
    server.unregister_client(client_id);
    drop(tx);
    let _ = writer.await;
}

// ── unix-socket transport (primary) ──────────────────────────────────────────

async fn serve_socket(server: Server, path: PathBuf) {
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("lvim-keyring-daemon: cannot create socket dir: {e}");
            std::process::exit(1);
        }
        set_mode(dir, 0o700);
    }
    // A stale socket from a crashed daemon would block bind — remove it first. (If a
    // LIVE daemon owns it, our own connect-before-spawn on the Lua side means we never
    // reach here; a leftover file is safe to clear.)
    let _ = std::fs::remove_file(&path);

    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lvim-keyring-daemon: cannot bind {}: {e}", path.display());
            std::process::exit(1);
        }
    };
    set_mode(&path, 0o600);

    // Idle auto-lock timer.
    {
        let server = server.clone();
        tokio::spawn(async move {
            loop {
                let secs = server.autolock_tick();
                tokio::time::sleep(Duration::from_secs(secs)).await;
            }
        });
    }

    // SIGTERM → lock (zeroize) + exit, so the wallet never survives a kill unlocked.
    {
        let server = server.clone();
        let path = path.clone();
        tokio::spawn(async move {
            if let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                sig.recv().await;
                server.lock();
                let _ = std::fs::remove_file(&path);
                std::process::exit(0);
            }
        });
    }

    let my_uid = current_uid();
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Only the owning user may connect (defence-in-depth atop the 0700 dir).
                match stream.peer_cred() {
                    Ok(cred) if cred.uid() == my_uid => {}
                    _ => continue, // wrong uid, or cred unavailable → refuse
                }
                let server = server.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    handle_conn(server, stream, path).await;
                });
            }
            Err(_) => continue,
        }
    }
}

/// One socket connection: a reader loop feeding dispatch, a single writer task so
/// response/notification lines never interleave. On disconnect, if no clients
/// remain the daemon locks and exits (after `linger`), so the wallet dies — and
/// therefore locks — with the last editor.
async fn handle_conn(server: Server, stream: UnixStream, sock_path: PathBuf) {
    let (read, write) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let client_id = server.register_client(tx.clone());

    let writer = tokio::spawn(async move {
        let mut w = write;
        while let Some(line) = rx.recv().await {
            if w.write_all(line.as_bytes()).await.is_err() || w.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = w.flush().await;
        }
    });

    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if let Ok(req) = serde_json::from_str::<Request>(&line) {
            let server = server.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                server.handle(req, &tx).await;
            });
        }
    }

    // Unregister BEFORE awaiting the writer: the clients map holds a clone of this connection's
    // sender, so the writer's receiver only runs dry once BOTH `tx` and that clone are gone — drop
    // one and remove the other, then the writer task returns.
    drop(tx);
    let remaining = server.unregister_client(client_id);
    let _ = writer.await;
    if remaining == 0 {
        // Persist mode: keep running (unlocked, until idle-lock / SIGTERM) so terminal git can still
        // resolve credentials with no editor open. The socket stays.
        if server.persist() {
            return;
        }
        let linger = server.linger();
        if linger.is_zero() {
            server.lock();
            let _ = std::fs::remove_file(&sock_path);
            std::process::exit(0);
        } else {
            let server2 = server.clone();
            let sock_path = sock_path.clone();
            tokio::spawn(async move {
                tokio::time::sleep(linger).await;
                if server2.client_count() == 0 {
                    server2.lock();
                    let _ = std::fs::remove_file(&sock_path);
                    std::process::exit(0);
                }
            });
        }
    }
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    unsafe {
        libc::getuid()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn set_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}
