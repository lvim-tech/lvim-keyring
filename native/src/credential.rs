// lvim-keyring-native/credential: the `git-credential` helper subcommand.
//
// git resolves HTTPS credentials through helper programs that speak a tiny stdin/stdout key=value
// protocol (`git help credential`). Wired once with
//   git config --global credential.helper '!<path>/lvim-keyring-daemon git-credential'
// git then calls `… git-credential get|store|erase`, and THIS module answers from the wallet — so
// `git push` over HTTPS (and terminal git) resolve tokens from the same encrypted store, with no
// lvim-git code involved. Looks up `git/<host>` first, then `forge/<host>` (a forge PAT IS the HTTPS
// password for GitHub/GitLab), so a token stored once for the forge serves git too.
//
// This runs as a SHORT-LIVED subprocess before any tokio runtime, so it uses a plain blocking
// std unix socket. A locked / absent wallet prints nothing and exits 0 — git then prompts as usual
// (the helper must never block git with an error).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

/// The agent socket path: `$LVIM_KEYRING_SOCK`, else `$XDG_RUNTIME_DIR/lvim-keyring/agent.sock`.
fn socket_path() -> Option<String> {
    if let Ok(s) = std::env::var("LVIM_KEYRING_SOCK") {
        if !s.is_empty() {
            return Some(s);
        }
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok().filter(|s| !s.is_empty())?;
    Some(format!("{runtime}/lvim-keyring/agent.sock"))
}

/// Read git's key=value lines from stdin until a blank line / EOF.
fn read_attrs() -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once('=') {
            attrs.insert(k.to_string(), v.to_string());
        }
    }
    attrs
}

/// One request/response against the agent (blocking). Returns the parsed JSON response, or None on
/// any I/O / connect failure (the caller then behaves as "no credential").
fn rpc(method: &str, params: serde_json::Value) -> Option<serde_json::Value> {
    let path = socket_path()?;
    let mut stream = UnixStream::connect(path).ok()?;
    let req = serde_json::json!({ "id": 1, "method": method, "params": params }).to_string();
    stream.write_all(req.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    stream.flush().ok()?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut buf = Vec::new();
        let n = read_line(&mut reader, &mut buf)?;
        if n == 0 {
            return None;
        }
        let text = String::from_utf8_lossy(&buf);
        let msg: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
        if msg.get("id").and_then(serde_json::Value::as_u64) != Some(1) {
            continue; // a notification — skip
        }
        return Some(msg);
    }
}

/// Read one `\n`-terminated line into `buf`; returns bytes read (0 = EOF).
fn read_line<R: Read>(reader: &mut BufReader<R>, buf: &mut Vec<u8>) -> Option<usize> {
    let mut byte = [0u8; 1];
    let mut n = 0;
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Some(n),
            Ok(_) => {
                n += 1;
                if byte[0] == b'\n' {
                    return Some(n);
                }
                buf.push(byte[0]);
            }
            Err(_) => return None,
        }
    }
}

/// Fetch `git/<host>` then fall back to `forge/<host>`; returns (value, user?).
fn lookup(host: &str) -> Option<(String, Option<String>)> {
    for name in [format!("git/{host}"), format!("forge/{host}")] {
        if let Some(msg) = rpc("secret.get", serde_json::json!({ "name": name })) {
            if msg.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                let value = msg
                    .pointer("/result/value")
                    .and_then(serde_json::Value::as_str)?
                    .to_string();
                let user = msg
                    .pointer("/result/meta/user")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);
                return Some((value, user));
            }
        }
    }
    None
}

/// Run the `git-credential <op>` subcommand. Returns the process exit code (always 0 — a helper must
/// not fail git; "no answer" is silence, and git falls back to prompting).
pub fn run(op: &str) -> i32 {
    let attrs = read_attrs();
    let host = match attrs.get("host") {
        Some(h) => h.clone(),
        None => return 0,
    };
    match op {
        "get" => {
            if let Some((value, user)) = lookup(&host) {
                let stdout = std::io::stdout();
                let mut out = stdout.lock();
                // A username git already knows is echoed back; else the entry's user meta if any.
                let uname = attrs.get("username").cloned().or(user);
                if let Some(u) = uname {
                    let _ = writeln!(out, "username={u}");
                }
                let _ = writeln!(out, "password={value}");
            }
        }
        "store" => {
            // Best-effort: persist what git captured under `git/<host>` (only if unlocked).
            if let Some(password) = attrs.get("password") {
                let mut params = serde_json::json!({ "name": format!("git/{host}"), "value": password });
                if let Some(u) = attrs.get("username") {
                    params["meta"] = serde_json::json!({ "user": u });
                }
                let _ = rpc("secret.set", params);
            }
        }
        "erase" => {
            let _ = rpc("secret.delete", serde_json::json!({ "name": format!("git/{host}") }));
        }
        _ => {}
    }
    0
}
