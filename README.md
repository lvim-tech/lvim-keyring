# lvim-keyring

A **password wallet / secrets manager** for Neovim: secrets **encrypted at rest**, gated behind
**one master password**, reachable by every other lvim-tech plugin through a small public API — and a
`{{ vault "name" }}` template verb that lets **lvim-db** resolve connection credentials from the
wallet with no configuration beyond the template.

The crypto lives entirely in a small **Rust daemon** (Argon2id key derivation + XChaCha20-Poly1305
authenticated encryption). The daemon is a per-user **agent**: it holds the unlocked material in its
own memory (never in the editor), speaks over a per-user unix socket, and is shared by every editor
instance and by lvim-db — one unlock, everywhere, until you lock. Locking (manually, on idle, when the
editor quits, or when the last editor exits) zeroes the key at once.

## How it works

- **The vault** is one sealed file — by default `stdpath("data")/lvim-keyring/keyring.vault` (the same
  `stdpath("data")/lvim-<plugin>/` convention lvim-db and lvim-vault use), overridable with the
  `vault_path` option. Copying that file anywhere is a complete, portable encrypted backup — it is
  useless without the master password.
- **The master password** is run through Argon2id (memory-hard) to derive the encryption key; the KDF
  parameters are stored in the file header, so an old vault keeps opening while new writes can use
  stronger parameters. A wrong password fails the authentication check — there is nothing else to
  guess.
- **The agent** derives and holds the key only while unlocked. It auto-locks after idle time, on an
  explicit lock, when the editor quits (`lock.on_exit`, default on — and since the agent is shared, ANY
  editor's exit locks it for all of them), and when the last editor disconnects. Every secret value
  crosses into the editor only at the moment a consumer explicitly asks for it.
- **Unlock is on-demand and wallet-owned.** A consumer just uses a secret (`{{ vault }}` / `kr.get`);
  if the wallet is locked, the daemon PARKS that read and signals the editor, and lvim-keyring pops the
  master-password prompt itself — then serves the parked read. Consumers never manage unlock. The agent
  starts with the editor (a light, locked, idle process) so it is always listening for this.
- **The panel** browses entries grouped by namespace; it never renders a value. Reveal is an explicit
  keypress into a transient popup; copy puts the value in a register with an auto-clear timer.

## Installation

Requires Neovim >= 0.10, [lvim-utils](https://github.com/lvim-tech/lvim-utils) and
[lvim-ui](https://github.com/lvim-tech/lvim-ui), and a **Rust toolchain** (`cargo`) to build the
daemon.

### lvim-installer (recommended)

Install and manage it from the LVIM package manager — open the **Plugins** tab:

```vim
:LvimInstaller plugins
```

lvim-installer installs plugins through Neovim's built-in `vim.pack`, so no external plugin manager is
needed.

### Native (vim.pack)

```lua
vim.pack.add({ "https://github.com/lvim-tech/lvim-keyring" })
require("lvim-keyring").setup()
```

### Build the daemon

After installing (either way), build the backend once (and after each update):

```sh
sh native/build.sh
```

Without the daemon the plugin still loads; every action reports that the backend must be built (see
`:checkhealth lvim-keyring`).

## Setup

`setup()` merges your options into the live config. The full default configuration — every option at
its default value:

```lua
require("lvim-keyring").setup({
    vault_path = nil, -- default: stdpath("data") .. "/lvim-keyring/keyring.vault"
    socket_path = nil, -- default: $XDG_RUNTIME_DIR/lvim-keyring/agent.sock
    daemon_path = nil, -- explicit daemon binary path (else probe env → native/build → native/target)
    warn_on_missing = true, -- one INFO notification when the daemon is not built
    linger_seconds = 0, -- daemon lifetime after the last client disconnects (0 = lock + die with the last editor)
    persist = false, -- keep the agent alive past the last editor (for terminal git); idle auto-lock still applies
    kdf = { memory_mib = 64, iterations = 3, parallelism = 4 }, -- Argon2id, applied at create/rotate
    lock = {
        timeout_minutes = 15, -- idle auto-lock; 0 = never
        on_exit = true, -- lock when the editor quits; the agent is SHARED, so any nvim's exit re-locks it
    },
    clipboard = { register = "+", clear_seconds = 30 }, -- copy target + auto-clear (0 = never clear)
    generate = { length = 24, symbols = true }, -- generated-password defaults
    ui = { layout = "float" }, -- panel layout: "float" | "area" | "bottom"
    title = "Keyring",
    title_pos = "center", -- "left" | "center" | "right"
    icons = {
        panel = "󰌋",
        locked = "󰌾",
        unlocked = "󰌿",
        entry = "",
        generate = "󰑐",
        expand_closed = "",
        expand_open = "",
    },
    -- lvim-keyring owns ONLY these two accents. Every other parent (db/forge/git/…) — its NAME, ICON
    -- and ACCENT — is registered at runtime by that plugin (see "Namespaces" below); nothing about a
    -- consumer namespace is hardcoded here.
    colors = {
        common = "cyan", -- the catch-all namespace for unqualified names
        default = "blue", -- fallback for a namespace nobody registered
    },
    keymaps = { -- panel / action keys (all remappable)
        add = "a",
        edit = "e",
        rename = "r",
        delete = "d",
        copy = "y",
        reveal = "v",
        generate = "g",
        totp = "t", -- add a TOTP (2FA) entry
        lock = "L",
        rotate = "R",
        help = "?",
    },
})
```

## Usage

- `:LvimKeyring` — open the wallet panel (creates the vault on first run, unlocks otherwise).
- `:LvimKeyring unlock` / `lock` / `status` — manage the lock state.
- `:LvimKeyring add` — add a secret (name → masked value).
- `:LvimKeyring generate` — generate a password into the clipboard register.
- `:LvimKeyring rotate` — change the master password.
- `:LvimKeyring import <path>` — import from a `.env` or `.json` file (confirms; the source stays plaintext).

In the panel (all keys remappable via `config.keymaps`):

| Key | Action |
|-----|--------|
| `a` | add a secret |
| `t` | add a TOTP (2FA) entry |
| `e` | edit the entry's user metadata |
| `r` | rename the entry |
| `d` | delete the entry |
| `y` | copy the value (or TOTP code) to the register (auto-clears) |
| `v` / `<CR>` | reveal the value — or a TOTP entry's current code + countdown — in a popup |
| `g` | generate a password + store it |
| `L` | lock the wallet |
| `R` | rotate the master password |
| `?` | help |

Entries are grouped into **collapsible sections by namespace** — the first `/`-segment of the name;
an unqualified name lives under `common`. A **TOTP entry** stores a base32 2FA secret; reveal/copy show
the current 6-digit code (never the raw secret).

## Public API — for other plugins

lvim-keyring is a **provider**: another plugin reaches in to read or write a secret; lvim-keyring never
depends on, or keeps a list of, its consumers.

```lua
local kr = require("lvim-keyring")

kr.ensure_unlocked(function(ok) end) -- unlocked → cb(true) now; locked → prompt, then cb(ok)
kr.get("forge/github.com", function(value, err) end) -- async; err == "locked" is possible
kr.get_sync("forge/github.com", 3000) -- value?, err? — for sync seams (does not prompt)
kr.set("db/prod", "s3cr3t", { user = "app", url = "…" }, function(ok, err) end)
kr.delete(name, cb) -- kr.rename(from, to, cb) -- kr.list(cb) -- names + meta only, never values
kr.generate({ length = 24, symbols = true, store_as = "db/new" }, function(value, err) end)
kr.totp("forge/github.com-2fa", function(t, err) end) -- { code, remaining, period } for a TOTP entry
kr.is_unlocked() -- boolean (event-refreshed) -- kr.on_state(function(s) end) for a statusline glyph
kr.has("db/prod", function(exists, err) end) -- is the name already stored? (names only, no value)
kr.migrate({ { name = "db/prod", value = "…" } }, function(outcome, err) end) -- move plaintext IN
```

**Migrating plaintext secrets.** `migrate` is the universal seam: a plugin detects its OWN plaintext
(only it knows where its secrets live), hands `{ name, value, meta? }` candidates here, and lvim-keyring
does the common part — unlock, ONE confirm, store each not-already-present — returning
`{ stored, skipped, failed }` so the caller can rewrite its store to reference the wallet. lvim-db uses
this for `:LvimDb keyring-migrate` (it scans saved connections for literal passwords, stores them under
`db/<name>`, and rewrites each to `{{ vault "db/<name>" }}`).

**Namespaces — register your parent once, don't hardcode it here.** lvim-keyring hardcodes NO consumer
namespace: only `common` (catch-all) and `default` (fallback). A plugin registers its own parent once,
with an icon + accent, and everyone then uses the registered parent:

```lua
-- in the consuming plugin's setup (pcall-guarded so it never hard-depends on lvim-keyring):
pcall(function()
    require("lvim-keyring").register_namespace("forge", { icon = "", accent = "magenta" })
end)
```

Then read/write with a namespaced view (bare names, no baked prefix):

```lua
local kr = require("lvim-keyring").scope("forge")
kr.get("github.com", function(token) end) -- resolves "forge/github.com"
kr.set("gitlab.com", token) -- stores "forge/gitlab.com"
```

The stored key is always `namespace/name`, so a `{{ vault "forge/github.com" }}` template resolves the
same entry. lvim-db registers `db`, lvim-forge registers `forge`, lvim-git registers `git` — automatically, when installed. An unregistered namespace renders with the default accent + a key icon; nothing breaks.

### lvim-db credentials — the `{{ vault }}` template

lvim-db's connection form accepts credential **templates**; add the wallet as one:

```
Password:  {{ vault "db/prod" }}
```

lvim-db's daemon reads that secret from the wallet's socket at connect time — no driver or plugin
configuration needed. If the wallet is **locked**, the daemon PARKS the resolve and lvim-keyring pops
its own master-password prompt (the agent runs from editor startup and listens for exactly this); the
connect then proceeds transparently once you unlock. The consumer plugin does nothing — the wallet
owns the unlock. This is the general contract for any `{{ vault }}` / `kr.get` consumer.

### lvim-forge tokens

lvim-forge resolves its API token from the wallet automatically when installed: `forge/<host>` is
tried between the `config` token and the `GITHUB_TOKEN`-style env var. Store one with a masked prompt:

```vim
:LvimForge auth store github.com
```

`:checkhealth lvim-forge` reports the token source as `keyring` once it resolves from the wallet.

### git over HTTPS — the credential helper

The daemon ships a git credential helper, so `git push`/`fetch` over HTTPS (from lvim-git or the
terminal) read the token from the wallet with no per-repo setup. Wire it once:

```sh
git config --global credential.helper '!/absolute/path/to/lvim-keyring-daemon git-credential'
```

It looks up `git/<host>` first, then falls back to `forge/<host>` (a forge PAT is the HTTPS password
for GitHub/GitLab), so one stored token serves both. When the wallet is locked or absent, the helper
stays silent and git prompts as usual — it never blocks a push.

## Security

**Protected against:**

- **Theft of the vault file, a backup, or the whole disk (at rest).** Argon2id (64 MiB / 3 / 4 by
  default) + XChaCha20-Poly1305; the only offline attack is a password-guessing run priced by the KDF.
  Entry names, count and timestamps are inside the ciphertext, not leaked by the file.
- **Tampering.** The Poly1305 tag covers the body, and the file header (KDF parameters + salt) is the
  authenticated associated data — a bit-flip, a parameter downgrade, or a swapped salt all fail to
  authenticate, they do not silently weaken the vault.
- **Other users on the machine.** The socket directory is `0700`, the socket `0600`, and a connecting
  peer's uid is checked; `$XDG_RUNTIME_DIR` is a per-user tmpfs. Core dumps and non-root ptrace of the
  daemon are blocked.
- **Forgotten sessions.** Idle auto-lock, lock-on-editor-exit (default; any editor), lock-on-last-editor-exit, an explicit lock, and a clipboard
  auto-clear.

**Honest limitations** — stated so you can decide if they matter to you:

- **Any process of the same user can read a secret while the wallet is unlocked** — including any
  Neovim plugin. This is the ssh-agent / OS-keyring model; per-caller authorization inside one uid is
  not meaningfully enforceable, and this does not pretend to. What the design DOES guarantee is that the
  master key and the at-rest store never live in the editor, plaintext exists in Lua only per-value at
  explicit use, and locking revokes everything at once.
- **The master password transits the editor once per unlock** (typed into a scratch buffer, sent to the
  agent, the buffer wiped). Lua strings cannot be zeroed; a memory snapshot of Neovim taken mid-prompt
  could contain it. The derived key and the decrypted entries never enter the editor.
- **Unlocked material may reach unencrypted swap / hibernation.** Use encrypted swap or zram if that
  matters to you.
- **A revealed or copied value is in editor memory / the system clipboard** by necessity while you use
  it; the wallet bounds the exposure (per-value, at explicit use, revocable) but cannot make it not
  exist.

## Health

`:checkhealth lvim-keyring` reports the daemon binary, whether the agent is reachable over its socket,
the vault's existence and lock state, the socket directory posture, and whether the git credential
helper is wired.

## Highlights

Every group is defined from the live lvim-utils palette (re-applied on `ColorScheme`): per-namespace
badge/name accents (`LvimKeyringBadge*` / `LvimKeyringName*`) and the neutral text / meta / value
tones. Override colours through `config.colors` (a palette key or `#rrggbb`), never by redefining the
groups.
