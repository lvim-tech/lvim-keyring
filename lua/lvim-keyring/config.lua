-- lvim-keyring.config: the live configuration.
--
-- This table IS the effective config: `setup()` merges the user's opts into it in
-- place (via lvim-utils.utils.merge), and every reader does
-- `require("lvim-keyring.config")` — so there is one source of truth, not a copy
-- passed around. Runtime state (the socket handle, the last-known lock flag) lives
-- in `state.lua`, never here.
--
---@module "lvim-keyring.config"

---@class LvimKeyringKdf
---@field memory_mib integer  Argon2id memory cost, MiB (applied at create/rotate)
---@field iterations integer  Argon2id time cost (passes)
---@field parallelism integer Argon2id lanes

---@class LvimKeyringLock
---@field timeout_minutes integer  idle auto-lock; 0 = never

---@class LvimKeyringClipboard
---@field register string      the register a value is yanked into (e.g. "+")
---@field clear_seconds integer seconds after which the copied value is auto-cleared (0 = never)

---@class LvimKeyringGenerate
---@field length integer   generated-password length
---@field symbols boolean  include punctuation

---@class LvimKeyringConfig
---@field vault_path string?    default: stdpath("data").."/lvim-keyring/keyring.vault"
---@field socket_path string?   default: $XDG_RUNTIME_DIR/lvim-keyring/agent.sock
---@field daemon_path string?   explicit daemon binary path (else probe env → native/build → native/target)
---@field warn_on_missing boolean  one INFO notification when the daemon is not built
---@field linger_seconds integer   daemon lifetime after the last client disconnects (0 = die with the last editor)
---@field persist boolean          keep the agent alive past the last editor (opt-in; for terminal git). Idle auto-lock still applies
---@field kdf LvimKeyringKdf
---@field lock LvimKeyringLock
---@field clipboard LvimKeyringClipboard
---@field generate LvimKeyringGenerate
---@field ui { layout: string }   panel layout: "float" | "area" | "bottom"
---@field title string       panel title
---@field title_pos "left"|"center"|"right"
---@field icons table<string, string>   Nerd-Font glyphs (single-width, verified)
---@field colors table<string, string>  namespace accents (palette key or "#rrggbb")
---@field keymaps table<string, string>  panel/action keys (all remappable)

---@type LvimKeyringConfig
local M = {
    vault_path = nil,
    socket_path = nil,
    daemon_path = nil,
    warn_on_missing = true,
    linger_seconds = 0,
    persist = false,
    kdf = { memory_mib = 64, iterations = 3, parallelism = 4 },
    lock = { timeout_minutes = 15 },
    clipboard = { register = "+", clear_seconds = 30 },
    generate = { length = 24, symbols = true },
    ui = { layout = "float" },
    title = "Keyring",
    title_pos = "center",
    icons = {
        panel = "󰌋", -- nf-md-key_variant
        locked = "󰌾", -- nf-md-lock
        unlocked = "󰌿", -- nf-md-lock_open_variant
        entry = "", -- nf-fa-key
        generate = "󰑐", -- nf-md-refresh
        expand_closed = "", -- nf-fa-caret_right
        expand_open = "", -- nf-fa-caret_down
    },
    -- lvim-keyring owns ONLY these two accents: `common` (the catch-all namespace for unqualified
    -- names) and `default` (the fallback for a namespace nobody registered). Every OTHER parent
    -- (db / forge / git / …) — its NAME, ICON and ACCENT — is registered at runtime by that plugin
    -- via require("lvim-keyring").register_namespace(name, { icon, accent }); nothing about them is
    -- hardcoded here.
    colors = {
        common = "cyan",
        default = "blue",
    },
    keymaps = {
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
}

return M
