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
---@field kdf LvimKeyringKdf
---@field lock LvimKeyringLock
---@field clipboard LvimKeyringClipboard
---@field generate LvimKeyringGenerate
---@field ui { layout: string }   panel layout: "float" | "area" | "bottom"
---@field keymaps table<string, string>  panel/action keys (all remappable)

---@type LvimKeyringConfig
local M = {
    vault_path = nil,
    socket_path = nil,
    daemon_path = nil,
    warn_on_missing = true,
    linger_seconds = 0,
    kdf = { memory_mib = 64, iterations = 3, parallelism = 4 },
    lock = { timeout_minutes = 15 },
    clipboard = { register = "+", clear_seconds = 30 },
    generate = { length = 24, symbols = true },
    ui = { layout = "float" },
    keymaps = {
        add = "a",
        edit = "e",
        rename = "r",
        delete = "d",
        copy = "y",
        reveal = "v",
        generate = "g",
        lock = "L",
        rotate = "R",
        help = "?",
    },
}

return M
