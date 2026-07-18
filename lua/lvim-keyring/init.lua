-- lvim-keyring: a password wallet / secrets manager for the lvim-tech set.
--
-- Secrets are encrypted at rest (Argon2id + XChaCha20-Poly1305, all crypto in the
-- Rust daemon under native/), gated behind ONE master password, and reachable by
-- every other lvim-tech plugin through the public API below — plus a
-- `{{ vault "name" }}` template verb wired into lvim-db so its DB drivers resolve
-- wallet secrets with no driver changes.
--
-- This module IS the public API. `setup()` merges user opts into the live config
-- and wires the lock-state cache; the rest is the consumer surface (get/set/…) and
-- the prompt-backed unlock flow. Runtime lives in daemon.lua (the socket client);
-- the crypto and the master key never enter this process.
--
---@module "lvim-keyring"

local daemon = require("lvim-keyring.daemon")
local config = require("lvim-keyring.config")
local utils = require("lvim-utils.utils")

local M = {}

---@type boolean last-known lock state (event-refreshed via the vault.state notification)
local unlocked = false
---@type fun(state: { locked: boolean })[] on_state subscribers
local state_handlers = {}

--- Merge user opts into the live config, wire the lock-state cache + commands.
---@param opts LvimKeyringConfig?
function M.setup(opts)
    utils.merge(config, opts or {})
    local hl = require("lvim-utils.highlight")
    hl.setup()
    hl.bind(require("lvim-keyring.highlights").build)
    daemon.on("vault.state", function(params)
        unlocked = not (params and params.locked)
        for _, h in ipairs(state_handlers) do
            pcall(h, { locked = not unlocked })
        end
    end)
    require("lvim-keyring.commands").setup()
    require("lvim-utils.cursor").register({ ft = { "LvimKeyring" } })
end

-- ─── lock state ──────────────────────────────────────────────────────────────

--- Query the agent's live status: `cb({ locked, vault_exists, entries? }, err)`.
---@param cb fun(status: table?, err: string?)
function M.status(cb)
    daemon.request("vault.status", nil, function(res, err)
        if res then
            unlocked = not res.locked
        end
        cb(res, err)
    end)
end

--- The last-known lock state (event-refreshed). Cheap; for statusline polling.
---@return boolean
function M.is_unlocked()
    return unlocked
end

--- Subscribe to lock/unlock transitions: `handler({ locked })`. For a statusline glyph.
---@param handler fun(state: { locked: boolean })
function M.on_state(handler)
    state_handlers[#state_handlers + 1] = handler
end

--- The UNLOCK flow: prompt to create (first run) or unlock, then `cb(ok, err)`.
---@param cb fun(ok: boolean, err: string?)?
function M.unlock(cb)
    require("lvim-keyring.ui.prompt").unlock(cb or function() end)
end

--- Lock now (zeroizes the agent's key + entries). `cb(ok, err)`.
---@param cb fun(ok: boolean, err: string?)?
function M.lock(cb)
    daemon.request("vault.lock", nil, function(_, err)
        cb = cb or function() end
        cb(err == nil, err)
    end)
end

--- THE consumer seam: run `cb(true)` if already unlocked, else prompt to unlock
--- first. Every plugin that reads a secret goes through this so a locked wallet
--- prompts once instead of failing.
---@param cb fun(ok: boolean, err: string?)
function M.ensure_unlocked(cb)
    M.status(function(status, err)
        if err then
            cb(false, err)
            return
        end
        if status and not status.locked then
            cb(true, nil)
            return
        end
        M.unlock(cb)
    end)
end

-- ─── secret operations ───────────────────────────────────────────────────────

--- Get a secret's VALUE: `cb(value?, err?)`. `err == "locked"` when the wallet is
--- locked — a caller that wants to prompt should wrap with `ensure_unlocked`.
---@param name string
---@param cb fun(value: string?, err: string?)
function M.get(name, cb)
    daemon.request("secret.get", { name = name }, function(res, err)
        cb(res and res.value, err)
    end)
end

--- Synchronous get, bounded by `vim.wait` — for sync seams like lvim-forge's
--- `config.token = function() … end`. Returns `value?, err?`; does NOT prompt (a
--- locked wallet returns `nil, "locked"`; unlock from the editor first).
---@param name string
---@param timeout_ms integer?
---@return string?, string?
function M.get_sync(name, timeout_ms)
    local done, value, error = false, nil, nil
    M.get(name, function(v, e)
        done, value, error = true, v, e
    end)
    vim.wait(timeout_ms or 3000, function()
        return done
    end, 20)
    if not done then
        return nil, "keyring: timed out"
    end
    return value, error
end

--- Store a secret. With `value`, creates or overwrites; with `value == nil`, updates ONLY the `meta`
--- of an existing entry (the value is left untouched). `meta = { user?, url?, notes?, tags? }`.
---@param name string
---@param value string?
---@param meta table?
---@param cb fun(ok: boolean, err: string?)?
function M.set(name, value, meta, cb)
    cb = cb or function() end
    local params = { name = name }
    if value ~= nil then
        params.value = value
    end
    if meta then
        params.meta = meta
    end
    daemon.request("secret.set", params, function(_, err)
        cb(err == nil, err)
    end)
end

--- Delete a secret. `cb(ok, err)`.
---@param name string
---@param cb fun(ok: boolean, err: string?)?
function M.delete(name, cb)
    cb = cb or function() end
    daemon.request("secret.delete", { name = name }, function(_, err)
        cb(err == nil, err)
    end)
end

--- Rename a secret. `cb(ok, err)`.
---@param from string
---@param to string
---@param cb fun(ok: boolean, err: string?)?
function M.rename(from, to, cb)
    cb = cb or function() end
    daemon.request("secret.rename", { from = from, to = to }, function(_, err)
        cb(err == nil, err)
    end)
end

--- List entries — NAMES + META only, never values: `cb(entries?, err?)`.
---@param cb fun(entries: table[]?, err: string?)
function M.list(cb)
    daemon.request("secret.list", nil, function(res, err)
        cb(res and res.entries, err)
    end)
end

--- Generate a password. `opts = { length?, symbols?, store_as? }`. `cb(value?, err?)`.
---@param opts table?
---@param cb fun(value: string?, err: string?)
function M.generate(opts, cb)
    opts = opts or {}
    local params = {
        length = opts.length or config.generate.length,
        symbols = opts.symbols ~= nil and opts.symbols or config.generate.symbols,
    }
    if opts.store_as then
        params.store_as = opts.store_as
    end
    daemon.request("secret.generate", params, function(res, err)
        cb(res and res.value, err)
    end)
end

--- Rotate the master password (prompts old → new → confirm). `cb(ok, err)`.
---@param cb fun(ok: boolean, err: string?)?
function M.rotate(cb)
    require("lvim-keyring.ui.prompt").rotate(cb or function() end)
end

--- A NAMESPACED view of the wallet: every name is prefixed `namespace/`. A consumer passes its own
--- PARENT once — `local kr = require("lvim-keyring").scope("forge")` — then uses BARE names
--- (`kr.get(host, cb)` → resolves `forge/<host>`), instead of baking the prefix into every call and
--- instead of lvim-keyring keeping any list of who its consumers are. Names used through the
--- TOP-LEVEL API (no scope) are verbatim; the panel files an unqualified name under the `common`
--- section. The stored KEY is always the composed `namespace/name`, so a `{{ vault "forge/x" }}`
--- verb (or the git-credential helper) resolves the same entry.
---@param namespace string
---@return table
function M.scope(namespace)
    local prefix = namespace .. "/"
    local function key(name)
        return prefix .. name
    end
    return {
        get = function(name, cb)
            return M.get(key(name), cb)
        end,
        get_sync = function(name, timeout_ms)
            return M.get_sync(key(name), timeout_ms)
        end,
        set = function(name, value, meta, cb)
            return M.set(key(name), value, meta, cb)
        end,
        delete = function(name, cb)
            return M.delete(key(name), cb)
        end,
        rename = function(from, to, cb)
            return M.rename(key(from), key(to), cb)
        end,
    }
end

--- Open the wallet panel (unlocks first if needed).
function M.open()
    M.ensure_unlocked(function(ok, err)
        if not ok then
            if err and err ~= "" then
                vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
            end
            return
        end
        require("lvim-keyring.ui").open()
    end)
end

return M
