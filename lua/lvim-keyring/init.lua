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
---@type boolean one unlock prompt at a time (dedupes the daemon's vault.unlock_needed signal)
local prompting = false

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
    -- THE transparent-unlock seam: the daemon PARKS a locked secret read (e.g. an lvim-db `{{ vault }}`
    -- resolve) and signals here; the wallet — not the consumer — pops the master-password prompt. On
    -- cancel we tell the daemon to release the parked readers at once (they get `locked`).
    daemon.on("vault.unlock_needed", function()
        if prompting or unlocked then
            return
        end
        prompting = true
        require("lvim-keyring.ui.prompt").unlock(function(ok)
            prompting = false
            if not ok then
                daemon.request("vault.unlock_cancel", nil, function() end)
            end
        end)
    end)
    require("lvim-keyring.commands").setup()
    require("lvim-utils.cursor").register({ ft = { "LvimKeyring" } })
    -- Eager connect/spawn so the agent is RUNNING and this client is LISTENING from startup — that is
    -- what lets the wallet own the unlock prompt for a `{{ vault }}` resolve even before the user has
    -- opened the panel (a light, locked, idle process until the first unlock; it dies with the editor).
    vim.schedule(function()
        daemon.ensure(function() end)
    end)
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

--- Register a parent NAMESPACE with its icon + accent, so the panel renders `<name>/…` entries with
--- them (and the highlight groups are defined on the spot). A consumer plugin calls this ONCE from its
--- own setup (pcall-guarded, so it never hard-depends on lvim-keyring) — lvim-keyring keeps no list of
--- consumers and hardcodes no names/icons/colours beyond `common`/`default`.
---@param name string
---@param opts { icon?: string, accent?: string, color?: string }?
function M.register_namespace(name, opts)
    require("lvim-keyring.namespaces").register(name, opts)
end

--- The CURRENT TOTP code for a TOTP entry: `cb({ code, remaining, period }, err)`. The base32 secret
--- never leaves the daemon — only the digits + the seconds left in the step cross here.
---@param name string
---@param cb fun(totp: { code: string, remaining: integer, period: integer }?, err: string?)
function M.totp(name, cb)
    daemon.request("secret.totp", { name = name }, function(res, err)
        cb(res, err)
    end)
end

--- Whether an entry NAME already exists in the wallet: `cb(exists, err)`. Names/meta only (no value
--- read); used by consumers migrating plaintext secrets to avoid clobbering a wallet entry.
---@param name string
---@param cb fun(exists: boolean?, err: string?)
function M.has(name, cb)
    M.list(function(entries, err)
        if err then
            cb(nil, err)
            return
        end
        for _, e in ipairs(entries or {}) do
            if e.name == name then
                cb(true)
                return
            end
        end
        cb(false)
    end)
end

--- THE universal migration seam: move plaintext secrets INTO the wallet. A consumer plugin DETECTS its
--- own plaintext (only it knows where its secrets live), builds `candidates = { { name, value, meta? } }`,
--- and hands them here; lvim-keyring does the common part — ensure_unlocked, ONE confirm (with the count),
--- store each that is not already present — then the consumer rewrites its own store to reference the
--- wallet. An entry already in the wallet is SKIPPED (never clobbered). `cb(outcome, err)` where
--- `outcome = { stored = string[], skipped = string[], failed = string[] }` (nil + err on cancel/locked).
---@param candidates { name: string, value: string, meta: table? }[]
---@param cb fun(outcome: { stored: string[], skipped: string[], failed: string[] }?, err: string?)
function M.migrate(candidates, cb)
    cb = cb or function() end
    candidates = candidates or {}
    if #candidates == 0 then
        cb({ stored = {}, skipped = {}, failed = {} })
        return
    end
    M.ensure_unlocked(function(ok, uerr)
        if not ok then
            cb(nil, uerr or "locked")
            return
        end
        require("lvim-ui").confirm({
            prompt = ("Move %d plaintext secret(s) into the encrypted wallet?"):format(#candidates),
            callback = function(yes)
                if not yes then
                    cb(nil, "cancelled")
                    return
                end
                M.list(function(existing)
                    local present = {}
                    for _, e in ipairs(existing or {}) do
                        present[e.name] = true
                    end
                    local outcome = { stored = {}, skipped = {}, failed = {} }
                    local pending = #candidates
                    local function step()
                        pending = pending - 1
                        if pending == 0 then
                            cb(outcome)
                        end
                    end
                    for _, c in ipairs(candidates) do
                        if present[c.name] then
                            table.insert(outcome.skipped, c.name)
                            step()
                        else
                            M.set(c.name, c.value, c.meta, function(sok)
                                table.insert(sok and outcome.stored or outcome.failed, c.name)
                                step()
                            end)
                        end
                    end
                end)
            end,
        })
    end)
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
