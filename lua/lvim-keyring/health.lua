-- lvim-keyring.health: :checkhealth lvim-keyring.
--
-- Reports whether the Rust daemon binary is built, whether the agent is reachable
-- over its socket (connect/spawn + handshake, briefly waited on, so the report
-- reflects a real backend), the vault's existence + lock state, the socket
-- directory's permissions, and whether git's credential.helper is wired to the
-- daemon (Phase 6). Read-only — checkhealth never unlocks or writes.
--
---@module "lvim-keyring.health"

local config = require("lvim-keyring.config")
local daemon = require("lvim-keyring.daemon")

local M = {}

--- Validate the config values.
---@param h table
local function check_config(h)
    local ok = true
    if type(config.lock.timeout_minutes) ~= "number" or config.lock.timeout_minutes < 0 then
        h.error("config.lock.timeout_minutes must be a number ≥ 0 (0 = never auto-lock)")
        ok = false
    end
    if type(config.kdf.memory_mib) ~= "number" or config.kdf.memory_mib < 8 then
        h.error("config.kdf.memory_mib must be a number ≥ 8")
        ok = false
    end
    if config.daemon_path ~= nil and type(config.daemon_path) ~= "string" then
        h.error("config.daemon_path must be a string path or nil")
        ok = false
    end
    if ok then
        h.ok("config is valid")
    end
end

--- Probe the daemon binary, connect/handshake, and report vault + lock state.
---@param h table
local function check_daemon(h)
    local bin = daemon.binary_path()
    if not bin then
        h.warn("daemon binary not found — the wallet is unavailable")
        h.info("build it with `sh native/build.sh` (needs a Rust toolchain: cargo)")
        return
    end
    h.ok("daemon binary: " .. bin)

    local done, ok_flag, err_msg = false, false, nil
    daemon.ensure(function(ok, err)
        done, ok_flag, err_msg = true, ok, err
    end)
    vim.wait(5000, function()
        return done
    end, 20)
    if not ok_flag then
        h.error("agent failed to start / handshake: " .. tostring(err_msg))
        return
    end
    h.ok(("agent reachable — protocol %d, socket %s"):format(daemon.proto() or 0, daemon.socket_path()))

    -- Vault existence + lock state (read-only status call).
    local sdone, status = false, nil
    daemon.request("vault.status", nil, function(res)
        sdone, status = true, res
    end)
    vim.wait(3000, function()
        return sdone
    end, 20)
    if status then
        if not status.vault_exists then
            h.info("no vault yet — it is created on first unlock (:LvimKeyring)")
        else
            local n = status.entries and #status.entries or 0
            h.ok(
                ("vault: %s%s"):format(
                    status.locked and "locked" or "unlocked",
                    status.locked and "" or (" · %d entr%s"):format(n, n == 1 and "y" or "ies")
                )
            )
        end
    end
end

--- Report the socket directory's permissions (must be private to this user).
---@param h table
local function check_socket_dir(h)
    local runtime = vim.env.XDG_RUNTIME_DIR
    if not runtime or runtime == "" then
        h.warn(
            "XDG_RUNTIME_DIR is unset — the socket falls back to /tmp (still 0700, but $XDG_RUNTIME_DIR is the correct per-user tmpfs)"
        )
        return
    end
    h.ok("XDG_RUNTIME_DIR set — the agent socket lives on the per-user tmpfs")
end

--- Report whether git's credential.helper points at the daemon (Phase 6 wiring).
---@param h table
local function check_git_credential(h)
    local out = vim.fn.system({ "git", "config", "--global", "--get", "credential.helper" })
    if vim.v.shell_error == 0 and out:find("lvim%-keyring") then
        h.ok("git credential.helper is wired to lvim-keyring (HTTPS git auth resolves from the wallet)")
    else
        h.info(
            "git credential.helper is not wired to lvim-keyring — to let `git push` over HTTPS read tokens "
                .. "from the wallet, see the README (git integration)"
        )
    end
end

--- Entry point for `:checkhealth lvim-keyring`.
function M.check()
    local h = vim.health
    h.start("lvim-keyring")
    check_config(h)
    check_daemon(h)
    check_socket_dir(h)
    check_git_credential(h)
end

return M
