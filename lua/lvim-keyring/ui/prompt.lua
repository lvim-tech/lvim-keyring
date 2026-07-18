-- lvim-keyring.ui.prompt: the master-password flows — create, unlock, rotate.
--
-- Every one is a MASKED lvim-ui input (opts.mask → the value renders as `•` and
-- the plaintext never reaches the screen or lingers in a buffer). The flows are
-- the only place the master password transits the editor, and only ever to be
-- sent straight to the agent over the socket. Create requires a confirm (a typo
-- would otherwise seal the vault under a password the user does not know); unlock
-- re-prompts with the agent's error (including its rate-limit delay); rotate walks
-- old → new → confirm.
--
---@module "lvim-keyring.ui.prompt"

local daemon = require("lvim-keyring.daemon")
local ui = require("lvim-ui")

local M = {}

--- A single masked password prompt. `cb(value|nil)` — nil on cancel.
---@param title string
---@param cb fun(value: string?)
local function ask(title, cb)
    ui.input({
        title = title,
        mask = true,
        callback = function(ok, value)
            cb(ok and value or nil)
        end,
    })
end

--- Create a NEW vault: new password + confirm (loops on mismatch), then vault.create.
---@param cb fun(ok: boolean, err: string?)
function M.create(cb)
    ask("Create master password (new vault)", function(pw)
        if not pw or pw == "" then
            cb(false, "cancelled")
            return
        end
        ask("Confirm master password", function(again)
            if again == nil then
                cb(false, "cancelled")
                return
            end
            if again ~= pw then
                vim.notify("lvim-keyring: passwords did not match — try again", vim.log.levels.WARN)
                M.create(cb)
                return
            end
            daemon.request("vault.create", { password = pw }, function(_, err)
                if err then
                    cb(false, err)
                else
                    vim.notify("lvim-keyring: vault created and unlocked", vim.log.levels.INFO)
                    cb(true, nil)
                end
            end)
        end)
    end)
end

--- Unlock an EXISTING vault: one masked prompt, re-prompting on a wrong password.
---@param cb fun(ok: boolean, err: string?)
function M.unlock_existing(cb)
    ask("Master password", function(pw)
        if not pw or pw == "" then
            cb(false, "cancelled")
            return
        end
        daemon.request("vault.unlock", { password = pw }, function(_, err)
            if err then
                vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
                M.unlock_existing(cb)
            else
                cb(true, nil)
            end
        end)
    end)
end

--- The entry point: create on first run, else unlock. Decided by the agent's status.
---@param cb fun(ok: boolean, err: string?)
function M.unlock(cb)
    daemon.request("vault.status", nil, function(status, err)
        if err then
            cb(false, err)
            return
        end
        if status and not status.vault_exists then
            M.create(cb)
        else
            M.unlock_existing(cb)
        end
    end)
end

--- Rotate the master password: old → new → confirm, all masked.
---@param cb fun(ok: boolean, err: string?)
function M.rotate(cb)
    ask("Current master password", function(old)
        if not old or old == "" then
            cb(false, "cancelled")
            return
        end
        ask("New master password", function(new)
            if not new or new == "" then
                cb(false, "cancelled")
                return
            end
            ask("Confirm new master password", function(again)
                if again == nil then
                    cb(false, "cancelled")
                    return
                end
                if again ~= new then
                    vim.notify("lvim-keyring: new passwords did not match", vim.log.levels.WARN)
                    cb(false, "mismatch")
                    return
                end
                daemon.request("vault.rotate", { old_password = old, new_password = new }, function(_, rerr)
                    if rerr then
                        vim.notify("lvim-keyring: " .. rerr, vim.log.levels.WARN)
                        cb(false, rerr)
                    else
                        vim.notify("lvim-keyring: master password changed", vim.log.levels.INFO)
                        cb(true, nil)
                    end
                end)
            end)
        end)
    end)
end

return M
