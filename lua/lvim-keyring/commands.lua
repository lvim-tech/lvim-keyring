-- lvim-keyring.commands: the `:LvimKeyring` command + its subcommands.
--
-- `:LvimKeyring` with no argument opens the panel (unlocking first if needed);
-- the subcommands are the scriptable surface — unlock / lock / status / add /
-- generate / rotate. Registered once from `setup()`.
--
---@module "lvim-keyring.commands"

local M = {}

--- The subcommand table: name → handler. Kept here so completion and dispatch
--- read from ONE list.
---@type table<string, fun()>
local subs

--- Build the subcommand handlers lazily (they require the API, which requires this).
---@return table<string, fun()>
local function build()
    local kr = require("lvim-keyring")
    return {
        unlock = function()
            kr.unlock()
        end,
        lock = function()
            kr.lock(function(ok)
                if ok then
                    vim.notify("lvim-keyring: locked", vim.log.levels.INFO)
                end
            end)
        end,
        status = function()
            kr.status(function(st, err)
                if err then
                    vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
                    return
                end
                local n = st.entries and #st.entries or 0
                vim.notify(
                    ("lvim-keyring: %s%s"):format(
                        st.locked and "locked" or "unlocked",
                        st.vault_exists and (" · %d entr%s"):format(n, n == 1 and "y" or "ies") or " · no vault yet"
                    ),
                    vim.log.levels.INFO
                )
            end)
        end,
        add = function()
            require("lvim-keyring.ui").add()
        end,
        generate = function()
            kr.generate({}, function(value, err)
                if err then
                    vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
                    return
                end
                vim.fn.setreg(require("lvim-keyring.config").clipboard.register, value)
                vim.notify("lvim-keyring: generated a password (copied to register)", vim.log.levels.INFO)
            end)
        end,
        rotate = function()
            kr.rotate()
        end,
        import = function(args)
            local path = args and args[1]
            if path and path ~= "" then
                require("lvim-keyring.import").run(vim.fn.expand(path))
                return
            end
            require("lvim-ui").input({
                title = "Import secrets from file (.env or .json)",
                callback = function(ok, value)
                    if ok and value and value ~= "" then
                        require("lvim-keyring.import").run(vim.fn.expand(vim.trim(value)))
                    end
                end,
            })
        end,
    }
end

--- Register the `:LvimKeyring` user command.
function M.setup()
    subs = build()
    vim.api.nvim_create_user_command("LvimKeyring", function(opts)
        local sub = opts.fargs[1]
        if not sub then
            require("lvim-keyring").open()
            return
        end
        local handler = subs[sub]
        if handler then
            handler(vim.list_slice(opts.fargs, 2))
        else
            vim.notify("lvim-keyring: unknown subcommand '" .. sub .. "'", vim.log.levels.WARN)
        end
    end, {
        nargs = "*",
        desc = "lvim-keyring wallet",
        complete = function(arglead)
            local names = vim.tbl_keys(subs)
            table.sort(names)
            return vim.tbl_filter(function(n)
                return n:find(arglead, 1, true) == 1
            end, names)
        end,
    })
end

return M
