-- lvim-keyring.ui: the wallet panel (entry browser + actions).
--
-- Placeholder — the full surface-based panel (grouped-by-namespace entry list,
-- add / reveal / copy / rename / delete / generate / lock / rotate, help window)
-- is built in Phase 4. For now `open`/`add` route through the API so the commands
-- are functional before the panel lands.
--
---@module "lvim-keyring.ui"

local M = {}

--- Open the wallet panel (temporary: list entry names until the panel lands).
function M.open()
    require("lvim-keyring").list(function(entries, err)
        if err then
            vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
            return
        end
        local names = {}
        for _, e in ipairs(entries or {}) do
            names[#names + 1] = e.name
        end
        table.sort(names)
        vim.notify(
            #names > 0 and ("lvim-keyring: " .. #names .. " entries — " .. table.concat(names, ", "))
                or "lvim-keyring: no entries yet",
            vim.log.levels.INFO
        )
    end)
end

--- Add an entry: name → masked value.
function M.add()
    local ui = require("lvim-ui")
    ui.input({
        title = "Secret name (e.g. forge/github.com)",
        callback = function(ok, name)
            if not ok or name == "" then
                return
            end
            ui.input({
                title = "Value for " .. name,
                mask = true,
                callback = function(ok2, value)
                    if not ok2 then
                        return
                    end
                    require("lvim-keyring").set(name, value, nil, function(sok, err)
                        vim.notify(
                            sok and ("lvim-keyring: stored " .. name) or ("lvim-keyring: " .. (err or "failed")),
                            sok and vim.log.levels.INFO or vim.log.levels.WARN
                        )
                    end)
                end,
            })
        end,
    })
end

return M
