-- lvim-keyring.import: one-time migration of PLAINTEXT secrets into the wallet.
--
-- Reads a `.env` (KEY=VALUE, optional `export`, optional quotes, `#` comments) or a `.json` file
-- (`{ "name": "value" }` or `{ "name": { value, user, url, notes } }`) and stores each entry. The
-- source is plaintext on disk — the wizard requires the wallet unlocked, shows a typed confirm with
-- the count, and warns loudly; it never deletes the source. Names are used verbatim (the panel files
-- an unqualified name under `common`). An entry whose NAME already exists in the wallet is SKIPPED,
-- never clobbered — the same no-clobber guarantee `M.migrate` gives (kept in place here rather than
-- delegating to `migrate` so the import's distinct plaintext-on-disk confirm is not double-prompted).
--
---@module "lvim-keyring.import"

local M = {}

--- Strip one layer of matching surrounding quotes from a .env value.
---@param v string
---@return string
local function unquote(v)
    v = vim.trim(v)
    local q = v:sub(1, 1)
    if (q == '"' or q == "'") and v:sub(-1) == q and #v >= 2 then
        return v:sub(2, -2)
    end
    return v
end

--- Parse a `.env` file into `{ { name, value } }`.
---@param lines string[]
---@return { name: string, value: string }[]
local function parse_env(lines)
    local out = {}
    for _, raw in ipairs(lines) do
        local line = vim.trim(raw)
        if line ~= "" and line:sub(1, 1) ~= "#" then
            local key, val = line:match("^export%s+([%w_]+)%s*=%s*(.*)$")
            if not key then
                key, val = line:match("^([%w_]+)%s*=%s*(.*)$")
            end
            if key then
                out[#out + 1] = { name = key, value = unquote(val or "") }
            end
        end
    end
    return out
end

--- Parse a `.json` file into `{ { name, value, meta? } }`.
---@param text string
---@return { name: string, value: string, meta: table? }[]?, string?
local function parse_json(text)
    local ok, obj = pcall(vim.json.decode, text)
    if not ok or type(obj) ~= "table" then
        return nil, "not valid JSON"
    end
    local out = {}
    for name, v in pairs(obj) do
        if type(v) == "string" then
            out[#out + 1] = { name = name, value = v }
        elseif type(v) == "table" and type(v.value) == "string" then
            out[#out + 1] = {
                name = name,
                value = v.value,
                meta = { user = v.user, url = v.url, notes = v.notes },
            }
        end
    end
    return out
end

--- Parse `path`, returning the entries + the detected kind, or an error.
---@param path string
---@return { name: string, value: string, meta: table? }[]?, string? err, string? kind
function M.parse(path)
    if vim.fn.filereadable(path) ~= 1 then
        return nil, "file not readable: " .. path
    end
    local kind = path:match("%.json$") and "json" or "env"
    if kind == "json" then
        local text = table.concat(vim.fn.readfile(path), "\n")
        local entries, err = parse_json(text)
        return entries, err, "json"
    end
    return parse_env(vim.fn.readfile(path)), nil, "env"
end

--- The import wizard: parse → confirm (count + plaintext warning) → unlock → store each.
---@param path string
function M.run(path)
    local entries, err = M.parse(path)
    if err then
        vim.notify("lvim-keyring: import — " .. err, vim.log.levels.WARN)
        return
    end
    if not entries or #entries == 0 then
        vim.notify("lvim-keyring: import — no secrets found in " .. path, vim.log.levels.WARN)
        return
    end
    require("lvim-ui").confirm({
        prompt = ("Import %d secret(s) from %s into the wallet? (the source stays PLAINTEXT on disk)"):format(
            #entries,
            vim.fn.fnamemodify(path, ":~")
        ),
        callback = function(yes)
            if not yes then
                return
            end
            local kr = require("lvim-keyring")
            kr.ensure_unlocked(function(ok, uerr)
                if not ok then
                    if uerr and uerr ~= "" then
                        vim.notify("lvim-keyring: " .. uerr, vim.log.levels.WARN)
                    end
                    return
                end
                -- No-clobber: list present names first and SKIP any candidate already in the wallet, so an
                -- import never overwrites an existing entry's value/meta (same guarantee as M.migrate).
                kr.list(function(existing)
                    local present = {}
                    for _, e in ipairs(existing or {}) do
                        present[e.name] = true
                    end
                    local done, skipped, failed = 0, 0, 0
                    local total = #entries
                    local function report()
                        if done + skipped + failed ~= total then
                            return
                        end
                        local extra = {}
                        if skipped > 0 then
                            extra[#extra + 1] = ("%d skipped"):format(skipped)
                        end
                        if failed > 0 then
                            extra[#extra + 1] = ("%d failed"):format(failed)
                        end
                        vim.notify(
                            ("lvim-keyring: imported %d/%d secret(s)%s"):format(
                                done,
                                total,
                                #extra > 0 and (" (%s)"):format(table.concat(extra, ", ")) or ""
                            ),
                            (failed > 0 or skipped > 0) and vim.log.levels.WARN or vim.log.levels.INFO
                        )
                        if require("lvim-keyring.ui").refresh then
                            pcall(require("lvim-keyring.ui").refresh)
                        end
                    end
                    for _, e in ipairs(entries) do
                        if present[e.name] then
                            skipped = skipped + 1
                            report()
                        else
                            kr.set(e.name, e.value, e.meta, function(sok)
                                if sok then
                                    done = done + 1
                                else
                                    failed = failed + 1
                                end
                                report()
                            end)
                        end
                    end
                end)
            end)
        end,
    })
end

return M
