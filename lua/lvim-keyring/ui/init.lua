-- lvim-keyring.ui: the wallet panel — a grouped entry browser + actions.
--
-- Built on lvim-ui.tabs (the canonical surface chassis — never a raw float). ONE tab whose rows are
-- collapsible SECTIONS by namespace (db/, forge/, git/, common/), each entry a badge + name + dimmed
-- meta; the VALUE is never rendered. The footer carries the wallet-wide actions (add / generate /
-- lock / rotate) and the help chip; the per-row action keys (add / edit / rename / delete / copy /
-- reveal / generate) resolve the entry under the cursor through a registry. Reveal shows the value in
-- a transient popup; copy yanks it with an auto-clear timer. Every mutation re-lists and rebuilds.
--
---@module "lvim-keyring.ui"

local config = require("lvim-keyring.config")
local highlights = require("lvim-keyring.highlights")
local rows = require("lvim-keyring.ui.rows")
local ui = require("lvim-ui")

local M = {}

---@class LvimKeyringUiState
---@field handle table?            the ui.tabs handle
---@field entries table[]          the last-listed entries (names + meta, NO values)
---@field registry table<string, table>  row name → entry
---@field collapsed table<string, boolean>  namespace → collapsed?
---@field layout string?           session-sticky per-open layout override
local state = {
    handle = nil,
    tabs = nil, ---@type table[]?  the live tabs spec (rows mutated in place + recalc)
    entries = {},
    registry = {},
    collapsed = {},
    layout = nil,
    counts = { current = 0, total = 0 },
}

local kr -- lazy require of the API (avoids a load cycle: init → ui → init)
local function api()
    kr = kr or require("lvim-keyring")
    return kr
end

-- ── building the rows ─────────────────────────────────────────────────────────

--- Group the entries by namespace, sorted; returns an ordered list of `{ ns, entries }`.
---@return { ns: string, entries: table[] }[]
local function grouped()
    local buckets = {}
    for _, e in ipairs(state.entries) do
        local ns = rows.namespace(e.name)
        buckets[ns] = buckets[ns] or {}
        table.insert(buckets[ns], e)
    end
    local names = vim.tbl_keys(buckets)
    table.sort(names)
    local out = {}
    for _, ns in ipairs(names) do
        table.sort(buckets[ns], function(a, b)
            return a.name < b.name
        end)
        out[#out + 1] = { ns = ns, entries = buckets[ns] }
    end
    return out
end

--- Build the tab's rows: one collapsible section per namespace (or an empty-state row). Updates the
--- title counter (shown-in-expanded / total).
---@return table[]
local function build_rows()
    state.registry = {}
    if #state.entries == 0 then
        state.counts = { current = 0, total = 0 }
        return { rows.empty("No secrets yet — add one with " .. config.keymaps.add .. ", or :LvimKeyring add.") }
    end
    local out, shown = {}, 0
    for _, g in ipairs(grouped()) do
        local expanded = state.collapsed[g.ns] ~= true
        local children = {}
        if expanded then
            local namew = rows.name_width(g.entries)
            for _, e in ipairs(g.entries) do
                children[#children + 1] = rows.entry_row(e, state.registry, function(entry, _close)
                    -- <CR> on a row reveals the value in place (panel stays open); never closes.
                    M.reveal(entry.name)
                end, namew)
            end
            shown = shown + #g.entries
        end
        local accent = rows.accent(g.ns)
        out[#out + 1] = rows.section(
            "kr_sec_" .. g.ns,
            g.ns:upper(),
            #g.entries,
            expanded,
            children,
            accent,
            "LvimKeyringBadge" .. highlights.suffix(g.ns)
        )
    end
    state.counts = { current = shown, total = #state.entries }
    return out
end

--- The entry under the cursor, or nil.
---@return table?
local function cur_entry()
    local name = state.handle and state.handle.cursor_name and state.handle.cursor_name()
    return name and state.registry[name] or nil
end

-- ── refresh ─────────────────────────────────────────────────────────────────

--- Re-list from the agent and rebuild the open panel, keeping the cursor line.
function M.refresh()
    if not (state.handle and state.handle.valid and state.handle.valid()) then
        return
    end
    api().list(function(entries, err)
        if err then
            vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
            return
        end
        state.entries = entries or {}
        if not (state.handle and state.handle.valid and state.handle.valid() and state.tabs) then
            return
        end
        -- Mutate the tab spec's rows IN PLACE, then recalc (the handle re-reads the same table).
        local idx = state.handle.cursor_index()
        state.tabs[1].rows = build_rows()
        state.handle.recalc()
        state.handle.focus_index(idx)
    end)
end

-- ── actions ───────────────────────────────────────────────────────────────────

--- Reveal a secret's VALUE in a transient popup (explicit action; the list never shows values).
---@param name string
function M.reveal(name)
    api().get(name, function(value, err)
        if err then
            vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
            return
        end
        ui.info({ value or "" }, {
            title = name,
            footer = false,
            close_keys = { "q", "<Esc>", "<CR>", config.keymaps.reveal },
            highlights = { { line = 0, col_start = 0, col_end = -1, hl_group = "LvimKeyringValue" } },
        })
    end)
end

--- Copy a secret's value to the configured register, with an auto-clear timer that clears ONLY if the
--- register still holds our value (so a later yank is never clobbered).
---@param name string
function M.copy(name)
    api().get(name, function(value, err)
        if err or not value then
            vim.notify("lvim-keyring: " .. (err or "no value"), vim.log.levels.WARN)
            return
        end
        local reg = config.clipboard.register
        vim.fn.setreg(reg, value)
        local secs = config.clipboard.clear_seconds or 0
        if secs > 0 then
            vim.defer_fn(function()
                if vim.fn.getreg(reg) == value then
                    vim.fn.setreg(reg, "")
                end
            end, secs * 1000)
        end
        vim.notify(
            ("lvim-keyring: copied %s to register %s%s"):format(
                name,
                reg,
                secs > 0 and (" (auto-clears in %ds)"):format(secs) or ""
            ),
            vim.log.levels.INFO
        )
    end)
end

--- Add an entry: name → masked value → optional user meta.
function M.add()
    ui.input({
        title = "Secret name (e.g. forge/github.com)",
        callback = function(ok, name)
            if not ok or vim.trim(name) == "" then
                return
            end
            name = vim.trim(name)
            ui.input({
                title = "Value for " .. name,
                mask = true,
                callback = function(ok2, value)
                    if not ok2 then
                        return
                    end
                    api().set(name, value, nil, function(sok, err)
                        if not sok then
                            vim.notify("lvim-keyring: " .. (err or "failed"), vim.log.levels.WARN)
                            return
                        end
                        vim.notify("lvim-keyring: stored " .. name, vim.log.levels.INFO)
                        M.refresh()
                    end)
                end,
            })
        end,
    })
end

--- Edit the metadata (user) of the entry under the cursor — value untouched (set with no value).
---@param entry table
local function edit_meta(entry)
    local cur_user = entry.meta and type(entry.meta.user) == "string" and entry.meta.user or ""
    ui.input({
        title = ("User for %s (empty clears)"):format(entry.name),
        default = cur_user,
        callback = function(ok, value)
            if not ok then
                return
            end
            api().set(entry.name, nil, { user = value }, function(sok, err)
                if not sok then
                    vim.notify("lvim-keyring: " .. (err or "failed"), vim.log.levels.WARN)
                    return
                end
                M.refresh()
            end)
        end,
    })
end

--- Rename the entry under the cursor.
---@param entry table
local function rename(entry)
    ui.input({
        title = ("Rename %s to"):format(entry.name),
        default = entry.name,
        callback = function(ok, to)
            if not ok or vim.trim(to) == "" or vim.trim(to) == entry.name then
                return
            end
            api().rename(entry.name, vim.trim(to), function(rok, err)
                if not rok then
                    vim.notify("lvim-keyring: " .. (err or "failed"), vim.log.levels.WARN)
                    return
                end
                M.refresh()
            end)
        end,
    })
end

--- Delete the entry under the cursor (confirm first).
---@param entry table
local function delete(entry)
    ui.confirm({
        prompt = ("Delete secret '%s'?"):format(entry.name),
        callback = function(yes)
            if not yes then
                return
            end
            api().delete(entry.name, function(dok, err)
                if not dok then
                    vim.notify("lvim-keyring: " .. (err or "failed"), vim.log.levels.WARN)
                    return
                end
                M.refresh()
            end)
        end,
    })
end

--- Generate a password and store it under a prompted name.
local function generate_into()
    ui.input({
        title = "Generate + store as (e.g. db/new)",
        callback = function(ok, name)
            if not ok or vim.trim(name) == "" then
                return
            end
            api().generate({ store_as = vim.trim(name) }, function(_, err)
                if err then
                    vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
                    return
                end
                vim.notify("lvim-keyring: generated + stored " .. vim.trim(name), vim.log.levels.INFO)
                M.refresh()
            end)
        end,
    })
end

-- ── help ───────────────────────────────────────────────────────────────────────

local HELP = {
    { "add", "add a secret (name → value → meta)" },
    { "edit", "edit the entry's user metadata" },
    { "rename", "rename the entry" },
    { "delete", "delete the entry" },
    { "copy", "copy the value to the register (auto-clears)" },
    { "reveal", "reveal the value in a popup" },
    { "generate", "generate a password + store it" },
    { "lock", "lock the wallet" },
    { "rotate", "change the master password" },
    { "help", "this help" },
}

local function show_help()
    local items = {}
    for _, e in ipairs(HELP) do
        local lhs = config.keymaps[e[1]]
        if lhs and lhs ~= "" then
            items[#items + 1] = { lhs, e[2] }
        end
    end
    ui.help({
        title = config.title .. " keymaps",
        items = items,
        close_keys = { "q", "<Esc>", config.keymaps.help },
    })
end

-- ── the footer + row keys ────────────────────────────────────────────────────

--- The footer action band: wallet-wide actions + the help chip.
---@return table[]
local function build_footer()
    return {
        {
            key = config.keymaps.add,
            name = "add",
            run = function()
                M.add()
            end,
        },
        { key = config.keymaps.generate, name = "generate", run = generate_into },
        {
            key = config.keymaps.lock,
            name = "lock",
            run = function(st)
                st.close()
                api().lock(function(ok)
                    if ok then
                        vim.notify("lvim-keyring: locked", vim.log.levels.INFO)
                    end
                end)
            end,
        },
        {
            key = config.keymaps.rotate,
            name = "rotate",
            run = function()
                api().rotate()
            end,
        },
        { key = config.keymaps.help, name = "help", run = show_help },
    }
end

--- Wire the per-row action keys onto the panel buffer.
---@param buf integer
local function wire_keys(buf)
    local k = config.keymaps
    local function key(lhs, fn)
        if lhs and lhs ~= "" then
            vim.keymap.set("n", lhs, fn, { buffer = buf, nowait = true, silent = true })
        end
    end
    key(k.reveal, function()
        local e = cur_entry()
        if e then
            M.reveal(e.name)
        end
    end)
    key(k.copy, function()
        local e = cur_entry()
        if e then
            M.copy(e.name)
        end
    end)
    key(k.rename, function()
        local e = cur_entry()
        if e then
            rename(e)
        end
    end)
    key(k.delete, function()
        local e = cur_entry()
        if e then
            delete(e)
        end
    end)
    key(k.edit, function()
        local e = cur_entry()
        if e then
            edit_meta(e)
        end
    end)
end

--- A section header was toggled → flip its collapse state and rebuild.
---@param row table
local function on_toggle(row)
    local ns = row.name and row.name:match("^kr_sec_(.+)$")
    if not ns then
        return
    end
    state.collapsed[ns] = not row.expanded
    M.refresh()
end

-- ── open ───────────────────────────────────────────────────────────────────────

--- Open the wallet panel. Assumes the wallet is already unlocked (M.open in init.lua ensures it).
---@param layout string?
function M.open(layout)
    if state.handle and state.handle.valid and state.handle.valid() then
        state.handle.close()
    end
    state.handle = nil
    if layout then
        state.layout = layout
    end
    api().list(function(entries, err)
        if err then
            vim.notify("lvim-keyring: " .. err, vim.log.levels.WARN)
            return
        end
        state.entries = entries or {}
        state.tabs = {
            {
                label = config.title,
                icon = config.icons.panel,
                menu = true,
                rows = build_rows(),
                footer = build_footer(),
            },
        }
        state.handle = ui.tabs({
            title = config.title,
            title_pos = config.title_pos,
            title_count = function()
                return state.counts
            end,
            tabs = state.tabs,
            layout = state.layout or config.ui.layout,
            pad = 0,
            cursorline_hl = "LvimUiCursorLine",
            keymaps = { { key = config.keymaps.help, run = show_help } },
            on_change = on_toggle,
            on_open = function(buf, _win)
                wire_keys(buf)
            end,
            callback = function()
                state.handle = nil
                state.tabs = nil
            end,
        })
    end)
end

return M
