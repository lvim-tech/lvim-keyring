-- lvim-keyring.ui.rows: entry → ui.tabs row builders. The list is GROUPED into collapsible SECTIONS
-- by NAMESPACE (the first `/`-segment of a name: db/, forge/, git/, common/), each section a
-- `type="action"` accordion with an accent from config.colors. Every ENTRY child is a three-zone row:
-- a LEAD BADGE (the key icon, tinted with the namespace accent), the display name (the part after the
-- namespace) in that accent, and DIMMED metadata (user / url / relative-updated). The VALUE is NEVER
-- rendered — it is fetched on demand only for reveal/copy. Each row registers itself in the caller's
-- registry (row name → entry) so the per-row action keys resolve the entry under the cursor.
--
---@module "lvim-keyring.ui.rows"

local config = require("lvim-keyring.config")
local highlights = require("lvim-keyring.highlights")
local ui = require("lvim-ui")

local M = {}

--- Truncate `s` to at most `n` CHARACTERS, with a trailing ellipsis when clipped.
---@param s string
---@param n integer
---@return string
local function clip(s, n)
    if vim.fn.strchars(s) <= n then
        return s
    end
    return vim.fn.strcharpart(s, 0, n - 1) .. "…"
end

--- The namespace of an entry name — the first `/`-segment, or "common" when unqualified.
---@param name string
---@return string
function M.namespace(name)
    local ns = name:match("^([^/]+)/")
    return ns or "common"
end

--- The DISPLAY name — the part after the namespace (or the whole name when unqualified).
---@param name string
---@return string
local function display_name(name)
    return name:match("^[^/]+/(.+)$") or name
end

local namespaces = require("lvim-keyring.namespaces")

--- The accent (palette key / "#rrggbb") for a namespace: a REGISTERED parent's accent, else `common`
--- for the catch-all, else the `default` fallback. Nothing per-consumer is hardcoded here.
---@param ns string
---@return string
function M.accent(ns)
    local reg = namespaces.get(ns)
    if reg and reg.accent then
        return reg.accent
    end
    return ns == "common" and config.colors.common or config.colors.default
end

--- The entry badge glyph for a namespace: a registered parent's icon, else the default key icon.
---@param ns string
---@return string
function M.icon(ns)
    local reg = namespaces.get(ns)
    return (reg and reg.icon) or config.icons.entry
end

--- The highlight-group SUFFIX for a namespace: the registered parent's own suffix, else "Common" for
--- the catch-all, else "Default". Matches the groups highlights.build/namespace_groups define.
---@param ns string
---@return string
function M.group_suffix(ns)
    if namespaces.get(ns) then
        return highlights.suffix(ns)
    end
    return ns == "common" and "Common" or "Default"
end

--- A short "updated N ago" string from an epoch (seconds). Empty when unknown.
---@param updated integer?
---@return string
local function ago(updated)
    if not updated or updated <= 0 then
        return ""
    end
    local now = os.time()
    local d = math.max(0, now - updated)
    if d < 60 then
        return "just now"
    elseif d < 3600 then
        return math.floor(d / 60) .. "m ago"
    elseif d < 86400 then
        return math.floor(d / 3600) .. "h ago"
    else
        return math.floor(d / 86400) .. "d ago"
    end
end

--- A JSON field that may arrive as `vim.NIL` (a decoded `null`) — return a real string, or nil.
---@param v any
---@return string?
local function str(v)
    if type(v) == "string" and v ~= "" then
        return v
    end
    return nil
end

--- The metadata string shown DIMMED after the name (user · url · updated) — never the value.
---@param meta table
---@return string
local function meta_text(meta)
    meta = meta or {}
    local parts = {}
    local user = str(meta.user)
    if user then
        parts[#parts + 1] = user
    end
    local url = str(meta.url)
    if url then
        parts[#parts + 1] = clip(url, 40)
    end
    local rel = ago(type(meta.updated) == "number" and meta.updated or nil)
    if rel ~= "" then
        parts[#parts + 1] = rel
    end
    return table.concat(parts, "  ·  ")
end

--- A badge box: a single glyph wrapped in a space each side (so every badge is the same width).
---@param glyph string
---@return string
local function badge(glyph)
    return " " .. glyph .. " "
end

--- A collapsible SECTION header — the canonical fold header via lvim-ui.section. The caret box is
--- rendered in the namespace badge colour; the accent supplies the band + label (shared groups).
---@param name string
---@param label string
---@param count integer
---@param expanded boolean
---@param children table[]
---@param accent string
---@param badge_hl string
---@return table row
function M.section(name, label, count, expanded, children, accent, badge_hl)
    return ui.section({
        name = name,
        icon = badge(expanded and config.icons.expand_open or config.icons.expand_closed),
        box_hl = badge_hl,
        label = label,
        count = count,
        accent = accent,
        expanded = expanded,
        children = children,
    })
end

--- An empty-state row.
---@param text string
---@return table row
function M.empty(text)
    return { type = "spacer", name = "kr_empty", label = text, hl = { inactive = "LvimKeyringEmpty" } }
end

--- One ENTRY row. Badge = the key icon (namespace accent); label = display name (accent) + dimmed meta.
--- The value is NOT here. Registers `entry` under the row name so the action keys resolve it.
---@param entry table            -- { name, meta = { user, url, updated, … } }
---@param registry table<string, table>
---@param on_pick fun(entry: table, close: fun(confirmed: boolean, result: any))
---@param namew integer          -- the collection's widest display name (for column alignment)
---@return table row
function M.entry_row(entry, registry, on_pick, namew)
    local ns = M.namespace(entry.name)
    local sfx = M.group_suffix(ns)
    local rowname = "kr__" .. entry.name
    registry[rowname] = entry

    -- Label = " <name padded to namew>  <meta>". Byte ranges (leading space + name → accent, trailing
    -- meta → dim), mirroring lvim-vault's split_label: the +1 covers the leading space.
    local dn = clip(display_name(entry.name), 48)
    local meta = meta_text(entry.meta)
    local label = (" %-" .. namew .. "s"):format(dn)
    local spans = { { 1, 1 + #dn, "LvimKeyringName" .. sfx } }
    if meta ~= "" then
        local mstart = 1 + math.max(namew, #dn) + 2 -- leading space + padded name field + the 2-space gap
        label = label .. "  " .. meta
        spans[#spans + 1] = { mstart, mstart + #meta, "LvimKeyringMeta" }
    end

    return {
        type = "action",
        name = rowname,
        flat = true,
        tight = true,
        icon = badge(M.icon(ns)),
        icon_hl = "LvimKeyringBadge" .. sfx,
        label = label,
        label_spans = spans,
        run = function(_, close)
            on_pick(entry, close)
        end,
    }
end

--- The widest display name across `entries`, capped at 48 (for column alignment).
---@param entries table[]
---@return integer
function M.name_width(entries)
    local w = 1
    for _, e in ipairs(entries) do
        w = math.max(w, vim.fn.strdisplaywidth(display_name(e.name)))
    end
    return math.min(w, 48)
end

return M
