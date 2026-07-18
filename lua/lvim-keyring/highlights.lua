-- lvim-keyring.highlights: the panel's badge / text groups, self-themed from the lvim-utils palette.
--
-- One accent per NAMESPACE (db = blue, forge = magenta, git = orange, common = cyan — from
-- config.colors), each entry badge a tint of its accent toward the editor bg (the shared "mtint"
-- convention) so the rows track the live theme. `build()` is bound via lvim-utils.highlight.bind in
-- setup(), re-derived on ColorScheme / palette sync. Collapsible SECTION headers get their band /
-- hover / label from the shared lvim-utils.highlight.section_accent (via lvim-ui.section) — nothing
-- section-specific is defined here.
--
---@module "lvim-keyring.highlights"

local c = require("lvim-utils.colors")
local hl = require("lvim-utils.highlight")
local config = require("lvim-keyring.config")

local M = {}

--- Blend an accent toward the editor bg (the shared "mtint" convention).
---@param accent string
---@param t number
---@return string
local function mtint(accent, t)
    return hl.blend(accent, c.bg, t)
end

--- Resolve a `config.colors` value to a real colour: a palette KEY (`c[key]`, tracks the live theme)
--- or, when not a palette field, the value itself (a literal "#rrggbb").
---@param key string
---@return string
local function accent(key)
    return c[key] or key
end

--- The group SUFFIX for a namespace (so `db` → `LvimKeyringBadgeDb`). Capitalised, sanitised.
---@param ns string
---@return string
function M.suffix(ns)
    return (ns:gsub("^%l", string.upper):gsub("[^%w]", ""))
end

--- The keyring highlight groups from the live palette + config.colors: a badge + name-accent pair per
--- namespace, plus the neutral text/meta/value tones.
---@return table<string, table>
function M.build()
    local groups = {
        LvimKeyringText = { fg = c.fg },
        LvimKeyringMeta = { fg = mtint(c.fg, 0.55) }, -- dimmed user/url/updated
        LvimKeyringDim = { fg = mtint(c.fg, 0.6) },
        LvimKeyringEmpty = { fg = mtint(c.fg, 0.5), italic = true },
        LvimKeyringValue = { fg = c.yellow, bold = true }, -- the revealed value popup
    }
    for ns, col in pairs(config.colors) do
        local a = accent(col)
        local sfx = M.suffix(ns)
        groups["LvimKeyringBadge" .. sfx] = { fg = a, bg = mtint(a, 0.3), bold = true }
        groups["LvimKeyringName" .. sfx] = { fg = a }
    end
    return groups
end

return M
