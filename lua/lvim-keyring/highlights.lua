-- lvim-keyring.highlights: the panel's badge / text groups, self-themed from the lvim-utils palette.
--
-- lvim-keyring hardcodes NO consumer namespace: it defines only the `common` (catch-all) and `default`
-- (fallback) badge/name pairs plus the neutral text/meta/value tones. Per-parent groups come from the
-- REGISTRY (lvim-keyring.namespaces) — a plugin registers its parent with an accent, and `build()`
-- (bound via lvim-utils.highlight.bind, re-run on ColorScheme / palette sync) reads the registry to
-- (re)define `LvimKeyringBadge<Ns>` / `LvimKeyringName<Ns>` for each. Collapsible SECTION headers get
-- their band / label from the shared section_accent (via lvim-ui.section).
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

--- Resolve a colour value to a real colour: a palette KEY (`c[key]`, tracks the theme) or the value
--- itself (a literal "#rrggbb").
---@param key string
---@return string
local function resolve(key)
    return c[key] or key
end

--- The group SUFFIX for a namespace (`db` → `Db`). Capitalised, sanitised.
---@param ns string
---@return string
function M.suffix(ns)
    return (ns:gsub("^%l", string.upper):gsub("[^%w]", ""))
end

--- The badge/name group pair for one accent + suffix.
---@param sfx string
---@param accent string
---@return table<string, table>
local function pair(sfx, accent)
    local a = resolve(accent)
    return {
        ["LvimKeyringBadge" .. sfx] = { fg = a, bg = mtint(a, 0.3), bold = true },
        ["LvimKeyringName" .. sfx] = { fg = a },
    }
end

--- The highlight groups for ONE registered namespace (used by `namespaces.register` to define them on
--- the spot). Falls back to the default accent when the namespace has none.
---@param name string
---@return table<string, table>
function M.namespace_groups(name)
    local ns = require("lvim-keyring.namespaces").get(name) or {}
    return pair(M.suffix(name), ns.accent or config.colors.default)
end

--- The keyring highlight groups from the live palette: the neutral tones + the `common`/`default`
--- pairs + one pair per REGISTERED namespace. Bound via lvim-utils.highlight.bind in setup().
---@return table<string, table>
function M.build()
    local groups = {
        LvimKeyringText = { fg = c.fg },
        LvimKeyringMeta = { fg = mtint(c.fg, 0.55) }, -- dimmed user/url/updated
        LvimKeyringDim = { fg = mtint(c.fg, 0.6) },
        LvimKeyringEmpty = { fg = mtint(c.fg, 0.5), italic = true },
        LvimKeyringValue = { fg = c.yellow, bold = true }, -- the revealed value popup
    }
    -- lvim-keyring's OWN two: the catch-all + the fallback.
    for k, v in pairs(pair("Common", config.colors.common)) do
        groups[k] = v
    end
    for k, v in pairs(pair("Default", config.colors.default)) do
        groups[k] = v
    end
    -- Every registered parent namespace.
    for name, ns in pairs(require("lvim-keyring.namespaces").all()) do
        for k, v in pairs(pair(M.suffix(name), ns.accent or config.colors.default)) do
            groups[k] = v
        end
    end
    return groups
end

return M
