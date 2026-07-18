-- lvim-keyring.namespaces: the runtime registry of parent namespaces.
--
-- lvim-keyring the PROVIDER keeps NO list of its consumers and NO per-consumer names / icons / colours
-- in its config — it owns only `common` (the catch-all for unqualified names) and a `default` fallback.
-- Every OTHER plugin registers its own parent ONCE, with an icon + accent:
--
--   require("lvim-keyring").register_namespace("db", { icon = "", accent = "blue" })
--
-- (pcall-guarded on the consumer side, so nobody hard-depends on lvim-keyring). After that the panel
-- renders `db/…` entries with that icon + accent, and the highlight groups are defined on the spot
-- (and re-derived on every ColorScheme via highlights.build, which reads this registry). An
-- unregistered namespace falls back to the default accent + the default entry icon — nothing breaks.
--
---@module "lvim-keyring.namespaces"

local M = {}

---@class LvimKeyringNamespace
---@field accent string?  a lvim-utils palette key or "#rrggbb"
---@field icon string?    the entry badge glyph for this namespace

---@type table<string, LvimKeyringNamespace>
local reg = {}

--- Register (or update) a parent namespace with its icon + accent.
---@param name string
---@param opts { icon?: string, accent?: string, color?: string }?
function M.register(name, opts)
    if type(name) ~= "string" or name == "" then
        return
    end
    opts = opts or {}
    reg[name] = { accent = opts.accent or opts.color, icon = opts.icon }
    -- Define this namespace's highlight groups NOW (so a registration after setup takes effect
    -- immediately); highlights.build re-creates them on every ColorScheme from this same registry.
    local ok, hl = pcall(require, "lvim-utils.highlight")
    if ok then
        hl.register(require("lvim-keyring.highlights").namespace_groups(name), true)
    end
end

---@param name string
---@return LvimKeyringNamespace?
function M.get(name)
    return reg[name]
end

---@return table<string, LvimKeyringNamespace>
function M.all()
    return reg
end

return M
