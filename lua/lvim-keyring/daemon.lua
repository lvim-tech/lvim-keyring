-- lvim-keyring.daemon: the agent process lifecycle + JSON-RPC client.
--
-- The secrets work happens in a SEPARATE process — the Rust `lvim-keyring-daemon`
-- (native/) — spoken to over a per-user UNIX SOCKET (not stdio), so BOTH this
-- editor's Lua AND a sibling process (lvim-db-daemon resolving `{{ vault "…" }}`)
-- can share ONE unlocked agent. This module owns the client end: it CONNECTS to a
-- live socket if one exists (a second editor shares the first's unlock), else
-- SPAWNS the daemon detached (so it outlives the spawning editor and its own
-- last-client-disconnect logic governs its lifetime), handshakes, correlates
-- responses to requests by id, and routes the `vault.state` notification.
--
-- Out-of-process because the master key and decrypted entries must never live in
-- the editor's address space, and Argon2id must run off the event loop. Missing
-- binary degrades gracefully (one INFO notification); there is no pure-Lua
-- fallback — a Lua crypto stand-in would be a hack, not a fallback.
--
-- Public API:
--   • ensure(cb)          connect/spawn + handshake, cb(ok, err)
--   • request(m, p, cb)   one RPC call, cb(result, err)
--   • on(method, handler) subscribe to a notification
--   • is_running()        whether the socket is connected + handshaken
--   • stop()              disconnect this client (does NOT kill a shared daemon)
--
---@module "lvim-keyring.daemon"

local uv = vim.uv or vim.loop
local bit = require("bit")
local config = require("lvim-keyring.config")

local M = {}

--- Minimum backend protocol this Lua understands (additive-growth discipline).
local PROTO_MIN = 1

---@type uv.uv_pipe_t? the connected socket pipe, or nil
local pipe
---@type boolean whether the rpc.hello handshake completed
local ready = false
---@type integer? the negotiated protocol version
local proto
---@type string the partial trailing line carried between read chunks
local read_tail = ""
---@type integer monotonically increasing request id
local id_seq = 0
---@type table<integer, fun(result: any, err: string?)> id → pending response callback
local pending = {}
---@type table<string, fun(params: any)> method → notification handler
local handlers = {}
---@type fun(ok: boolean, err: string?)[] callbacks waiting for connect+handshake
local ensure_waiters = {}
---@type boolean whether a connect/spawn attempt is in flight
local connecting = false
---@type boolean one-shot guard for the "daemon not built" notification
local warned_missing = false

-- ─── paths ───────────────────────────────────────────────────────────────────

--- The agent socket path: config override, else $XDG_RUNTIME_DIR/lvim-keyring/agent.sock,
--- else a /tmp fallback keyed by uid (XDG_RUNTIME_DIR is the correct per-user tmpfs).
---@return string
function M.socket_path()
    if config.socket_path and config.socket_path ~= "" then
        return config.socket_path
    end
    local runtime = vim.env.XDG_RUNTIME_DIR
    if runtime and runtime ~= "" then
        return runtime .. "/lvim-keyring/agent.sock"
    end
    local uid = (uv.getuid and uv.getuid()) or 0
    return ("/tmp/lvim-keyring-%s/agent.sock"):format(uid)
end

--- Verify the socket's PARENT directory, when it already exists, is owned by us and mode 0700 — and
--- refuse otherwise. The `/tmp` fallback (used only when XDG_RUNTIME_DIR is unset) lives in a
--- world-writable dir: a local attacker could pre-create `/tmp/lvim-keyring-<uid>` and bind their OWN
--- socket there, then our client would send `vault.unlock { password }` straight to it (the daemon's
--- SO_PEERCRED guards the SERVER side only — the CLIENT must vet who it connects to). An absent dir is
--- fine: we create it privately (0700) before the daemon binds.
---@param sock string
---@return boolean ok, string? err
local function socket_dir_secure(sock)
    local dir = vim.fs.dirname(sock)
    local st = uv.fs_stat(dir)
    if not st then
        return true
    end
    local uid = (uv.getuid and uv.getuid()) or 0
    if st.uid ~= uid then
        return false, ("keyring: socket dir %s is not owned by you (uid %d) — refusing to use it"):format(dir, st.uid)
    end
    -- Low 9 bits of the mode must be exactly rwx------ (0700); any group/other access is a refusal.
    if bit.band(st.mode, 0x1FF) ~= 0x1C0 then
        return false, ("keyring: socket dir %s must be private (0700) — refusing to use it"):format(dir)
    end
    return true
end

--- Candidate daemon-binary paths, in probe order.
---@return string[]
local function candidate_paths()
    local paths = {}
    if config.daemon_path and config.daemon_path ~= "" then
        paths[#paths + 1] = config.daemon_path
    end
    local env = vim.env.LVIM_KEYRING_DAEMON
    if env and env ~= "" then
        paths[#paths + 1] = env
    end
    -- this file is <root>/lua/lvim-keyring/daemon.lua → strip to the plugin root
    local src = vim.fs.normalize(debug.getinfo(1, "S").source:sub(2))
    local root = src:gsub("/lua/lvim%-keyring/daemon%.lua$", "")
    paths[#paths + 1] = root .. "/native/build/lvim-keyring-daemon"
    paths[#paths + 1] = root .. "/native/target/release/lvim-keyring-daemon"
    return paths
end

--- The first existing daemon binary path, or nil.
---@return string?
function M.binary_path()
    for _, p in ipairs(candidate_paths()) do
        if uv.fs_stat(p) then
            return p
        end
    end
    return nil
end

--- Notify once (INFO) that the daemon binary is not built, if configured.
local function warn_missing()
    if config.warn_on_missing and not warned_missing then
        warned_missing = true
        vim.schedule(function()
            vim.notify(
                "lvim-keyring: backend not built — run `sh native/build.sh` (needs a Rust toolchain) to enable "
                    .. "the wallet.",
                vim.log.levels.INFO
            )
        end)
    end
end

-- ─── message plumbing ────────────────────────────────────────────────────────

--- Dispatch one decoded message: a response (by id) or a notification.
---@param msg table
local function on_message(msg)
    if msg.id ~= nil then
        local cb = pending[msg.id]
        pending[msg.id] = nil
        if cb then
            if msg.ok then
                cb(msg.result, nil)
            else
                cb(nil, msg.error or "unknown error")
            end
        end
    elseif msg.method then
        local h = handlers[msg.method]
        if h then
            pcall(h, msg.params)
        end
    end
end

--- Reassemble newline-delimited JSON across read-chunk boundaries.
---@param chunk string
local function on_read(chunk)
    read_tail = read_tail .. chunk
    while true do
        local nl = read_tail:find("\n", 1, true)
        if not nl then
            break
        end
        local line = vim.trim(read_tail:sub(1, nl - 1))
        read_tail = read_tail:sub(nl + 1)
        if line ~= "" then
            local ok, msg = pcall(vim.json.decode, line)
            if ok and type(msg) == "table" then
                on_message(msg)
            end
        end
    end
end

--- Tear down the client after a disconnect or a failed connect.
---@param err string?
local function teardown(err)
    ready = false
    connecting = false
    read_tail = ""
    if pipe then
        pcall(function()
            pipe:read_stop()
        end)
        pcall(function()
            pipe:close()
        end)
        pipe = nil
    end
    local dead = pending
    pending = {}
    for _, cb in pairs(dead) do
        pcall(cb, nil, err or "keyring agent stopped")
    end
    local waiters = ensure_waiters
    ensure_waiters = {}
    for _, cb in ipairs(waiters) do
        pcall(cb, false, err or "keyring agent stopped")
    end
end

--- Send a raw request object (only when the pipe is connected).
---@param obj table
local function send(obj)
    if pipe then
        pipe:write(vim.json.encode(obj) .. "\n")
    end
end

--- Perform the rpc.hello handshake, then flush the ensure waiters.
local function handshake()
    id_seq = id_seq + 1
    local hid = id_seq
    pending[hid] = function(result, err)
        local waiters = ensure_waiters
        ensure_waiters = {}
        connecting = false
        if err or type(result) ~= "table" then
            teardown(err or "handshake failed")
            for _, cb in ipairs(waiters) do
                pcall(cb, false, err or "handshake failed")
            end
            return
        end
        proto = tonumber(result.proto)
        if not proto or proto < PROTO_MIN then
            local msg = ("backend protocol %s is too old (need ≥ %d)"):format(tostring(proto), PROTO_MIN)
            teardown(msg)
            for _, cb in ipairs(waiters) do
                pcall(cb, false, msg)
            end
            return
        end
        ready = true
        -- seed the lock-state cache from the handshake
        local h = handlers["vault.state"]
        if h then
            pcall(h, { locked = result.locked })
        end
        for _, cb in ipairs(waiters) do
            pcall(cb, true, nil)
        end
    end
    send({ id = hid, method = "rpc.hello", params = vim.empty_dict() })
end

--- Attach read handling to the connected pipe and start the handshake.
local function on_connected()
    if not pipe then
        return
    end
    pipe:read_start(function(err, chunk)
        if err then
            vim.schedule(function()
                teardown("read error: " .. tostring(err))
            end)
            return
        end
        if chunk then
            vim.schedule(function()
                on_read(chunk)
            end)
        else
            -- EOF: the agent closed the connection
            vim.schedule(function()
                teardown("keyring agent disconnected")
            end)
        end
    end)
    handshake()
end

--- The environment the daemon is spawned with — where the vault lives and the
--- KDF / lock / linger knobs (the daemon reads these; config is Lua-side).
---@return table<string, string>
local function spawn_env()
    local env = {
        LVIM_KEYRING_KDF_M = tostring((config.kdf.memory_mib or 64) * 1024),
        LVIM_KEYRING_KDF_T = tostring(config.kdf.iterations or 3),
        LVIM_KEYRING_KDF_P = tostring(config.kdf.parallelism or 4),
        LVIM_KEYRING_LOCK_TIMEOUT = tostring((config.lock.timeout_minutes or 15) * 60),
        LVIM_KEYRING_LINGER = tostring(config.linger_seconds or 0),
        LVIM_KEYRING_PERSIST = config.persist and "1" or "0",
    }
    -- Always resolve + pass the vault path so the daemon writes where the EDITOR expects, not its own
    -- standalone default: config.vault_path, else the set's convention `stdpath("data")/lvim-keyring/`
    -- (same as lvim-db's store, lvim-vault's db, …). Kept configurable via config.vault_path.
    local vault = config.vault_path
    if not vault or vault == "" then
        vault = vim.fn.stdpath("data") .. "/lvim-keyring/keyring.vault"
    end
    env.LVIM_KEYRING_VAULT = vault
    return env
end

--- Spawn the daemon DETACHED (so it survives this editor and its own last-client
--- logic governs its lifetime), bound to our socket path.
---@param bin string
---@param sock string
local function spawn_daemon(bin, sock)
    -- Ensure the socket's parent dir exists with private perms before the daemon binds.
    local dir = vim.fs.dirname(sock)
    pcall(vim.fn.mkdir, dir, "p", 448) -- 0700
    pcall(vim.fn.jobstart, { bin, "--socket", sock }, { detach = true, env = spawn_env() })
end

--- Try to connect to `sock`; on success handshake, on failure `cb(false)` so the
--- caller can decide to spawn + retry.
---@param sock string
---@param cb fun(ok: boolean)
local function try_connect(sock, cb)
    local p = uv.new_pipe(false)
    p:connect(sock, function(err)
        -- The connect callbacks all run on the single libuv loop thread, serially, so testing `pipe`
        -- here is race-free: if a prior (in-flight-handshake) connect already won, this second socket is
        -- surplus — close it and report failure, so its fd is not orphaned nor the live `pipe` clobbered.
        if err or pipe then
            pcall(function()
                p:close()
            end)
            vim.schedule(function()
                cb(false)
            end)
        else
            pipe = p
            vim.schedule(function()
                on_connected()
                cb(true)
            end)
        end
    end)
end

--- Ensure the agent is connected + handshaken. `cb(ok, err)`. Concurrent callers
--- coalesce; a live socket is shared, a missing one is spawned then retried.
---@param cb fun(ok: boolean, err: string?)
function M.ensure(cb)
    if ready and pipe then
        cb(true, nil)
        return
    end
    ensure_waiters[#ensure_waiters + 1] = cb
    if connecting then
        return
    end
    connecting = true

    local sock = M.socket_path()
    -- Refuse a hijackable socket dir (an attacker-owned /tmp fallback) BEFORE we connect or spawn — the
    -- client must never hand the master password to a socket it does not trust.
    local secure, serr = socket_dir_secure(sock)
    if not secure then
        teardown(serr)
        return
    end
    try_connect(sock, function(ok)
        if ok then
            return -- on_connected() → handshake() flushes the waiters
        end
        -- No live socket: spawn the daemon, then retry connect a few times.
        local bin = M.binary_path()
        if not bin then
            warn_missing()
            teardown("daemon binary not found")
            return
        end
        spawn_daemon(bin, sock)
        local tries = 0
        local timer = uv.new_timer()
        timer:start(80, 80, function()
            tries = tries + 1
            vim.schedule(function()
                if pipe then
                    return -- a connect is already established (its handshake may still be in flight)
                end
                try_connect(sock, function(connected)
                    if connected then
                        timer:stop()
                        timer:close()
                    elseif tries >= 25 then -- ~2s
                        timer:stop()
                        timer:close()
                        teardown("could not connect to the keyring agent after spawning it")
                    end
                end)
            end)
        end)
    end)
end

--- Issue one RPC request. Ensures the agent is up first.
---@param method string
---@param params table?
---@param cb fun(result: any, err: string?)
function M.request(method, params, cb)
    M.ensure(function(ok, err)
        if not ok then
            cb(nil, err)
            return
        end
        id_seq = id_seq + 1
        local rid = id_seq
        pending[rid] = cb
        send({ id = rid, method = method, params = params or vim.empty_dict() })
    end)
end

--- Subscribe to a notification method (e.g. "vault.state"). One handler per method.
---@param method string
---@param handler fun(params: any)
function M.on(method, handler)
    handlers[method] = handler
end

--- The negotiated protocol version, or nil before the handshake.
---@return integer?
function M.proto()
    return proto
end

--- Whether the client is connected and handshaken.
---@return boolean
function M.is_running()
    return ready and pipe ~= nil
end

--- Disconnect THIS client. Does NOT kill the daemon (it may be shared); the daemon
--- self-exits when its last client disconnects.
function M.stop()
    teardown("client stopped")
end

return M
