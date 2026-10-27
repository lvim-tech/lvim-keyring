-- Where the client looks for the agent, and who it refuses to talk to.
--
-- The crypto and the master key live in the Rust daemon and never enter this process, so what is
-- left here is a socket client -- and the part of it worth stating is a refusal with a named
-- attack behind it. When $XDG_RUNTIME_DIR is unset the socket falls back under /tmp, which is
-- world-writable: a local attacker can pre-create `/tmp/lvim-keyring-<uid>` and bind their OWN
-- socket there, and the client would then send `vault.unlock { password }` straight to it. The
-- daemon's SO_PEERCRED guards the server side only, so the CLIENT has to vet the directory.
--
-- No case here drives a SUCCESSFUL connect: that would spawn a real per-user agent which outlives
-- the editor. Every case either asks a pure question or exercises a refusal that happens before
-- anything is spawned.

local daemon = require("lvim-keyring.daemon")
local config = require("lvim-keyring.config")

--- Run `fn` with `config.socket_path` set, then restore it.
---@param path string|nil
---@param fn fun(): any
---@return any
local function with_socket(path, fn)
    local was = config.socket_path
    config.socket_path = path
    local ok, result = pcall(fn)
    config.socket_path = was
    truthy(ok, tostring(result))
    return result
end

--- Ask a FRESH client to connect to `sock`, and wait for its answer.
---
--- Freshly loaded, deliberately: `ensure` short-circuits on a live connection and coalesces
--- concurrent callers, and `setup()` -- which the baseline calls -- already connected one. Reusing
--- that client meant the guard under test was never reached and the case passed for the wrong
--- reason, then that a later callback arrived with somebody else's error. A module of its own per
--- case has neither problem.
---@param sock string
---@return boolean ok
---@return string|nil err
local function fresh_ensure(sock)
    local was = config.socket_path
    config.socket_path = sock
    package.loaded["lvim-keyring.daemon"] = nil
    local client = require("lvim-keyring.daemon")

    local done, got_ok, got_err = false, nil, nil
    client.ensure(function(ok, err)
        done, got_ok, got_err = true, ok, err
    end)
    vim.wait(2000, function()
        return done
    end)

    client.stop()
    package.loaded["lvim-keyring.daemon"] = daemon
    config.socket_path = was

    truthy(done, "ensure never called back")
    return got_ok, got_err
end

describe("lvim-keyring: where the agent socket is")

it("a configured path wins", function()
    eq(
        "/tmp/explicitly-configured/agent.sock",
        with_socket("/tmp/explicitly-configured/agent.sock", daemon.socket_path)
    )
end)

it("without one, it lives under the per-user runtime directory", function()
    local was = vim.env.XDG_RUNTIME_DIR
    vim.env.XDG_RUNTIME_DIR = "/run/user/spec"
    local path = with_socket(nil, daemon.socket_path)
    vim.env.XDG_RUNTIME_DIR = was

    eq("/run/user/spec/lvim-keyring/agent.sock", path, "the per-user tmpfs is the correct home for a socket")
end)

it("with no runtime directory it falls back under /tmp, keyed by uid", function()
    local was = vim.env.XDG_RUNTIME_DIR
    vim.env.XDG_RUNTIME_DIR = nil
    local path = with_socket(nil, daemon.socket_path)
    vim.env.XDG_RUNTIME_DIR = was

    local uid = (vim.uv.getuid and vim.uv.getuid()) or 0
    eq(("/tmp/lvim-keyring-%s/agent.sock"):format(uid), path, "one socket per user, never a shared name")
end)

describe("lvim-keyring: who the client will talk to")

--- A directory at `mode`, to host a socket path.
---@param mode string  octal, e.g. "777"
---@return string dir
local function dir_with_mode(mode)
    local dir = vim.fn.tempname() .. "/sockdir"
    vim.fn.mkdir(dir, "p")
    vim.uv.fs_chmod(dir, tonumber(mode, 8))
    return dir
end

it("a world-writable socket directory is refused", function()
    -- This is the attack: anybody could have put a socket in there.
    local dir = dir_with_mode("777")
    local ok, err = fresh_ensure(dir .. "/agent.sock")
    eq(false, ok)
    truthy(err and err:match("private"), tostring(err))
    truthy(err:find(dir, 1, true), "the refusal names the directory: " .. tostring(err))
end)

it("any access beyond the owner's is enough to refuse", function()
    for _, mode in ipairs({ "750", "701", "710", "770", "707" }) do
        local ok, err = fresh_ensure(dir_with_mode(mode) .. "/agent.sock")
        eq(false, ok, "mode " .. mode .. " was accepted")
        truthy(err and err:match("private"), ("mode %s: %s"):format(mode, tostring(err)))
    end
end)

describe("lvim-keyring: finding the daemon binary")

--- An executable file at `path`.
---@param path string
local function fake_binary(path)
    vim.fn.mkdir(vim.fn.fnamemodify(path, ":h"), "p")
    vim.fn.writefile({ "#!/bin/sh", "exit 0" }, path)
    vim.uv.fs_chmod(path, tonumber("700", 8))
end

--- Run `fn` with a configured daemon path and a cleared env override.
---@param path string|nil
---@param fn fun(): any
---@return any
local function with_daemon_path(path, fn)
    local was_cfg, was_env = config.daemon_path, vim.env.LVIM_KEYRING_DAEMON
    config.daemon_path = path
    vim.env.LVIM_KEYRING_DAEMON = nil
    local ok, result = pcall(fn)
    config.daemon_path, vim.env.LVIM_KEYRING_DAEMON = was_cfg, was_env
    truthy(ok, tostring(result))
    return result
end

it("a configured path is probed first", function()
    local path = vim.fn.tempname() .. "/configured/lvim-keyring-daemon"
    fake_binary(path)
    eq(path, with_daemon_path(path, daemon.binary_path))
end)

it("an environment override is probed before the plugin's own build", function()
    local path = vim.fn.tempname() .. "/fromenv/lvim-keyring-daemon"
    fake_binary(path)

    local was_cfg, was_env = config.daemon_path, vim.env.LVIM_KEYRING_DAEMON
    config.daemon_path = nil
    vim.env.LVIM_KEYRING_DAEMON = path
    local found = daemon.binary_path()
    config.daemon_path, vim.env.LVIM_KEYRING_DAEMON = was_cfg, was_env

    eq(path, found)
end)

it("a configured path that does not exist does not hide the others", function()
    local found = with_daemon_path(vim.fn.tempname() .. "/missing/lvim-keyring-daemon", daemon.binary_path)
    -- Either the plugin's own build (this machine has one) or nil, but never the missing path.
    if found ~= nil then
        truthy(found:match("lvim%-keyring%-daemon$"), found)
        eq(nil, found:match("/missing/"), "a non-existent override must be skipped, not returned")
    end
end)

it("with nothing anywhere there is no binary, rather than a guess", function()
    -- The plugin's own build is a real path on this machine, so this case can only be stated by
    -- asking what binary_path does with a path that is not there -- and it is the shape above.
    -- What is checked here is that the answer is always an existing file or nil.
    local found = daemon.binary_path()
    if found ~= nil then
        truthy(vim.uv.fs_stat(found), "binary_path returned a path that does not exist: " .. found)
    end
end)

describe("lvim-keyring: the suite's own blast radius")

it("the socket this suite would use is inside the sandbox", function()
    -- The agent socket lives under $XDG_RUNTIME_DIR, which `make test` redirects for exactly this
    -- reason: setup() connects, so without the redirection a test run reaches into the user's real
    -- /run/user/<uid>/lvim-keyring and can spawn an agent beside the one they are using.
    local sandbox = vim.env.LVIM_TEST_HOME
    truthy(sandbox and sandbox ~= "", "the suite is supposed to run under make test")
    local sock = with_socket(nil, daemon.socket_path)
    truthy(
        vim.startswith(vim.fs.normalize(sock), vim.fs.normalize(sandbox)),
        "the socket path escapes the sandbox: " .. sock
    )
end)

it("stopping the client disconnects it without killing a shared daemon", function()
    daemon.stop()
    eq(false, daemon.is_running(), "this client is disconnected")
end)

it("a state subscriber can be registered and the lock state asked for", function()
    local keyring = require("lvim-keyring")
    local seen = {}
    local ok = pcall(keyring.on_state, function(state)
        seen[#seen + 1] = state
    end)
    truthy(ok, "subscribing must not raise")
    truthy(type(keyring.is_unlocked()) == "boolean", "the lock state is always answerable")
end)
