#!/bin/sh
# Build the lvim-keyring daemon into native/build/lvim-keyring-daemon — the path
# the Lua loader (lua/lvim-keyring/daemon.lua) probes first. Requires a Rust
# toolchain (cargo). Without the daemon the plugin still loads but every action
# reports that the backend must be built (see :checkhealth lvim-keyring).
#
#   sh native/build.sh
set -e
cd "$(dirname "$0")"

cargo build --release "$@"

mkdir -p build
cp -f target/release/lvim-keyring-daemon build/lvim-keyring-daemon
echo "installed build/lvim-keyring-daemon"
