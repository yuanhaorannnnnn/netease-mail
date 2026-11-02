#!/bin/sh
set -eu
plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runtime_root="${XDG_DATA_HOME:-$HOME/.local/share}/netease-mail/venv"
if [ ! -x "$runtime_root/bin/python" ]; then
    printf '%s\n' 'NetEase Mail runtime missing. Run sh scripts/install-runtime.sh from the plugin package.' >&2
    exit 1
fi
exec "$runtime_root/bin/python" "$plugin_root/skills/netease-mail/scripts/server.py"
