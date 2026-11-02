#!/bin/sh
set -eu
plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec sh "$plugin_root/scripts/run-python.sh" "$plugin_root/skills/netease-mail/scripts/server.py"
