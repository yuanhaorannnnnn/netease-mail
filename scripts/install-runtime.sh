#!/bin/sh
set -eu
plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$plugin_root/scripts/runtime_support.py" install
