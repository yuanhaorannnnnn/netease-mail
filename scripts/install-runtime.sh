#!/bin/sh
set -eu
plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runtime_root="${XDG_DATA_HOME:-$HOME/.local/share}/netease-mail/venv"
python3 -m venv "$runtime_root"
"$runtime_root/bin/python" -m pip install -r "$plugin_root/requirements.txt"
printf '%s\n' 'Runtime installed. Account setup and mailbox connection are separate steps.'
