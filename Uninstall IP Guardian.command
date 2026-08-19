#!/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
chmod +x uninstall.sh
bash ./uninstall.sh
printf '\nUninstall finished. You can close this window.\n'
read -r -p "Press Enter to close…" _
