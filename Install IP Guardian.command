#!/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
chmod +x install.sh build_app.sh uninstall.sh
bash ./install.sh
printf '\nInstallation finished. You can close this window.\n'
read -r -p "Press Enter to close…" _
