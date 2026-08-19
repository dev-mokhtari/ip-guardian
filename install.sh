#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
xattr -dr com.apple.quarantine "$ROOT" 2>/dev/null || true
/bin/bash "$ROOT/build_app.sh"

APP="$ROOT/dist/IP Guardian.app"
USER_APPLICATIONS="${HOME}/Applications"
DEST="$USER_APPLICATIONS/IP Guardian.app"

killall "IPGuardian" 2>/dev/null || true
mkdir -p "$USER_APPLICATIONS"

copy_app() {
  rm -rf "$DEST"
  cp -R "$APP" "$DEST"
}

copy_app

xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true
open "$DEST"

echo
echo "Installed: $DEST"
echo "IP Guardian 1 is open and its shield remains available in the macOS menu bar."
