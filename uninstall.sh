#!/bin/bash
set -euo pipefail

killall "IPGuardian" 2>/dev/null || true

DEST="${HOME}/Applications/IP Guardian.app"
rm -rf "$DEST"

echo "IP Guardian was removed from ${HOME}/Applications."
echo "Saved app selections and preferences remain in UserDefaults."
