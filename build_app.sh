#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"


if ! command -v swift >/dev/null 2>&1; then
  echo "Swift was not found. Install Apple's Command Line Tools first:"
  echo "  xcode-select --install"
  exit 1
fi

APP_NAME="IP Guardian"
EXECUTABLE="IPGuardian"
APP_DIR="$ROOT/dist/$APP_NAME.app"
CONTENTS="$APP_DIR/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
ARCHIVE="$ROOT/dist/$APP_NAME.zip"
DEPLOYMENT_TARGET="13.0"

rm -rf "$ROOT/dist"
mkdir -p "$MACOS" "$RESOURCES"

# One slice per architecture, merged with lipo, so a single download runs on
# both Apple Silicon and Intel Macs. `swift build --arch a --arch b` would need
# full Xcode; building one architecture at a time needs only the Command Line
# Tools, so nobody has to switch or install a larger toolchain.
SLICES=()
for ARCH in arm64 x86_64; do
  SCRATCH="$ROOT/.build/universal-$ARCH"
  TARGET="$ARCH-apple-macos$DEPLOYMENT_TARGET"
  # Braces and plain ASCII: bash 3.2 decides where a variable name ends with a
  # locale-dependent test, so "$ARCH…" swallowed the ellipsis into the name and
  # failed under set -u in a UTF-8 terminal.
  echo "Building IP Guardian 1 for ${ARCH}..."
  if swift build -c release --scratch-path "$SCRATCH" \
       -Xswiftc -target -Xswiftc "$TARGET" \
       --jobs "${SWIFT_BUILD_JOBS:-2}"; then
    BIN_DIR="$(swift build -c release --scratch-path "$SCRATCH" \
      -Xswiftc -target -Xswiftc "$TARGET" --show-bin-path)"
    SLICES+=("$BIN_DIR/$EXECUTABLE")
  else
    echo "  The $ARCH slice could not be built; continuing without it."
  fi
done

if [ "${#SLICES[@]}" -eq 0 ]; then
  echo "No architecture could be built."
  exit 1
fi

lipo -create -output "$MACOS/$EXECUTABLE" "${SLICES[@]}"
cp "$ROOT/Info.plist" "$CONTENTS/Info.plist"
cp "$ROOT/Resources/AppIcon.icns" "$RESOURCES/AppIcon.icns"
# Country flags travel with the app: no network request, and nothing learns
# which country the user is connected through.
rm -rf "$RESOURCES/Flags"
cp -R "$ROOT/Resources/Flags" "$RESOURCES/Flags"
chmod +x "$MACOS/$EXECUTABLE"

# Only what this script just produced. Clearing the whole source folder meant
# that unpacking the repository as a zip and building it silently trusted every
# file that came with it, which is far more than the app being built here.
xattr -cr "$APP_DIR" 2>/dev/null || true

codesign --force --deep --sign - "$APP_DIR" >/dev/null 2>&1 || true

# A ready-to-send archive, so a user never needs a compiler to install this.
ditto -c -k --keepParent "$APP_DIR" "$ARCHIVE"

echo
echo "Built successfully:"
echo "  $APP_DIR"
echo "  architectures: $(lipo -archs "$MACOS/$EXECUTABLE")"
echo "  shareable archive: $ARCHIVE"
