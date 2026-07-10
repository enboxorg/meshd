#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf 'usage: %s <semver> <output.app>\n' "$(basename "$0")" >&2
  exit 2
fi

VERSION="$1"
APP="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$APP" in
  *.app) ;;
  *)
    printf 'output path must end in .app: %s\n' "$APP" >&2
    exit 2
    ;;
esac

SHORT_VERSION="$(${ROOT}/scripts/macos-tray-version.sh "$VERSION" short)"
BUILD_VERSION="$(${ROOT}/scripts/macos-tray-version.sh "$VERSION" build)"
BINARY="${APP}/Contents/MacOS/meshd-tray"

rm -rf "$APP"
mkdir -p "${APP}/Contents/MacOS"
cp "${ROOT}/packaging/meshd-tray/Info.plist" "${APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${SHORT_VERSION}" "${APP}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${BUILD_VERSION}" "${APP}/Contents/Info.plist"

export CGO_ENABLED=1
export MACOSX_DEPLOYMENT_TARGET=12.0
ldflags="${MESHD_TRAY_LDFLAGS:--X main.version=${VERSION#v}}"
go build -trimpath -ldflags="$ldflags" -o "$BINARY" "${ROOT}/cmd/meshd-tray"

# Sign nested code first, then seal the containing bundle. Avoid --deep for
# signing so a future nested component cannot be signed implicitly.
codesign --force --sign - "$BINARY"
codesign --force --sign - "$APP"

"${ROOT}/scripts/verify-macos-tray.sh" "$APP" "$VERSION"
