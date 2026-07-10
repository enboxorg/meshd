#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf 'usage: %s <meshd-tray.app> <semver>\n' "$(basename "$0")" >&2
  exit 2
fi

APP="$1"
VERSION="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST="${APP}/Contents/Info.plist"
BINARY="${APP}/Contents/MacOS/meshd-tray"
EXPECTED_SHORT="$(${ROOT}/scripts/macos-tray-version.sh "$VERSION" short)"
EXPECTED_BUILD="$(${ROOT}/scripts/macos-tray-version.sh "$VERSION" build)"

plutil -lint "$PLIST" >/dev/null

actual_short="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$PLIST")"
actual_build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$PLIST")"
minimum_system="$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$PLIST")"

[ "$actual_short" = "$EXPECTED_SHORT" ] || {
  printf 'unexpected CFBundleShortVersionString: got %s, want %s\n' "$actual_short" "$EXPECTED_SHORT" >&2
  exit 1
}
[ "$actual_build" = "$EXPECTED_BUILD" ] || {
  printf 'unexpected CFBundleVersion: got %s, want %s\n' "$actual_build" "$EXPECTED_BUILD" >&2
  exit 1
}
[ "$minimum_system" = '12.0' ] || {
  printf 'unexpected LSMinimumSystemVersion: got %s, want 12.0\n' "$minimum_system" >&2
  exit 1
}

min_versions="$(otool -l "$BINARY" | awk '$1 == "minos" { print $2 }')"
[ -n "$min_versions" ] || {
  printf 'meshd-tray has no LC_BUILD_VERSION minimum OS\n' >&2
  exit 1
}
while IFS= read -r min_version; do
  case "$min_version" in
    12.0|12.0.0) ;;
    *)
      printf 'unexpected Mach-O deployment target: got %s, want 12.0\n' "$min_version" >&2
      exit 1
      ;;
  esac
done <<EOF
${min_versions}
EOF

codesign --verify --deep --strict --verbose=2 "$APP"
