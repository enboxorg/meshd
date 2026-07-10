#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_SCRIPT="${HERE}/../macos-tray-version.sh"

test "$("$VERSION_SCRIPT" v0.0.7 short)" = '0.0.7'
test "$("$VERSION_SCRIPT" v0.0.7 build)" = '1.0.7'
test "$("$VERSION_SCRIPT" 12.34.56-rc.1+build.9 short)" = '12.34.56'
test "$("$VERSION_SCRIPT" 12.34.56-rc.1+build.9 build)" = '13.34.56'

for invalid in 0.0 01.2.3 0.100.0 0.0.100 9999.0.0 not-a-version; do
  if "$VERSION_SCRIPT" "$invalid" build >/dev/null 2>&1; then
    printf 'expected invalid version to fail: %s\n' "$invalid" >&2
    exit 1
  fi
done

printf 'macOS tray version mapping test passed\n'
