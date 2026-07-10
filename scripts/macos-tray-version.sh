#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf 'usage: %s <semver> <short|build>\n' "$(basename "$0")" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage

version="${1#v}"
kind="$2"
core="${version%%[-+]*}"
suffix="${version#"$core"}"

IFS='.' read -r major minor patch extra <<EOF
${core}
EOF

valid_component() {
  case "$1" in
    0|[1-9]|[1-9][0-9]*) return 0 ;;
    *) return 1 ;;
  esac
}

if [ -n "${extra:-}" ] || ! valid_component "${major:-}" ||
  ! valid_component "${minor:-}" || ! valid_component "${patch:-}"; then
  printf 'invalid semantic version: %s\n' "$1" >&2
  exit 1
fi

if [ -n "$suffix" ] && [[ ! "$suffix" =~ ^(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  printf 'invalid semantic version suffix: %s\n' "$1" >&2
  exit 1
fi

# Apple's CFBundleVersion format permits three numeric components. Its first
# component must be positive and is limited to four digits; the remaining two
# components are limited to two digits. Offset SemVer's major by one so the
# project's pre-1.0 releases remain valid and retain semantic ordering.
major_value=$((10#$major))
minor_value=$((10#$minor))
patch_value=$((10#$patch))
if [ "$major_value" -gt 9998 ] || [ "$minor_value" -gt 99 ] || [ "$patch_value" -gt 99 ]; then
  printf 'semantic version cannot be represented as an Apple bundle version: %s\n' "$1" >&2
  exit 1
fi

case "$kind" in
  short)
    printf '%d.%d.%d\n' "$major_value" "$minor_value" "$patch_value"
    ;;
  build)
    printf '%d.%d.%d\n' "$((major_value + 1))" "$minor_value" "$patch_value"
    ;;
  *)
    usage
    ;;
esac
