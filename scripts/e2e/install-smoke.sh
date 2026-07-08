#!/usr/bin/env bash

set -euo pipefail

INSTALL_URL="${MESHD_INSTALL_URL:-https://meshd.sh/install}"
REQUESTED_VERSION="${MESHD_INSTALL_REQUESTED_VERSION:-}"
EXPECTED_VERSION="${MESHD_INSTALL_EXPECTED_VERSION:-}"
TMP_DIR="${MESHD_INSTALL_TMP_DIR:-}"
CLEANUP_TMP=false

fail() {
  printf 'install-smoke: error: %s\n' "$*" >&2
  exit 1
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

cleanup() {
  if [ "$CLEANUP_TMP" = true ] && [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT INT TERM

if ! has_command curl; then
  fail 'curl is required'
fi

if ! has_command bash; then
  fail 'bash is required'
fi

if [ -z "$TMP_DIR" ]; then
  TMP_DIR="$(mktemp -d)"
  CLEANUP_TMP=true
fi

HOME_DIR="${TMP_DIR}/home"
mkdir -p "$HOME_DIR"

args=(--no-modify-path)
if [ -n "$REQUESTED_VERSION" ]; then
  args+=(--version "$REQUESTED_VERSION")
fi

if [ -z "$EXPECTED_VERSION" ] && [ -n "$REQUESTED_VERSION" ]; then
  EXPECTED_VERSION="$REQUESTED_VERSION"
fi

printf '==> Fetching installer from %s\n' "$INSTALL_URL"
curl -fsSL "$INSTALL_URL" | HOME="$HOME_DIR" bash -s -- "${args[@]}"

bin="${HOME_DIR}/.meshd/bin/meshd"
if [ ! -x "$bin" ]; then
  fail "expected installed binary at ${bin}"
fi

version_output="$("$bin" --version)"
printf '==> Installed binary reports: %s\n' "$version_output"

if [ -n "$EXPECTED_VERSION" ]; then
  expected="${EXPECTED_VERSION#v}"
  case "$version_output" in
    "meshd ${expected}"*) ;;
    *) fail "expected meshd ${expected}, got: ${version_output}" ;;
  esac
fi

"$bin" --help >/dev/null
printf '==> Installer smoke test passed\n'
