#!/usr/bin/env bash

set -euo pipefail

INSTALL_URL="${MESHD_INSTALL_URL:-https://meshd.sh/install}"
# meshd.sh sits behind Cloudflare bot protection that returns 403 to datacenter
# IPs such as CI runners, even though it serves fine to real users. When the
# primary edge is unreachable, fall back to this source (e.g. the raw install.sh
# at the release tag) so the smoke test still exercises the installer and the
# published release binaries end to end instead of failing the release.
INSTALL_FALLBACK_URL="${MESHD_INSTALL_FALLBACK_URL:-}"
INSTALL_USER_AGENT="${MESHD_INSTALL_USER_AGENT:-meshd-install-smoke/1 (+https://github.com/enboxorg/meshd)}"
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

fetch_installer() {
  # Write the installer script to $1, trying the primary URL then the fallback.
  # A realistic User-Agent sidesteps UA-based edge rules and --retry rides out
  # transient network errors; a persistent primary failure (e.g. a Cloudflare
  # 403 to a CI runner) falls through to the fallback rather than failing.
  local out="$1" url
  for url in "$INSTALL_URL" "$INSTALL_FALLBACK_URL"; do
    [ -n "$url" ] || continue
    printf '==> Fetching installer from %s\n' "$url"
    if curl -fsSL --retry 3 --retry-connrefused -A "$INSTALL_USER_AGENT" "$url" -o "$out"; then
      return 0
    fi
    printf 'install-smoke: warning: could not fetch installer from %s\n' "$url" >&2
  done
  return 1
}

installer="${TMP_DIR}/install.sh"
if ! fetch_installer "$installer"; then
  fail "could not fetch the installer from any source (primary: ${INSTALL_URL}${INSTALL_FALLBACK_URL:+, fallback: ${INSTALL_FALLBACK_URL}})"
fi
HOME="$HOME_DIR" bash "$installer" "${args[@]}"

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
