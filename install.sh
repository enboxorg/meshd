#!/usr/bin/env bash

set -euo pipefail

APP='meshd'
REPO='enboxorg/meshd'
INSTALL_DIR="${HOME}/.${APP}/bin"
REQUESTED_VERSION="${VERSION:-}"
# Test/ops override for the release download base (offline CI tests use a
# file:// mirror). Layout must match GitHub releases: <base>/<tag>/<archive>.
DOWNLOAD_BASE="${MESHD_INSTALL_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"
NO_MODIFY_PATH=false
TMP_DIR=''

cleanup() {
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT INT TERM

usage() {
  cat <<'EOF'
meshd installer

Usage: install.sh [options] [up [meshd-up-arguments...]]

Options:
  -h, --help              Show this help message
  -v, --version <version> Install a specific version (example: 0.1.0)
      --no-modify-path    Do not modify shell profile files

Everything after 'up' is passed to 'meshd up', so one command can install
meshd, request to join a network, wait for dashboard approval, and start
the mesh.

Examples:
  curl -fsSL https://meshd.sh/install | bash
  curl -fsSL https://meshd.sh/install | bash -s -- --version 0.1.0
  curl -fsSL https://meshd.sh/install | bash -s -- up 'meshd://invite/<token>'
EOF
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

http_get() {
  if has_command curl; then
    curl -fsSL "$1"
    return
  fi

  if has_command wget; then
    wget -qO- "$1"
    return
  fi

  fail 'curl or wget is required'
}

download_file() {
  local url="$1"
  local out="$2"

  if has_command curl; then
    curl -fsSL "$url" -o "$out"
    return
  fi

  if has_command wget; then
    wget -q "$url" -O "$out"
    return
  fi

  fail 'curl or wget is required'
}

detect_os() {
  case "$(uname -s)" in
    Linux) printf 'linux' ;;
    Darwin) printf 'darwin' ;;
    FreeBSD) printf 'freebsd' ;;
    CYGWIN*|MINGW*|MSYS*) printf 'windows' ;;
    *) fail 'unsupported operating system' ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'x64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) fail 'unsupported CPU architecture' ;;
  esac
}

latest_tag() {
  http_get "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

resolve_tag() {
  if [ -z "$REQUESTED_VERSION" ]; then
    latest_tag
    return
  fi

  case "$REQUESTED_VERSION" in
    v*) printf '%s' "$REQUESTED_VERSION" ;;
    *) printf 'v%s' "$REQUESTED_VERSION" ;;
  esac
}

extract_archive() {
  local archive="$1"
  local out_dir="$2"
  local os="$3"

  if [ "$os" = 'windows' ]; then
    if ! has_command unzip; then
      fail 'unzip is required for Windows artifacts'
    fi
    unzip -q "$archive" -d "$out_dir"
    return
  fi

  if ! has_command tar; then
    fail 'tar is required'
  fi
  tar -xzf "$archive" -C "$out_dir"
}

add_to_path() {
  local shell_name
  shell_name="$(basename "${SHELL:-bash}")"

  # fish does not use POSIX `export` syntax and does not source ~/.profile.
  # Drop an auto-sourced conf.d snippet using fish's own idempotent helper.
  if [ "$shell_name" = "fish" ]; then
    local fish_dir="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d"
    local fish_file="${fish_dir}/meshd.fish"
    local fish_line="fish_add_path ${INSTALL_DIR}"
    if [ -f "$fish_file" ] && grep -Fxq "$fish_line" "$fish_file"; then
      return
    fi
    if mkdir -p "$fish_dir" 2>/dev/null && [ -w "$fish_dir" ]; then
      printf '# meshd\n%s\n' "$fish_line" >> "$fish_file"
      printf 'Updated PATH in %s\n' "$fish_file"
      return
    fi
    printf 'Add this to your fish config:\n'
    printf '  %s\n' "$fish_line"
    return
  fi

  local line
  line="export PATH=${INSTALL_DIR}:\$PATH"

  local files=''
  case "$shell_name" in
    zsh) files="${ZDOTDIR:-$HOME}/.zshrc ${ZDOTDIR:-$HOME}/.zshenv" ;;
    bash) files="$HOME/.bashrc $HOME/.bash_profile $HOME/.profile" ;;
    *) files="$HOME/.profile" ;;
  esac

  local config=''
  for file in $files; do
    if [ -f "$file" ]; then
      config="$file"
      break
    fi
  done

  if [ -z "$config" ]; then
    printf 'Add this to your shell profile:\n'
    printf '  %s\n' "$line"
    return
  fi

  if grep -Fxq "$line" "$config"; then
    return
  fi

  if [ -w "$config" ]; then
    printf '\n# meshd\n%s\n' "$line" >> "$config"
    printf 'Updated PATH in %s\n' "$config"
    return
  fi

  printf 'Add this to your shell profile:\n'
  printf '  %s\n' "$line"
}

# run_meshd_up hands off to the freshly installed binary by absolute path
# (PATH updates only reach future shells). Under `curl | bash` stdin is the
# script pipe, so reattach /dev/tty when one exists — that keeps the vault
# password and sudo prompts working.
run_meshd_up() {
  local bin="$1"
  shift

  # ${1+"$@"} instead of bare "$@": bash <= 4.3 (macOS ships 3.2) treats an
  # empty "$@" as unbound under set -u.
  printf '\n==> Running meshd up\n'
  local code=0
  if (exec </dev/tty) 2>/dev/null; then
    "$bin" up ${1+"$@"} </dev/tty || code=$?
  else
    "$bin" up ${1+"$@"} || code=$?
  fi

  if [ "$code" -ne 0 ]; then
    local resume_args=''
    if [ "$#" -gt 0 ]; then
      resume_args=" $*"
    fi
    printf '\nmeshd up did not complete. Any join request stays pending; resume with:\n' >&2
    printf '  %s up%s\n' "$bin" "$resume_args" >&2
    exit "$code"
  fi
}

main() {
  RUN_UP=false
  RUN_UP_ARGS=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      -v|--version)
        if [[ -z "${2:-}" ]]; then
          fail '--version requires an argument'
        fi
        REQUESTED_VERSION="$2"
        shift 2
        ;;
      --no-modify-path)
        NO_MODIFY_PATH=true
        shift
        ;;
      up)
        RUN_UP=true
        shift
        RUN_UP_ARGS=("$@")
        break
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done

  local os
  os="$(detect_os)"
  local arch
  arch="$(detect_arch)"
  local tag
  tag="$(resolve_tag)"
  [ -n "$tag" ] || fail 'unable to determine release tag'

  local archive=''
  if [ "$os" = 'windows' ]; then
    archive="meshd-${os}-${arch}.zip"
  else
    archive="meshd-${os}-${arch}.tar.gz"
  fi

  local url
  url="${DOWNLOAD_BASE}/${tag}/${archive}"

  TMP_DIR="$(mktemp -d)"

  printf '==> Installing meshd %s\n' "$tag"
  download_file "$url" "${TMP_DIR}/${archive}"
  extract_archive "${TMP_DIR}/${archive}" "$TMP_DIR" "$os"

  mkdir -p "$INSTALL_DIR"

  local suffix=''
  if [ "$os" = 'windows' ]; then
    suffix='.exe'
  fi

  # Install atomically: a plain cp onto a running binary fails with
  # "Text file busy" (re-running the one-liner while meshd is up), while a
  # rename over it succeeds.
  cp "${TMP_DIR}/meshd${suffix}" "${INSTALL_DIR}/meshd${suffix}.new"
  chmod +x "${INSTALL_DIR}/meshd${suffix}.new"
  mv -f "${INSTALL_DIR}/meshd${suffix}.new" "${INSTALL_DIR}/meshd${suffix}"

  if [ "$NO_MODIFY_PATH" = false ] && [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    add_to_path
  fi

  printf '==> Installed to %s\n' "$INSTALL_DIR"
  "${INSTALL_DIR}/meshd${suffix}" --version || true

  if [ "$RUN_UP" = true ]; then
    # meshd up can wait minutes for dashboard approval; drop the download
    # scratch dir before handing off.
    cleanup
    TMP_DIR=''
    run_meshd_up "${INSTALL_DIR}/meshd${suffix}" ${RUN_UP_ARGS[@]+"${RUN_UP_ARGS[@]}"}
    return
  fi

  printf 'Run: meshd up\n'
}

main "$@"
