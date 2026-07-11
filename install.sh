#!/usr/bin/env bash

set -euo pipefail

APP='meshd'
REPO='enboxorg/meshd'
INSTALL_DIR="${HOME}/.${APP}/bin"
TRAY_APP_DIR="${HOME}/.${APP}/meshd-tray.app"
TRAY_APP_BACKUP="${TRAY_APP_DIR}.previous"
TRAY_SWAP_ACTIVE=false
TRAY_LAUNCH_AGENT_LABEL='org.enbox.meshd-tray'
TRAY_AUTOSTART_MARKER="${HOME}/.${APP}/.tray-autostart-initialized"
LAUNCHCTL="${MESHD_INSTALL_LAUNCHCTL:-/bin/launchctl}"
MESHD_WINDOWS_RESTART=false
REQUESTED_VERSION="${VERSION:-}"
# Test/ops override for the release download base (offline CI tests use a
# file:// mirror). Layout must match GitHub releases: <base>/<tag>/<archive>.
DOWNLOAD_BASE="${MESHD_INSTALL_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"
NO_MODIFY_PATH=false
TMP_DIR=''

cleanup() {
  if [ "$TRAY_SWAP_ACTIVE" = true ] && [ ! -e "$TRAY_APP_DIR" ] && [ -e "$TRAY_APP_BACKUP" ]; then
    mv "$TRAY_APP_BACKUP" "$TRAY_APP_DIR" || true
  fi
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
the mesh. On the first macOS install, the menu-bar app is also enabled at
login after setup completes.

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

print_shell_command() {
  local arg
  printf '  '
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

profile_arg_from() {
  while [ "$#" -gt 0 ]; do
    if [ "$1" = '--profile' ] && [ "$#" -gt 1 ]; then
      printf '%s' "$2"
      return 0
    fi
    shift
  done
  return 0
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

restart_macos_tray_if_loaded() {
  [ -x "$LAUNCHCTL" ] || return 0

  local service="gui/$(id -u)/${TRAY_LAUNCH_AGENT_LABEL}"
  if "$LAUNCHCTL" print "$service" >/dev/null 2>&1; then
    if ! "$LAUNCHCTL" kickstart -k "$service" >/dev/null 2>&1; then
      printf 'warning: meshd-tray was updated but could not be restarted; reopen it from the next login\n' >&2
    fi
  fi
}

install_macos_tray() {
  local source_app="$1"
  local staged="${TRAY_APP_DIR}.new"
  local had_previous=false

  [ -f "${source_app}/Contents/Info.plist" ] || fail 'macOS tray bundle is missing Info.plist'
  [ -f "${source_app}/Contents/MacOS/meshd-tray" ] || fail 'macOS tray bundle is missing its executable'

  # Recover the previous bundle if an earlier install was interrupted between
  # the two same-filesystem renames.
  if [ ! -e "$TRAY_APP_DIR" ] && [ -e "$TRAY_APP_BACKUP" ]; then
    mv "$TRAY_APP_BACKUP" "$TRAY_APP_DIR"
  fi
  rm -rf "$staged" "$TRAY_APP_BACKUP"
  cp -R "$source_app" "$staged"
  chmod +x "${staged}/Contents/MacOS/meshd-tray"

  TRAY_SWAP_ACTIVE=true
  if [ -e "$TRAY_APP_DIR" ]; then
    mv "$TRAY_APP_DIR" "$TRAY_APP_BACKUP"
    had_previous=true
  fi
  if ! mv "$staged" "$TRAY_APP_DIR"; then
    if [ "$had_previous" = true ]; then
      mv "$TRAY_APP_BACKUP" "$TRAY_APP_DIR" || true
    fi
    if [ -e "$TRAY_APP_DIR" ] || [ "$had_previous" = false ]; then
      TRAY_SWAP_ACTIVE=false
    fi
    return 1
  fi
  if ! ln -sfn "${TRAY_APP_DIR}/Contents/MacOS/meshd-tray" "${INSTALL_DIR}/meshd-tray"; then
    rm -rf "$TRAY_APP_DIR"
    if [ "$had_previous" = true ]; then
      mv "$TRAY_APP_BACKUP" "$TRAY_APP_DIR" || true
    fi
    if [ -e "$TRAY_APP_DIR" ] || [ "$had_previous" = false ]; then
      TRAY_SWAP_ACTIVE=false
    fi
    return 1
  fi

  rm -rf "$TRAY_APP_BACKUP"
  TRAY_SWAP_ACTIVE=false
  restart_macos_tray_if_loaded
}

enable_macos_tray_at_login() {
  local tray="${INSTALL_DIR}/meshd-tray"
  local profile="${1:-}"
  local tray_args=(install)
  if [ -n "$profile" ]; then
    tray_args+=(--profile "$profile")
  fi

  printf '\n==> Enabling meshd-tray at login\n'
  if "$tray" "${tray_args[@]}"; then
    if ! (
      umask 077
      printf 'initialized\n' > "${TRAY_AUTOSTART_MARKER}.new" &&
        mv -f "${TRAY_AUTOSTART_MARKER}.new" "$TRAY_AUTOSTART_MARKER"
    ); then
      printf 'warning: could not record meshd-tray login setup; a later installer run may retry it\n' >&2
      rm -f "${TRAY_AUTOSTART_MARKER}.new" || true
    fi
    return
  fi

  # launchctl requires an interactive Aqua session. A headless/SSH install
  # must still be allowed to finish the invite flow; leave an actionable retry
  # without retaining the invite in a LaunchAgent argument or environment.
  printf 'warning: meshd-tray could not be enabled at login; retry with:\n' >&2
  if [ -n "$profile" ]; then
    print_shell_command "$tray" install --profile "$profile" >&2
  else
    print_shell_command "$tray" install >&2
  fi
  return 0
}

windows_native_path() {
  if has_command cygpath; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

refresh_windows_startup_shortcut() {
  local target="$1"
  has_command powershell.exe || return 0

  local native_target
  native_target="$(windows_native_path "$target")"
  MESHD_TRAY_AUTOSTART_TARGET="$native_target" powershell.exe -NoProfile -NonInteractive -Command '
    $ErrorActionPreference = "Stop"
    $linkPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\meshd-tray.lnk"
    if (-not (Test-Path -LiteralPath $linkPath)) { exit 0 }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($linkPath)
    $target = $env:MESHD_TRAY_AUTOSTART_TARGET
    $installDir = Split-Path $target
    $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
      try {
        $_.Path -and (Split-Path $_.Path) -eq $installDir -and $_.Name -like "meshd-tray*"
      } catch { $false }
    })
    $shortcut.TargetPath = $target
    $shortcut.WorkingDirectory = $installDir
    $shortcut.Save()
    if ($running.Count -gt 0) {
      $running | Stop-Process -Force
      $running | Wait-Process -ErrorAction SilentlyContinue
      Start-Process -FilePath $linkPath
    }
  '
}

install_windows_tray() {
  local source_exe="$1"
  local tag="$2"
  local version_id="${tag#v}"
  version_id="${version_id//[^a-zA-Z0-9._-]/_}"
  [ -n "$version_id" ] || fail 'release tag cannot be used as a Windows tray filename'

  local checksum size
  read -r checksum size _ <<EOF
$(cksum "$source_exe")
EOF
  local versioned_name="meshd-tray-${version_id}-${checksum}-${size}.exe"
  local versioned_path="${INSTALL_DIR}/${versioned_name}"
  local stable_path="${INSTALL_DIR}/meshd-tray.exe"
  local pointer_path="${INSTALL_DIR}/meshd-tray.current"

  if [ ! -f "$versioned_path" ]; then
    cp "$source_exe" "${versioned_path}.new"
    chmod +x "${versioned_path}.new"
    mv -f "${versioned_path}.new" "$versioned_path"
  fi

  printf '%s\n' "$versioned_name" > "${pointer_path}.new"
  mv -f "${pointer_path}.new" "$pointer_path"

  cp "$source_exe" "${stable_path}.new"
  chmod +x "${stable_path}.new"

  # Retarget and stop the old version before attempting to replace the stable
  # command path. A running Startup tray executes the versioned image, but a
  # manually launched older install may still be holding the stable path.
  refresh_windows_startup_shortcut "$versioned_path"

  if ! mv -f "${stable_path}.new" "$stable_path"; then
    rm -f "${stable_path}.new"
    if [ ! -f "$stable_path" ]; then
      return 1
    fi
    printf 'warning: the meshd-tray command is currently running; the Startup shortcut will use the new version\n' >&2
  fi

  local old
  for old in "${INSTALL_DIR}"/meshd-tray-*.exe; do
    [ -e "$old" ] || continue
    [ "$old" = "$versioned_path" ] && continue
    rm -f "$old" 2>/dev/null || true
  done
}

prepare_windows_meshd_upgrade() {
  local installed="${INSTALL_DIR}/meshd.exe"
  [ -f "$installed" ] || return 0

  local output
  if ! output="$("$installed" down 2>&1)"; then
    printf '%s\n' "$output" >&2
    fail 'could not stop the running Windows meshd daemon for upgrade'
  fi
  case "$output" in
    *'Stopping meshd'*)
      MESHD_WINDOWS_RESTART=true
      ;;
  esac
}

restart_windows_meshd_after_upgrade() {
  [ "$MESHD_WINDOWS_RESTART" = true ] || return 0

  printf '==> Restarting meshd after Windows upgrade\n'
  local bin="${INSTALL_DIR}/meshd.exe"
  if (exec </dev/tty) 2>/dev/null; then
    "$bin" up </dev/tty
  else
    "$bin" up
  fi
  MESHD_WINDOWS_RESTART=false
}

# run_meshd_up hands off to the freshly installed binary by absolute path
# (PATH updates only reach future shells). Under `curl | bash` stdin is the
# script pipe, so reattach /dev/tty when one exists — that keeps the vault
# password and sudo prompts working.
run_meshd_up() {
  local bin="$1"
  local profile="$2"
  shift 2

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
    printf '\nmeshd up did not complete. Re-run the original command to retry.\n' >&2
    printf 'If its join request is already pending, resume without repeating the invite:\n' >&2
    if [ -n "$profile" ]; then
      print_shell_command "$bin" up --profile "$profile" >&2
    else
      print_shell_command "$bin" up >&2
    fi
    return "$code"
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

  if [ "$os" = 'windows' ]; then
    prepare_windows_meshd_upgrade
  fi

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

  local tray_installed=false
  local macos_tray_needs_autostart=false
  local up_profile
  up_profile="$(profile_arg_from ${RUN_UP_ARGS[@]+"${RUN_UP_ARGS[@]}"})"
  if [ "$os" = 'darwin' ] && [ -d "${TMP_DIR}/meshd-tray.app" ]; then
    # Installer-owned one-time state lets existing tray users receive this
    # behavior once, while a later explicit tray uninstall remains respected
    # across upgrades.
    if [ ! -e "$TRAY_AUTOSTART_MARKER" ]; then
      macos_tray_needs_autostart=true
    fi
    install_macos_tray "${TMP_DIR}/meshd-tray.app"
    tray_installed=true
  elif [ "$os" = 'windows' ] && [ -f "${TMP_DIR}/meshd-tray.exe" ]; then
    install_windows_tray "${TMP_DIR}/meshd-tray.exe" "$tag"
    tray_installed=true
  fi

  if [ "$os" = 'windows' ] && [ "$RUN_UP" = false ]; then
    restart_windows_meshd_after_upgrade
  fi

  if [ "$NO_MODIFY_PATH" = false ] && [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    add_to_path
  fi

  printf '==> Installed to %s\n' "$INSTALL_DIR"
  "${INSTALL_DIR}/meshd${suffix}" --version || true

  if [ "$tray_installed" = true ] && [ "$os" != 'darwin' ]; then
    printf 'Enable the menu-bar app at login with: meshd-tray install\n'
  fi

  if [ "$RUN_UP" = true ]; then
    # meshd up can wait minutes for dashboard approval; drop the download
    # scratch dir before handing off.
    cleanup
    TMP_DIR=''
    local up_code=0
    run_meshd_up "${INSTALL_DIR}/meshd${suffix}" "$up_profile" ${RUN_UP_ARGS[@]+"${RUN_UP_ARGS[@]}"} || up_code=$?
    if [ "$macos_tray_needs_autostart" = true ]; then
      enable_macos_tray_at_login "$up_profile"
    fi
    if [ "$up_code" -ne 0 ]; then
      exit "$up_code"
    fi
    return
  fi

  if [ "$macos_tray_needs_autostart" = true ]; then
    enable_macos_tray_at_login "$up_profile"
  fi

  printf 'Run: meshd up\n'
}

main "$@"
