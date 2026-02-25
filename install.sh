#!/usr/bin/env bash

set -euo pipefail

PACKAGE='github.com/enboxorg/dwn-mesh/cmd/dwn-mesh@latest'

log() {
  printf '==> %s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

is_windows() {
  case "$(uname -s)" in
    CYGWIN*|MINGW*|MSYS*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

install_go() {
  if is_windows; then
    if ! has_command powershell.exe; then
      fail 'Go is required and powershell.exe was not found to install it.'
    fi

    log 'Installing Go via winget (PowerShell)'
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "winget install -e --id GoLang.Go"
    return
  fi

  if has_command brew; then
    log 'Installing Go via Homebrew'
    brew install go
    return
  fi

  if has_command apt-get; then
    log 'Installing Go via apt-get'
    sudo apt-get update
    sudo apt-get install -y golang-go
    return
  fi

  if has_command dnf; then
    log 'Installing Go via dnf'
    sudo dnf install -y golang
    return
  fi

  if has_command yum; then
    log 'Installing Go via yum'
    sudo yum install -y golang
    return
  fi

  if has_command pacman; then
    log 'Installing Go via pacman'
    sudo pacman -Sy --noconfirm go
    return
  fi

  if has_command apk; then
    log 'Installing Go via apk'
    sudo apk add --no-cache go
    return
  fi

  if has_command zypper; then
    log 'Installing Go via zypper'
    sudo zypper install -y go
    return
  fi

  fail 'Go is required. Please install Go 1.25+ and rerun this script.'
}

resolve_go() {
  if has_command go; then
    printf '%s\n' "$(command -v go)"
    return
  fi

  if is_windows; then
    local candidate='/c/Program Files/Go/bin/go.exe'
    if [ -x "$candidate" ]; then
      PATH="/c/Program Files/Go/bin:$PATH"
      printf '%s\n' "$candidate"
      return
    fi
  fi

  fail 'Unable to locate Go after installation.'
}

main() {
  log 'Installing dwn-mesh CLI'

  if ! has_command go; then
    install_go
  fi

  local go_cmd
  go_cmd="$(resolve_go)"

  "$go_cmd" install "$PACKAGE"

  local go_bin
  go_bin="$($go_cmd env GOPATH)/bin"
  PATH="$go_bin:$PATH"

  local mesh_cmd=''
  if has_command dwn-mesh; then
    mesh_cmd='dwn-mesh'
  elif has_command dwn-mesh.exe; then
    mesh_cmd='dwn-mesh.exe'
  fi

  if [ -z "$mesh_cmd" ]; then
    fail 'Installation completed, but dwn-mesh is not on PATH.'
  fi

  log 'Installed successfully'
  "$mesh_cmd" --version

  printf 'If needed, add this to your shell profile:\n'
  printf '  export PATH="%s:$PATH"\n' "$go_bin"
}

main "$@"
