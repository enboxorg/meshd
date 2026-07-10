#!/usr/bin/env bash
# Offline test for versioned Windows tray installation and upgrades. The host
# remains Linux; a fake uname selects the Windows release artifact.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL="${HERE}/../../install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

for command in curl zip unzip; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'install-tray-windows test requires %s\n' "$command" >&2
    exit 1
  }
done

FAKE_BIN="${WORK}/bin"
PAYLOAD="${WORK}/payload"
HOME_DIR="${WORK}/home"
DAEMON_LOG="${WORK}/daemon.log"
mkdir -p "$FAKE_BIN" "$PAYLOAD" "$HOME_DIR"

cat > "${FAKE_BIN}/uname" <<'FAKE'
#!/usr/bin/env bash
case "${1:-}" in
  -s) printf 'MINGW64_NT-10.0\n' ;;
  -m) printf 'x86_64\n' ;;
  *) printf 'MINGW64_NT-10.0\n' ;;
esac
FAKE
chmod +x "${FAKE_BIN}/uname"

make_release() {
  local version="$1"
  local marker="$2"
  local dist="${WORK}/dist/v${version}"
  mkdir -p "$dist"
  cat > "${PAYLOAD}/meshd.exe" <<FAKE
#!/usr/bin/env bash
case "\${1:-}" in
  --version) echo 'meshd ${version}' ;;
  down)
    echo 'Stopping meshd (test fixture)...'
    echo 'down ${version}' >> "\$MESHD_TEST_WINDOWS_DAEMON_LOG"
    ;;
  up)
    echo 'up ${version}' >> "\$MESHD_TEST_WINDOWS_DAEMON_LOG"
    ;;
esac
FAKE
  cat > "${PAYLOAD}/meshd-tray.exe" <<FAKE
#!/usr/bin/env bash
# tray fixture: ${marker}
exit 0
FAKE
  chmod +x "${PAYLOAD}/meshd.exe" "${PAYLOAD}/meshd-tray.exe"
  (cd "$PAYLOAD" && zip -q "${dist}/meshd-windows-x64.zip" meshd.exe meshd-tray.exe)
}

run_install() {
  local version="$1"
  HOME="$HOME_DIR" \
  PATH="${FAKE_BIN}:$PATH" \
  VERSION="$version" \
  MESHD_INSTALL_DOWNLOAD_BASE="file://${WORK}/dist" \
  MESHD_TEST_WINDOWS_DAEMON_LOG="$DAEMON_LOG" \
    bash "$INSTALL" --no-modify-path >/dev/null
}

make_release 9.9.9 first
run_install 9.9.9
test -x "${HOME_DIR}/.meshd/bin/meshd-tray.exe"
first_target="$(tr -d '\r\n' < "${HOME_DIR}/.meshd/bin/meshd-tray.current")"
case "$first_target" in meshd-tray-9.9.9-*.exe) ;; *) exit 1 ;; esac
test -x "${HOME_DIR}/.meshd/bin/${first_target}"
grep -q 'tray fixture: first' "${HOME_DIR}/.meshd/bin/meshd-tray.exe"

make_release 9.9.10 second
run_install 9.9.10
second_target="$(tr -d '\r\n' < "${HOME_DIR}/.meshd/bin/meshd-tray.current")"
case "$second_target" in meshd-tray-9.9.10-*.exe) ;; *) exit 1 ;; esac
test -x "${HOME_DIR}/.meshd/bin/${second_target}"
grep -q 'tray fixture: second' "${HOME_DIR}/.meshd/bin/meshd-tray.exe"
test ! -e "${HOME_DIR}/.meshd/bin/${first_target}"
grep -q '^down 9.9.9$' "$DAEMON_LOG"
grep -q '^up 9.9.10$' "$DAEMON_LOG"

echo 'Windows tray artifact upgrade test passed'
