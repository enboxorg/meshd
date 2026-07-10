#!/usr/bin/env bash
# Offline test for installing the macOS tray bundle from the normal release
# archive. The host remains Linux; a fake uname selects the Darwin artifact.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL="${HERE}/../../install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

command -v curl >/dev/null 2>&1 || { echo 'install-tray test requires curl' >&2; exit 1; }

VERSION_TAG='9.9.9'
DIST="${WORK}/dist/v${VERSION_TAG}"
PAYLOAD="${WORK}/payload"
FAKE_BIN="${WORK}/bin"
mkdir -p "$DIST" "$PAYLOAD/meshd-tray.app/Contents/MacOS" "$FAKE_BIN"

cat > "${FAKE_BIN}/uname" <<'FAKE'
#!/usr/bin/env bash
case "${1:-}" in
  -s) printf 'Darwin\n' ;;
  -m) printf 'arm64\n' ;;
  *) printf 'Darwin\n' ;;
esac
FAKE
chmod +x "${FAKE_BIN}/uname"

cat > "${FAKE_BIN}/launchctl" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MESHD_TEST_LAUNCHCTL_LOG"
case "${1:-}" in
  print|kickstart) exit 0 ;;
  *) exit 1 ;;
esac
FAKE
chmod +x "${FAKE_BIN}/launchctl"

cat > "${PAYLOAD}/meshd" <<'FAKE'
#!/usr/bin/env bash
if [ "${1:-}" = '--version' ]; then
  echo 'meshd 9.9.9'
fi
FAKE
cat > "${PAYLOAD}/meshd-tray.app/Contents/MacOS/meshd-tray" <<'FAKE'
#!/usr/bin/env bash
# tray fixture: first
exit 0
FAKE
printf '<plist><dict><key>LSUIElement</key><true/></dict></plist>\n' > "${PAYLOAD}/meshd-tray.app/Contents/Info.plist"
chmod +x "${PAYLOAD}/meshd" "${PAYLOAD}/meshd-tray.app/Contents/MacOS/meshd-tray"
tar -czf "${DIST}/meshd-darwin-arm64.tar.gz" -C "$PAYLOAD" meshd meshd-tray.app

HOME_DIR="${WORK}/home"
LAUNCHCTL_LOG="${WORK}/launchctl.log"
mkdir -p "$HOME_DIR"
output="$(
  HOME="$HOME_DIR" \
  PATH="${FAKE_BIN}:$PATH" \
  VERSION="$VERSION_TAG" \
  MESHD_INSTALL_DOWNLOAD_BASE="file://${WORK}/dist" \
  MESHD_INSTALL_LAUNCHCTL="${FAKE_BIN}/launchctl" \
  MESHD_TEST_LAUNCHCTL_LOG="$LAUNCHCTL_LOG" \
    bash "$INSTALL" --no-modify-path
)"

test -x "${HOME_DIR}/.meshd/bin/meshd"
test -x "${HOME_DIR}/.meshd/meshd-tray.app/Contents/MacOS/meshd-tray"
test -f "${HOME_DIR}/.meshd/meshd-tray.app/Contents/Info.plist"
test -L "${HOME_DIR}/.meshd/bin/meshd-tray"
test "$(readlink "${HOME_DIR}/.meshd/bin/meshd-tray")" = "${HOME_DIR}/.meshd/meshd-tray.app/Contents/MacOS/meshd-tray"
grep -q 'tray fixture: first' "${HOME_DIR}/.meshd/meshd-tray.app/Contents/MacOS/meshd-tray"
grep -q '^kickstart -k gui/[0-9][0-9]*/org.enbox.meshd-tray$' "$LAUNCHCTL_LOG"
grep -q 'meshd-tray install' <<<"$output"

# Reinstall over an existing app and verify the two-rename swap leaves the new
# bundle live, removes its rollback copy, and restarts the loaded LaunchAgent.
sed -i 's/tray fixture: first/tray fixture: second/' "${PAYLOAD}/meshd-tray.app/Contents/MacOS/meshd-tray"
tar -czf "${DIST}/meshd-darwin-arm64.tar.gz" -C "$PAYLOAD" meshd meshd-tray.app
HOME="$HOME_DIR" \
PATH="${FAKE_BIN}:$PATH" \
VERSION="$VERSION_TAG" \
MESHD_INSTALL_DOWNLOAD_BASE="file://${WORK}/dist" \
MESHD_INSTALL_LAUNCHCTL="${FAKE_BIN}/launchctl" \
MESHD_TEST_LAUNCHCTL_LOG="$LAUNCHCTL_LOG" \
  bash "$INSTALL" --no-modify-path >/dev/null

grep -q 'tray fixture: second' "${HOME_DIR}/.meshd/meshd-tray.app/Contents/MacOS/meshd-tray"
test ! -e "${HOME_DIR}/.meshd/meshd-tray.app.previous"
test "$(grep -c '^kickstart -k gui/[0-9][0-9]*/org.enbox.meshd-tray$' "$LAUNCHCTL_LOG")" -eq 2

echo 'tray artifact install test passed'
