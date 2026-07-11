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
  exit 0
fi
printf 'meshd-up\n' >> "${MESHD_TEST_EVENT_LOG:?}"
printf '%s\n' "$@" > "${MESHD_TEST_MESHD_ARGV_LOG:?}"
exit "${MESHD_TEST_MESHD_EXIT:-0}"
FAKE
cat > "${PAYLOAD}/meshd-tray.app/Contents/MacOS/meshd-tray" <<'FAKE'
#!/usr/bin/env bash
# tray fixture: first
printf 'tray-install\n' >> "${MESHD_TEST_EVENT_LOG:?}"
printf '%s\n' "$@" >> "${MESHD_TEST_TRAY_ARGV_LOG:?}"
exit "${MESHD_TEST_TRAY_EXIT:-0}"
FAKE
printf '<plist><dict><key>LSUIElement</key><true/></dict></plist>\n' > "${PAYLOAD}/meshd-tray.app/Contents/Info.plist"
chmod +x "${PAYLOAD}/meshd" "${PAYLOAD}/meshd-tray.app/Contents/MacOS/meshd-tray"
tar -czf "${DIST}/meshd-darwin-arm64.tar.gz" -C "$PAYLOAD" meshd meshd-tray.app

HOME_DIR="${WORK}/home"
LAUNCHCTL_LOG="${WORK}/launchctl.log"
EVENT_LOG="${WORK}/events.log"
MESHD_ARGV_LOG="${WORK}/meshd-argv.log"
TRAY_ARGV_LOG="${WORK}/tray-argv.log"
mkdir -p "$HOME_DIR"
output="$(
  HOME="$HOME_DIR" \
  PATH="${FAKE_BIN}:$PATH" \
  VERSION="$VERSION_TAG" \
  MESHD_INSTALL_DOWNLOAD_BASE="file://${WORK}/dist" \
  MESHD_INSTALL_LAUNCHCTL="${FAKE_BIN}/launchctl" \
  MESHD_TEST_LAUNCHCTL_LOG="$LAUNCHCTL_LOG" \
  MESHD_TEST_EVENT_LOG="$EVENT_LOG" \
  MESHD_TEST_MESHD_ARGV_LOG="$MESHD_ARGV_LOG" \
  MESHD_TEST_TRAY_ARGV_LOG="$TRAY_ARGV_LOG" \
    bash "$INSTALL" --no-modify-path up 'meshd://invite/test-token' --profile work
)"

test -x "${HOME_DIR}/.meshd/bin/meshd"
test -x "${HOME_DIR}/.meshd/meshd-tray.app/Contents/MacOS/meshd-tray"
test -f "${HOME_DIR}/.meshd/meshd-tray.app/Contents/Info.plist"
test -L "${HOME_DIR}/.meshd/bin/meshd-tray"
test "$(readlink "${HOME_DIR}/.meshd/bin/meshd-tray")" = "${HOME_DIR}/.meshd/meshd-tray.app/Contents/MacOS/meshd-tray"
grep -q 'tray fixture: first' "${HOME_DIR}/.meshd/meshd-tray.app/Contents/MacOS/meshd-tray"
grep -q '^kickstart -k gui/[0-9][0-9]*/org.enbox.meshd-tray$' "$LAUNCHCTL_LOG"
test "$(cat "$MESHD_ARGV_LOG")" = "$(printf 'up\nmeshd://invite/test-token\n--profile\nwork')"
test "$(cat "$TRAY_ARGV_LOG")" = "$(printf 'install\n--profile\nwork')"
test "$(cat "$EVENT_LOG")" = "$(printf 'meshd-up\ntray-install')"
test -f "${HOME_DIR}/.meshd/.tray-autostart-initialized"
grep -q 'Enabling meshd-tray at login' <<<"$output"

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
MESHD_TEST_EVENT_LOG="$EVENT_LOG" \
MESHD_TEST_MESHD_ARGV_LOG="$MESHD_ARGV_LOG" \
MESHD_TEST_TRAY_ARGV_LOG="$TRAY_ARGV_LOG" \
  bash "$INSTALL" --no-modify-path >/dev/null

grep -q 'tray fixture: second' "${HOME_DIR}/.meshd/meshd-tray.app/Contents/MacOS/meshd-tray"
test ! -e "${HOME_DIR}/.meshd/meshd-tray.app.previous"
test "$(grep -c '^kickstart -k gui/[0-9][0-9]*/org.enbox.meshd-tray$' "$LAUNCHCTL_LOG")" -eq 2
test "$(cat "$TRAY_ARGV_LOG")" = "$(printf 'install\n--profile\nwork')"

# A plain first install also enables the tray without running meshd up.
PLAIN_HOME="${WORK}/plain-home"
PLAIN_EVENT_LOG="${WORK}/plain-events.log"
PLAIN_MESHD_ARGV_LOG="${WORK}/plain-meshd-argv.log"
PLAIN_TRAY_ARGV_LOG="${WORK}/plain-tray-argv.log"
mkdir -p "$PLAIN_HOME"
plain_output="$(
  HOME="$PLAIN_HOME" \
  PATH="${FAKE_BIN}:$PATH" \
  VERSION="$VERSION_TAG" \
  MESHD_INSTALL_DOWNLOAD_BASE="file://${WORK}/dist" \
  MESHD_INSTALL_LAUNCHCTL="${FAKE_BIN}/launchctl" \
  MESHD_TEST_LAUNCHCTL_LOG="$LAUNCHCTL_LOG" \
  MESHD_TEST_EVENT_LOG="$PLAIN_EVENT_LOG" \
  MESHD_TEST_MESHD_ARGV_LOG="$PLAIN_MESHD_ARGV_LOG" \
  MESHD_TEST_TRAY_ARGV_LOG="$PLAIN_TRAY_ARGV_LOG" \
    bash "$INSTALL" --no-modify-path
)"
test ! -e "$PLAIN_MESHD_ARGV_LOG"
test "$(cat "$PLAIN_TRAY_ARGV_LOG")" = 'install'
test "$(cat "$PLAIN_EVENT_LOG")" = 'tray-install'
test -f "${PLAIN_HOME}/.meshd/.tray-autostart-initialized"
grep -q 'Run: meshd up' <<<"$plain_output"

# Headless tray registration is optional: a successful invite remains
# successful, emits an absolute retry command, and can be retried later.
WARN_HOME="${WORK}/warn home"
WARN_EVENT_LOG="${WORK}/warn-events.log"
WARN_MESHD_ARGV_LOG="${WORK}/warn-meshd-argv.log"
WARN_TRAY_ARGV_LOG="${WORK}/warn-tray-argv.log"
WARN_STDERR="${WORK}/warn-stderr.log"
mkdir -p "$WARN_HOME"
HOME="$WARN_HOME" \
PATH="${FAKE_BIN}:$PATH" \
VERSION="$VERSION_TAG" \
MESHD_INSTALL_DOWNLOAD_BASE="file://${WORK}/dist" \
MESHD_INSTALL_LAUNCHCTL="${FAKE_BIN}/launchctl" \
MESHD_TEST_LAUNCHCTL_LOG="$LAUNCHCTL_LOG" \
MESHD_TEST_EVENT_LOG="$WARN_EVENT_LOG" \
MESHD_TEST_MESHD_ARGV_LOG="$WARN_MESHD_ARGV_LOG" \
MESHD_TEST_TRAY_ARGV_LOG="$WARN_TRAY_ARGV_LOG" \
MESHD_TEST_TRAY_EXIT=9 \
  bash "$INSTALL" --no-modify-path up 'meshd://invite/warn-token' --profile work \
    >/dev/null 2>"$WARN_STDERR"

test "$(cat "$WARN_MESHD_ARGV_LOG")" = "$(printf 'up\nmeshd://invite/warn-token\n--profile\nwork')"
test "$(cat "$WARN_TRAY_ARGV_LOG")" = "$(printf 'install\n--profile\nwork')"
test "$(cat "$WARN_EVENT_LOG")" = "$(printf 'meshd-up\ntray-install')"
test ! -e "${WARN_HOME}/.meshd/.tray-autostart-initialized"
warn_retry="$(printf '%q ' "${WARN_HOME}/.meshd/bin/meshd-tray" install --profile work)"
grep -Fq "  $warn_retry" "$WARN_STDERR"
! grep -q 'warn-token' "$WARN_STDERR"

# A failed invite and a failed headless LaunchAgent registration preserve the
# meshd up exit code, still attempt tray setup afterward, and leave the marker
# absent so a later interactive install can retry.
FAIL_HOME="${WORK}/fail home"
FAIL_EVENT_LOG="${WORK}/fail-events.log"
FAIL_MESHD_ARGV_LOG="${WORK}/fail-meshd-argv.log"
FAIL_TRAY_ARGV_LOG="${WORK}/fail-tray-argv.log"
FAIL_STDERR="${WORK}/fail-stderr.log"
mkdir -p "$FAIL_HOME"
rc=0
HOME="$FAIL_HOME" \
PATH="${FAKE_BIN}:$PATH" \
VERSION="$VERSION_TAG" \
MESHD_INSTALL_DOWNLOAD_BASE="file://${WORK}/dist" \
MESHD_INSTALL_LAUNCHCTL="${FAKE_BIN}/launchctl" \
MESHD_TEST_LAUNCHCTL_LOG="$LAUNCHCTL_LOG" \
MESHD_TEST_EVENT_LOG="$FAIL_EVENT_LOG" \
MESHD_TEST_MESHD_ARGV_LOG="$FAIL_MESHD_ARGV_LOG" \
MESHD_TEST_TRAY_ARGV_LOG="$FAIL_TRAY_ARGV_LOG" \
MESHD_TEST_MESHD_EXIT=7 \
MESHD_TEST_TRAY_EXIT=9 \
  bash "$INSTALL" --no-modify-path up 'meshd://invite/failure-token' --profile work \
    >/dev/null 2>"$FAIL_STDERR" || rc=$?

test "$rc" -eq 7
test "$(cat "$FAIL_MESHD_ARGV_LOG")" = "$(printf 'up\nmeshd://invite/failure-token\n--profile\nwork')"
test "$(cat "$FAIL_TRAY_ARGV_LOG")" = "$(printf 'install\n--profile\nwork')"
test "$(cat "$FAIL_EVENT_LOG")" = "$(printf 'meshd-up\ntray-install')"
test ! -e "${FAIL_HOME}/.meshd/.tray-autostart-initialized"
grep -q 'meshd-tray could not be enabled at login' "$FAIL_STDERR"
fail_up_retry="$(printf '%q ' "${FAIL_HOME}/.meshd/bin/meshd" up --profile work)"
fail_tray_retry="$(printf '%q ' "${FAIL_HOME}/.meshd/bin/meshd-tray" install --profile work)"
grep -Fq "  $fail_up_retry" "$FAIL_STDERR"
grep -Fq "  $fail_tray_retry" "$FAIL_STDERR"
! grep -q 'failure-token' "$FAIL_STDERR"

echo 'tray artifact install test passed'
