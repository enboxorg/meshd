#!/usr/bin/env bash
#
# Unit test for install-smoke.sh's installer-fetch/fallback behavior. Runs fully
# offline against a fake installer served over file:// URLs — no release, no
# network — so it is safe to run on every CI push/PR.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMOKE="${HERE}/install-smoke.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

# A stand-in for the real install.sh: it just drops an executable that reports
# the version it was asked to install, which is all install-smoke.sh checks.
FAKE="${WORK}/fake-install.sh"
cat > "$FAKE" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
ver="test"
while [ $# -gt 0 ]; do
  case "$1" in
    --version) ver="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "${HOME}/.meshd/bin"
cat > "${HOME}/.meshd/bin/meshd" <<EOF
#!/usr/bin/env bash
[ "\$1" = "--version" ] && echo "meshd ${ver}" || true
exit 0
EOF
chmod +x "${HOME}/.meshd/bin/meshd"
FAKE

fails=0
check() { # check <name> <expected-rc> <actual-rc>
  if [ "$2" -eq "$3" ]; then
    printf 'ok   - %s\n' "$1"
  else
    printf 'FAIL - %s (want rc=%s, got rc=%s)\n' "$1" "$2" "$3"
    fails=$((fails + 1))
  fi
}

run() { # run with a clean env; echoes nothing, returns the smoke script's rc
  MESHD_INSTALL_REQUESTED_VERSION="0.17.0" \
  MESHD_INSTALL_EXPECTED_VERSION="v0.17.0" \
  "$@" bash "$SMOKE" >/dev/null 2>&1
}

# Capture each run's exit code without tripping `set -e` on the expected failure.
# 1. Primary reachable → installs from primary.
rc=0; run env MESHD_INSTALL_URL="file://${FAKE}" || rc=$?
check "primary reachable installs" 0 "$rc"

# 2. Primary unreachable but fallback works → installs from fallback.
rc=0; run env MESHD_INSTALL_URL="file://${WORK}/missing.sh" MESHD_INSTALL_FALLBACK_URL="file://${FAKE}" || rc=$?
check "falls back when primary fails" 0 "$rc"

# 3. Both sources unreachable → fails.
rc=0; run env MESHD_INSTALL_URL="file://${WORK}/a.sh" MESHD_INSTALL_FALLBACK_URL="file://${WORK}/b.sh" || rc=$?
check "fails when no source is reachable" 1 "$rc"

if [ "$fails" -ne 0 ]; then
  printf '%d test(s) failed\n' "$fails" >&2
  exit 1
fi
printf 'all install-smoke fetch tests passed\n'
