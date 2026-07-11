#!/usr/bin/env bash
#
# Offline test for install.sh's `up` passthrough: everything after `up` must
# reach the installed binary as `meshd up <args...>`, exit codes must
# propagate, and the plain no-arg install must keep its contract. Runs against
# a fake release archive served over file:// — no network, safe on every PR.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL="${HERE}/../../install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

# install.sh's downloader prefers curl, and only curl handles the file://
# mirror this test serves (wget does not support file:// URLs).
command -v curl >/dev/null 2>&1 || { echo 'install-up test requires curl' >&2; exit 1; }

VERSION_TAG="9.9.9"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64|amd64) arch='x64' ;;
  aarch64|arm64) arch='arm64' ;;
  *) echo "unsupported test arch" >&2; exit 1 ;;
esac

# Fake release: a meshd stand-in that records its argv and exits with
# MESHD_FAKE_EXIT (default 0).
DIST="${WORK}/dist/v${VERSION_TAG}"
mkdir -p "$DIST"
cat > "${WORK}/meshd" <<'FAKE'
#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then
  echo "meshd 9.9.9"
  exit 0
fi
printf '%s\n' "$@" > "${MESHD_FAKE_ARGV_OUT:?}"
exit "${MESHD_FAKE_EXIT:-0}"
FAKE
chmod +x "${WORK}/meshd"
tar -czf "${DIST}/meshd-${os}-${arch}.tar.gz" -C "$WORK" meshd

fails=0
check() { # check <name> <condition-rc>
  if [ "$2" -eq 0 ]; then
    printf 'ok   - %s\n' "$1"
  else
    printf 'FAIL - %s\n' "$1"
    fails=$((fails + 1))
  fi
}

run_install() { # run_install <home> [args...]
  local home="$1"
  shift
  HOME="$home" \
  VERSION="$VERSION_TAG" \
  MESHD_INSTALL_DOWNLOAD_BASE="file://${WORK}/dist" \
  MESHD_FAKE_ARGV_OUT="${home}/argv.txt" \
    bash "$INSTALL" --no-modify-path "$@" </dev/null
}

# 1. Plain install: no run, final hint points at meshd up.
home1="${WORK}/home1"; mkdir -p "$home1"
out1="$(run_install "$home1")"
rc=0
[ -x "${home1}/.meshd/bin/meshd" ] || rc=1
check "plain install drops the binary" "$rc"
rc=0
grep -q 'Run: meshd up' <<<"$out1" || rc=1
check "plain install hints 'meshd up'" "$rc"
rc=0
[ ! -e "${home1}/argv.txt" ] || rc=1
check "plain install does not run meshd up" "$rc"

# 2. `up` passthrough: args after `up` reach the binary verbatim (including
# ones that look like installer flags), via the absolute binary path.
home2="${WORK}/home2"; mkdir -p "$home2"
run_install "$home2" up 'meshd://invite/test-token' --no-tun --wait-timeout 1h >/dev/null
rc=0
expected="$(printf 'up\nmeshd://invite/test-token\n--no-tun\n--wait-timeout\n1h\n')"
[ "$(cat "${home2}/argv.txt")" = "$expected" ] || rc=1
check "up passthrough forwards args verbatim" "$rc"

# 3. Exit codes from meshd up propagate, with a resume hint that never repeats
# the bearer invite into terminal or CI logs.
home3="${WORK}/home3"; mkdir -p "$home3"
rc=0
stderr3="${WORK}/stderr3.txt"
MESHD_FAKE_EXIT=7 run_install "$home3" up 'meshd://invite/x' --profile work >/dev/null 2>"$stderr3" || rc=$?
check "meshd up exit code propagates" "$([ "$rc" -eq 7 ]; echo $?)"
rc=0
grep -q "resume without repeating the invite" "$stderr3" || rc=1
grep -q -- "--profile work" "$stderr3" || rc=1
! grep -q "meshd://invite/x" "$stderr3" || rc=1
check "failure prints a redacted resume hint" "$rc"

# 4. Unknown options still fail hard (guards against silently swallowing
# typos like 'pu' or a bare invite URL).
home4="${WORK}/home4"; mkdir -p "$home4"
rc=0
run_install "$home4" 'meshd://invite/oops' >/dev/null 2>&1 || rc=$?
check "unknown option still fails" "$([ "$rc" -ne 0 ]; echo $?)"

# 5. Bare `up` with no further arguments still runs (resume-style invocation;
# also guards the set -u empty-"$@" expansion on old bash).
home5="${WORK}/home5"; mkdir -p "$home5"
run_install "$home5" up >/dev/null
rc=0
[ "$(cat "${home5}/argv.txt")" = "up" ] || rc=1
check "bare up runs with no extra args" "$rc"

if [ "$fails" -gt 0 ]; then
  echo "${fails} install-up test(s) failed" >&2
  exit 1
fi
echo "all install-up passthrough tests passed"
