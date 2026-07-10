# CLAUDE.md — Agent Instructions for meshd

## Workflow: Git Worktrees

All work MUST be done in fresh git worktrees. Never work directly on `main`.

### Starting work

1. Ensure an issue exists (or create one) for the work being done.
2. Create a fresh worktree from the latest `main`:
   ```sh
   git fetch origin
   git worktree add ../meshd-<short-name> -b <branch-name> origin/main
   ```
   Branch naming: `feat/<topic>`, `fix/<topic>`, or `chore/<topic>`.
3. Work inside the worktree directory for all changes.

### Before asking to move forward

Every PR must pass all of these before requesting review:

```sh
go build ./...                        # Zero build errors
go vet ./...                          # Zero vet warnings
go test ./... -count=1 -race          # All tests pass, no data races
```

All new or changed behavior must have corresponding tests. Do not skip tests.

### Submitting work

1. Commit with clear, conventional commit messages (`feat:`, `fix:`, `refactor:`, `chore:`, `test:`, `docs:`).
2. Push the branch and open a PR with `gh pr create`. The PR body must include:
   - A summary of what changed and why.
   - Confirmation that build, vet, and tests all pass.
3. Do NOT ask to move forward until the PR is open and all checks pass.

### After merge

1. Delete the worktree and the local branch:
   ```sh
   git worktree remove ../meshd-<short-name>
   git branch -d <branch-name>
   ```
2. New work starts in a new fresh worktree. Never reuse old worktrees.

## Project Context

- **Language**: Go 1.25+.
- **Module**: `github.com/enboxorg/meshd`.
- **Vendored deps**: `GOFLAGS=-mod=vendor`. Run `go mod vendor` after dependency changes.
- **Private dependency**: `github.com/enboxorg/meshnet` (WireGuard engine fork). Requires `GOPRIVATE=github.com/enboxorg/*`.
- **Structure**:
  - `cmd/meshd/` — main binary
  - `internal/control/` — DWN-based control client (replaces Tailscale coordination)
  - `internal/dwn/` — DWN protocol operations
  - `internal/mesh/` — mesh network orchestration
  - `internal/engine/` — WireGuard engine integration + DWN control client
  - `internal/state/` — local state management
  - `internal/did/` — DID operations
  - `pkg/` — public library packages (crypto, dids, jwk)
  - `protocols/` — DWN protocol definitions
  - `schemas/` — JSON schemas
- **CI**: GitHub Actions runs `go build`, `go vet`, `go test -race` on PRs. Integration tests run on push to main only (require `DWN_ENDPOINT` secret).

## Vendored meshnet fork (`github.com/enboxorg/meshnet`)

meshd vendors a Tailscale/meshnet fork for the WireGuard networking engine.
The vendor directory is NOT a scratch pad. Treat it as upstream code.

### Rules for vendor changes

1. **Never edit files in `vendor/` directly.** Changes to meshnet must be
   committed to `github.com/enboxorg/meshnet` first, then re-vendored:
   ```sh
   cd ~/src/enboxorg/meshnet
   # make changes, commit, push
   cd ~/src/enboxorg/dwn-mesh
   GOPRIVATE=github.com/enboxorg/* go get github.com/enboxorg/meshnet@<commit>
   go mod vendor
   ```

2. **Minimize meshnet modifications.** meshnet should remain a pure
   WireGuard networking engine. meshd has zero modifications to the vendor
   tree — the DWN control client (`DWNControl`) lives entirely in
   `internal/engine/dwncontrol.go`, implementing meshnet's exported
   `controlclient.Client` interface from outside the package.

3. **Prefer meshd-side solutions.** Before adding fields or callbacks to
   meshnet types, consider whether the same goal can be achieved entirely
   in meshd's code (e.g., using closures, interfaces, or wrapper types in
   `internal/engine/`). All the types needed to implement a control client
   (`Client`, `Observer`, `Options`, `Status`) are exported from meshnet.

### Long-term direction

As we learn what meshd actually needs from the Tailscale fork, the goal is
to progressively decouple:
- Keep meshnet as a pure networking engine (WireGuard, magicsock, DERP, netstack)
- Eventually, reduce meshnet to only the networking primitives we actually use
- The less we modify the fork, the easier it is to pull upstream fixes

## Rules

- No workarounds. Fix root causes.
- No hardcoded DIDs or gateway URLs in source code. Use env vars or config.
- No committing secrets (`.env`, credentials, private keys).
- Keep PRs focused. One concern per PR.
- Run `go mod tidy && go mod vendor` if dependencies change.
- Never edit `vendor/` directly. Push changes to the upstream repo first.

## Versioning

**Patch-only for now.** This module is pre-release (`0.x`) and makes **no
backwards-compatibility guarantees** until we cut a stable release. Every change
ships as a **patch** bump — never minor, never major.

- Breaking changes are acceptable and expected. Do **not** add compatibility
  shims, migration paths, or deprecation cycles to preserve old behavior; just
  change it. Callers are updated in lockstep.
- This is **hard-enforced** in `release-please-config.json` via
  `"versioning": "always-bump-patch"`, so every release is a patch bump no
  matter the commit types — a `feat:` commit will **not** produce a minor.
  Use whichever conventional-commit type best describes the change (`feat:`,
  `fix:`, `refactor:`, …) for a clean changelog; it no longer affects the
  version. The current version lives in `.release-please-manifest.json`.
