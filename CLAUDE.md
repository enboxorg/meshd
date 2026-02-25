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
  - `internal/engine/` — WireGuard engine integration
  - `internal/state/` — local state management
  - `internal/did/` — DID operations
  - `pkg/` — public library packages (crypto, dids, jwk)
  - `protocols/` — DWN protocol definitions
  - `schemas/` — JSON schemas
- **CI**: GitHub Actions runs `go build`, `go vet`, `go test -race` on PRs. Integration tests run on push to main only (require `DWN_ENDPOINT` secret).

## Rules

- No workarounds. Fix root causes.
- No hardcoded DIDs or gateway URLs in source code. Use env vars or config.
- No committing secrets (`.env`, credentials, private keys).
- Keep PRs focused. One concern per PR.
- Run `go mod tidy && go mod vendor` if dependencies change.
