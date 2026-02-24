# meshnet

Private Go repository: `github.com/enboxorg/meshnet`

## What This Is

meshnet is the WireGuard mesh networking engine for dwn-mesh. It is a fork of [dexnet](https://github.com/WebP2P/dexnet) (itself a Tailscale BSD-3 fork) with import paths rewritten to `github.com/enboxorg/meshnet`.

The key change dwn-mesh makes: replacing Tailscale's centralized coordination server with DWN-based coordination via `internal/control` in the `dwn-mesh` repo.

## Private Go Module

This is a **private** Go repository. Consumers must configure Go to authenticate when fetching this module.

### Setup for development

```bash
# 1. Configure GOPRIVATE so Go doesn't try the public proxy
export GOPRIVATE=github.com/enboxorg/*

# 2. Configure git to use SSH for GitHub (if not already)
git config --global url."git@github.com:".insteadOf "https://github.com/"

# 3. Or use a GitHub token for HTTPS
export GONOSUMCHECK=github.com/enboxorg/*
git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
```

### Setup for CI (GitHub Actions)

```yaml
env:
  GOPRIVATE: github.com/enboxorg/*
  GONOSUMCHECK: github.com/enboxorg/*

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-go@v5
    with:
      go-version: '1.24'
  - name: Configure private modules
    run: git config --global url."https://x-access-token:${{ secrets.GH_TOKEN }}@github.com/".insteadOf "https://github.com/"
```

The `GH_TOKEN` secret needs `repo` scope to read private repos in the `enboxorg` org.

### go.mod dependency

```
require github.com/enboxorg/meshnet v0.0.0-<timestamp>-<commit>
```

Or use a replace directive for local development:

```
replace github.com/enboxorg/meshnet => ../meshnet
```

## Lineage

```
Tailscale v1.95.0 (BSD-3-Clause)
  └── WebP2P/dexnet (3 commits: import rename, IPv4/IPv6 rebase, macOS split DNS)
       └── enboxorg/meshnet (import rename to enboxorg/meshnet, DWN control integration)
```

## IP Space

- IPv4: `10.200.0.0/16` (Tailscale uses `100.64.0.0/10`)
- IPv6: `fd0d:e100:d3c5::/48` (Tailscale uses `fd7a:115c:a1e0::/48`)
- Service IP: `10.200.0.1` / `fd0d:e100:d3c5:de1::1`

## Key Integration Point

The coordination gap is in `control/controlclient/`. Tailscale's client talks to `controlplane.tailscale.com`. dwn-mesh replaces this with a DWN-based control client that:

1. Reads mesh state from DWN records (network config, members, endpoints, ACL)
2. Builds `tailcfg.MapResponse` from that state
3. Feeds it to the networking engine

The DWN control client lives in `dwn-mesh/internal/control/`, not in this repo. This repo provides the networking engine that consumes `MapResponse`.

## Go Practices

- Go 1.25+ (matches upstream dexnet)
- Module path: `github.com/enboxorg/meshnet`
- Upstream tracking: `git remote upstream` points to `WebP2P/dexnet`
- To pull upstream changes: `git fetch upstream && git merge upstream/master`

## License

BSD-3-Clause (inherited from Tailscale)
