// Package dashboard resolves the active meshd dashboard context and builds
// dashboard URLs that select the corresponding owner and network.
package dashboard

import (
	"net/url"
	"os"
	"strings"

	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
)

// DefaultURL is the public meshd administration dashboard.
const DefaultURL = "https://admin.meshd.sh"

// Context identifies the owner and network that the dashboard should select.
type Context struct {
	OwnerDID        string
	NetworkRecordID string
}

// WithOverrides returns fallback with any non-empty explicit values applied.
func WithOverrides(fallback Context, ownerDID, networkRecordID string) Context {
	ctx := fallback
	if ownerDID = strings.TrimSpace(ownerDID); ownerDID != "" {
		ctx.OwnerDID = ownerDID
	}
	if networkRecordID = strings.TrimSpace(networkRecordID); networkRecordID != "" {
		ctx.NetworkRecordID = networkRecordID
	}
	return ctx
}

// ResolveContext returns the dashboard context for the active profile.
//
// Resolution is intentionally best-effort: the dashboard remains useful when
// no profile or network exists, and callers can still open its unscoped URL.
// The profile config supplies the fallback owner while network.json, when
// present, supplies the authoritative network owner and record ID.
func ResolveContext(flagProfile string) Context {
	ctx := Context{}

	// A direct state-directory override intentionally bypasses profiles, just as
	// profile.ResolveDataPath does. Do not mix an unrelated configured owner into
	// state loaded from that directory.
	if os.Getenv("MESHD_STATE_DIR") == "" {
		if name, err := profile.Resolve(flagProfile); err == nil {
			if cfg, cfgErr := profile.ReadConfig(); cfgErr == nil && cfg.Profiles[name] != nil {
				ctx.OwnerDID = cfg.Profiles[name].EffectiveOwnerDID()
			}
		}
	}

	stateDir, err := profile.ResolveDataPath(flagProfile)
	if err != nil {
		return ctx
	}
	network, err := state.LoadNetworkState(stateDir)
	if err != nil || network == nil {
		return ctx
	}

	ctx.OwnerDID = network.EffectiveOwnerDID(ctx.OwnerDID)
	ctx.NetworkRecordID = network.NetworkRecordID
	return ctx
}

// BuildURL constructs a dashboard URL for ctx. Existing query parameters and
// fragments on a custom dashboard URL are preserved.
func BuildURL(dashboardURL string, ctx Context) string {
	base := strings.TrimRight(strings.TrimSpace(dashboardURL), "/")
	if base == "" {
		base = DefaultURL
	}

	parsed, err := url.Parse(base)
	if err != nil {
		return appendLegacyQuery(base, ctx)
	}
	values := parsed.Query()
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if ctx.OwnerDID != "" {
		values.Set("owner", ctx.OwnerDID)
	}
	if ctx.NetworkRecordID != "" {
		values.Set("network", ctx.NetworkRecordID)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func appendLegacyQuery(base string, ctx Context) string {
	values := url.Values{}
	if ctx.OwnerDID != "" {
		values.Set("owner", ctx.OwnerDID)
	}
	if ctx.NetworkRecordID != "" {
		values.Set("network", ctx.NetworkRecordID)
	}
	encoded := values.Encode()
	if encoded == "" {
		return base
	}
	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	return base + separator + encoded
}
