package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enboxorg/meshnet/control/controlclient"
	"github.com/enboxorg/meshnet/types/netmap"
)

type feedGatingHarness struct {
	cc             *DWNControl
	feedSync       *feedSyncRecorder
	loads          *atomic.Int32
	fingerprint    *atomic.Pointer[string]
	fingerprintErr *atomic.Pointer[error]
}

func newFeedGatingHarness(t *testing.T) *feedGatingHarness {
	t.Helper()
	loads := &atomic.Int32{}
	fingerprint := &atomic.Pointer[string]{}
	initial := "aa11"
	fingerprint.Store(&initial)
	fingerprintErr := &atomic.Pointer[error]{}
	feedSync := newFeedSyncRecorder(testFeedLinkKey, nil, nil)

	cc, err := NewDWNControl(
		&DWNControlConfig{
			MapResponseFunc: func(ctx context.Context) (*netmap.NetworkMap, error) {
				loads.Add(1)
				return &netmap.NetworkMap{}, nil
			},
			Streams: []RefreshStream{RefreshStreamFeed},
			FeedFingerprintFunc: func(ctx context.Context) (string, error) {
				if errPtr := fingerprintErr.Load(); errPtr != nil {
					return "", *errPtr
				}
				return *fingerprint.Load(), nil
			},
			FeedSync:     feedSync,
			PollInterval: time.Hour,
		},
		controlclient.Options{SkipStartForTests: true},
	)
	if err != nil {
		t.Fatalf("NewDWNControl: %v", err)
	}
	t.Cleanup(cc.Shutdown)
	return &feedGatingHarness{
		cc:             cc,
		feedSync:       feedSync,
		loads:          loads,
		fingerprint:    fingerprint,
		fingerprintErr: fingerprintErr,
	}
}

func (h *feedGatingHarness) refresh(t *testing.T, reasons ...RefreshReason) {
	t.Helper()
	if err := h.cc.refreshControlState(context.Background(), RefreshBatch{Reasons: reasons}); err != nil {
		t.Fatalf("refreshControlState(%v): %v", reasons, err)
	}
}

func (h *feedGatingHarness) setFingerprint(fp string) {
	h.fingerprint.Store(&fp)
}

func TestDWNControlFeedFingerprintGatesPeriodicRefreshes(t *testing.T) {
	h := newFeedGatingHarness(t)

	// Startup always performs a full load and records the fingerprint
	// fetched immediately before it.
	h.refresh(t, RefreshReasonStartup)
	if got := h.loads.Load(); got != 1 {
		t.Fatalf("loads after startup = %d, want 1", got)
	}
	if got := h.feedSync.storedFingerprint(); got != "aa11" {
		t.Fatalf("stored fingerprint = %q, want aa11", got)
	}

	// Periodic-only refresh with an unchanged fingerprint skips the load.
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 1 {
		t.Fatalf("loads after stable periodic = %d, want 1 (skipped)", got)
	}

	// A changed fingerprint forces the full load and re-records it.
	h.setFingerprint("bb22")
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 2 {
		t.Fatalf("loads after changed fingerprint = %d, want 2", got)
	}
	if got := h.feedSync.storedFingerprint(); got != "bb22" {
		t.Fatalf("stored fingerprint = %q, want bb22", got)
	}
}

func TestDWNControlFeedNonPeriodicReasonsAlwaysLoad(t *testing.T) {
	h := newFeedGatingHarness(t)
	h.refresh(t, RefreshReasonStartup)

	// Event-driven, manual, endpoint, and mixed batches never skip, even
	// with a stable fingerprint.
	for i, reasons := range [][]RefreshReason{
		{RefreshReasonFeed},
		{RefreshReasonManual},
		{RefreshReasonEndpoint},
		{RefreshReasonFeed, RefreshReasonPeriodic},
	} {
		h.refresh(t, reasons...)
		if got := h.loads.Load(); got != int32(i+2) {
			t.Fatalf("loads after %v = %d, want %d", reasons, got, i+2)
		}
	}
}

func TestDWNControlFeedForcesFullLoadAfterInterval(t *testing.T) {
	h := newFeedGatingHarness(t)
	h.refresh(t, RefreshReasonStartup)

	// Stable fingerprint within the interval: skipped.
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 1 {
		t.Fatalf("loads = %d, want 1", got)
	}

	// Belt and braces: past the forced-rebuild interval a stable
	// fingerprint no longer skips.
	h.cc.lastFullRefreshAt = time.Now().Add(-h.cc.config.FeedFullRefreshInterval - time.Minute)
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 2 {
		t.Fatalf("loads after forced interval = %d, want 2", got)
	}

	// The forced load refreshes the timestamp, re-arming the skip.
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 2 {
		t.Fatalf("loads after re-armed skip = %d, want 2", got)
	}
}

func TestDWNControlFeedFingerprintProbeFailureDisablesSkip(t *testing.T) {
	h := newFeedGatingHarness(t)
	h.refresh(t, RefreshReasonStartup)

	// A failing probe cannot prove stability: the load proceeds and the
	// stored fingerprint is cleared (unknown).
	probeErr := errors.New("probe failed")
	h.fingerprintErr.Store(&probeErr)
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 2 {
		t.Fatalf("loads after probe failure = %d, want 2", got)
	}
	if got := h.feedSync.storedFingerprint(); got != "" {
		t.Fatalf("stored fingerprint = %q, want cleared", got)
	}

	// Probe recovers with the original fingerprint: the previous entry was
	// cleared, so one more full load re-establishes the baseline.
	h.fingerprintErr.Store(nil)
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 3 {
		t.Fatalf("loads after probe recovery = %d, want 3", got)
	}
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 3 {
		t.Fatalf("loads after restored baseline = %d, want 3 (skipped)", got)
	}
}

func TestDWNControlFeedEmptyServerFingerprintNeverSkips(t *testing.T) {
	h := newFeedGatingHarness(t)
	h.setFingerprint("")
	h.refresh(t, RefreshReasonStartup)
	h.refresh(t, RefreshReasonPeriodic)
	if got := h.loads.Load(); got != 2 {
		t.Fatalf("loads with empty fingerprints = %d, want 2 (no skipping)", got)
	}
}
