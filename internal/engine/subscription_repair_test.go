package engine

import (
	"testing"

	"github.com/enboxorg/meshd/internal/dwn"
)

func TestSubscriptionWatcherMarksTopologyRepairBeforeCoordinatorLifecycle(t *testing.T) {
	tests := []struct {
		name  string
		event dwn.SubscriptionLifecycleEvent
		want  []refreshCoordinatorCall
	}{
		{
			name: "fresh establishment",
			event: dwn.SubscriptionLifecycleEvent{
				Kind:             dwn.SubscriptionLifecycleEstablished,
				NeedsFullRefresh: true,
			},
			want: []refreshCoordinatorCall{{
				method: "live", stream: RefreshStreamTopology, live: true, needsFullRefresh: true,
			}},
		},
		{
			name: "progress gap",
			event: dwn.SubscriptionLifecycleEvent{
				Kind: dwn.SubscriptionLifecycleProgressGap,
				Gap:  &dwn.ProgressGapInfo{Reason: "compacted"},
			},
			want: []refreshCoordinatorCall{{
				method: "live", stream: RefreshStreamTopology, needsFullRefresh: true,
			}},
		},
		{
			name: "terminal",
			event: dwn.SubscriptionLifecycleEvent{
				Kind: dwn.SubscriptionLifecycleTerminal,
			},
			want: []refreshCoordinatorCall{
				{method: "live", stream: RefreshStreamTopology},
				{method: "notify", reason: RefreshReasonTopology},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := newRecordingRefreshCoordinator()
			repairCalls := 0
			w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
				TopologyRepairHandler: func() {
					if calls := coordinator.takeCalls(); len(calls) != 0 {
						t.Fatalf("coordinator called before topology repair: %#v", calls)
					}
					repairCalls++
				},
			})
			w.SetRefreshCoordinator(coordinator)

			w.handleSubscriptionLifecycle(RefreshStreamTopology, test.event)

			if repairCalls != 1 {
				t.Fatalf("repair calls = %d, want 1", repairCalls)
			}
			requireRefreshCoordinatorCalls(t, coordinator, test.want)
		})
	}
}

func TestSubscriptionWatcherDoesNotMarkRepairForHealthyOrDeliveryLifecycle(t *testing.T) {
	repairCalls := 0
	w := NewSubscriptionWatcher(SubscriptionWatcherConfig{
		TopologyRepairHandler: func() { repairCalls++ },
	})
	w.handleSubscriptionLifecycle(RefreshStreamTopology, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleEstablished,
	})
	w.handleSubscriptionLifecycle(RefreshStreamDelivery, dwn.SubscriptionLifecycleEvent{
		Kind:             dwn.SubscriptionLifecycleEstablished,
		NeedsFullRefresh: true,
	})
	w.handleSubscriptionLifecycle(RefreshStreamDelivery, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleProgressGap,
	})
	w.handleSubscriptionLifecycle(RefreshStreamDelivery, dwn.SubscriptionLifecycleEvent{
		Kind: dwn.SubscriptionLifecycleTerminal,
	})

	if repairCalls != 0 {
		t.Fatalf("repair calls = %d, want 0", repairCalls)
	}
}
