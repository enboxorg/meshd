package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/control"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshnet/types/netmap"
)

type recordingControlStateLoader struct {
	applyResponse       *control.MapResponse
	applyError          error
	postValidationError error
	loadResponse        *control.MapResponse
	loadError           error
	calls               []string
}

type recordingControlStateConverter struct {
	responses []*control.MapResponse
	maps      []*netmap.NetworkMap
	err       error
}

func (c *recordingControlStateConverter) Convert(response *control.MapResponse) (*netmap.NetworkMap, error) {
	c.responses = append(c.responses, response)
	if c.err != nil {
		return nil, c.err
	}
	result := &netmap.NetworkMap{}
	c.maps = append(c.maps, result)
	return result, nil
}

func (l *recordingControlStateLoader) ApplyPendingStateValidated(_ context.Context, validate control.PendingStateValidator) (*control.MapResponse, error) {
	l.calls = append(l.calls, "apply")
	if l.applyError != nil {
		return l.applyResponse, l.applyError
	}
	if validate != nil {
		if err := validate(l.applyResponse); err != nil {
			return l.applyResponse, err
		}
	}
	if l.postValidationError != nil {
		return l.applyResponse, l.postValidationError
	}
	return l.applyResponse, nil
}

func (l *recordingControlStateLoader) LoadStateValidated(_ context.Context, validate control.PendingStateValidator) (*control.MapResponse, error) {
	l.calls = append(l.calls, "load")
	if l.loadError != nil {
		return l.loadResponse, l.loadError
	}
	if validate != nil {
		if err := validate(l.loadResponse); err != nil {
			return l.loadResponse, err
		}
	}
	return l.loadResponse, nil
}

func TestRefreshMapResponseFuncUsesPendingStateForTopologyOnlyBatch(t *testing.T) {
	response := &control.MapResponse{}
	loader := &recordingControlStateLoader{
		applyResponse: response,
		loadError:     errors.New("full load must not run"),
	}
	resultCalls := 0
	fn := refreshMapResponseFunc(loader, NewConverter("mesh.test"), func(got *control.MapResponse, err error) {
		resultCalls++
		if got != response || err != nil {
			t.Fatalf("result = (%p, %v), want (%p, nil)", got, err, response)
		}
	})

	if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonTopology}}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !reflect.DeepEqual(loader.calls, []string{"apply"}) {
		t.Fatalf("loader calls = %v, want [apply]", loader.calls)
	}
	if resultCalls != 1 {
		t.Fatalf("result calls = %d, want 1", resultCalls)
	}
}

func TestRefreshMapResponseFuncUsesFullStateForNonTopologyBatches(t *testing.T) {
	tests := []struct {
		name    string
		reasons []RefreshReason
	}{
		{name: "empty"},
		{name: "startup", reasons: []RefreshReason{RefreshReasonStartup}},
		{name: "periodic", reasons: []RefreshReason{RefreshReasonPeriodic}},
		{name: "delivery", reasons: []RefreshReason{RefreshReasonDelivery}},
		{name: "manual", reasons: []RefreshReason{RefreshReasonManual}},
		{name: "endpoint", reasons: []RefreshReason{RefreshReasonEndpoint}},
		{name: "mixed", reasons: []RefreshReason{RefreshReasonTopology, RefreshReasonDelivery}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loader := &recordingControlStateLoader{
				applyError:   errors.New("pending state must not run"),
				loadResponse: &control.MapResponse{},
			}
			resultCalls := 0
			fn := refreshMapResponseFunc(loader, NewConverter("mesh.test"), func(got *control.MapResponse, err error) {
				resultCalls++
				if got != loader.loadResponse || err != nil {
					t.Fatalf("result = (%p, %v), want full response", got, err)
				}
			})
			if _, err := fn(context.Background(), RefreshBatch{Reasons: test.reasons}); err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if !reflect.DeepEqual(loader.calls, []string{"load"}) {
				t.Fatalf("loader calls = %v, want [load]", loader.calls)
			}
			if resultCalls != 1 {
				t.Fatalf("result calls = %d, want 1", resultCalls)
			}
		})
	}
}

func TestRefreshMapResponseFuncFullConverterFailurePublishesOnce(t *testing.T) {
	convertErr := errors.New("full candidate rejected")
	response := &control.MapResponse{}
	loader := &recordingControlStateLoader{loadResponse: response}
	converter := &recordingControlStateConverter{err: convertErr}
	resultCalls := 0
	fn := refreshMapResponseFunc(loader, converter, func(got *control.MapResponse, err error) {
		resultCalls++
		if got != response || !errors.Is(err, convertErr) {
			t.Fatalf("result = (%p, %v), want candidate and converter error", got, err)
		}
	})

	if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonStartup}}); !errors.Is(err, convertErr) {
		t.Fatalf("refresh error = %v", err)
	}
	if !reflect.DeepEqual(loader.calls, []string{"load"}) {
		t.Fatalf("loader calls = %v, want [load]", loader.calls)
	}
	if len(converter.responses) != 1 || converter.responses[0] != response || resultCalls != 1 {
		t.Fatalf("converter responses=%#v result calls=%d", converter.responses, resultCalls)
	}
}

func TestRefreshMapResponseFuncFallsBackOnceForFullReconciliationSentinel(t *testing.T) {
	fullResponse := &control.MapResponse{}
	loader := &recordingControlStateLoader{
		applyError:   fmt.Errorf("wrapped: %w", control.ErrFullReconciliationRequired),
		loadResponse: fullResponse,
	}
	converter := &recordingControlStateConverter{}
	resultCalls := 0
	fn := refreshMapResponseFunc(loader, converter, func(got *control.MapResponse, err error) {
		resultCalls++
		if got != fullResponse || err != nil {
			t.Fatalf("result = (%p, %v), want final full response", got, err)
		}
	})

	if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonTopology}}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !reflect.DeepEqual(loader.calls, []string{"apply", "load"}) {
		t.Fatalf("loader calls = %v, want [apply load]", loader.calls)
	}
	if resultCalls != 1 {
		t.Fatalf("result calls = %d, want one final publication", resultCalls)
	}
	if len(converter.responses) != 1 || converter.responses[0] != fullResponse {
		t.Fatalf("converted responses = %#v, want final response exactly once", converter.responses)
	}
}

func TestRefreshMapResponseFuncCommitFenceFailureDiscardsCandidate(t *testing.T) {
	candidate := &control.MapResponse{}
	fullResponse := &control.MapResponse{}
	loader := &recordingControlStateLoader{
		applyResponse:       candidate,
		postValidationError: control.ErrFullReconciliationRequired,
		loadResponse:        fullResponse,
	}
	converter := &recordingControlStateConverter{}
	resultCalls := 0
	fn := refreshMapResponseFunc(loader, converter, func(got *control.MapResponse, err error) {
		resultCalls++
		if got != fullResponse || err != nil {
			t.Fatalf("published result = (%p, %v), want final full response", got, err)
		}
	})

	got, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonTopology}})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !reflect.DeepEqual(loader.calls, []string{"apply", "load"}) {
		t.Fatalf("loader calls = %v, want [apply load]", loader.calls)
	}
	if len(converter.responses) != 2 || converter.responses[0] != candidate || converter.responses[1] != fullResponse {
		t.Fatalf("converted responses = %#v, want candidate then full", converter.responses)
	}
	if len(converter.maps) != 2 || got != converter.maps[1] || got == converter.maps[0] {
		t.Fatalf("returned map = %p, converted maps = %#v", got, converter.maps)
	}
	if resultCalls != 1 {
		t.Fatalf("result calls = %d, want only the full outcome", resultCalls)
	}
}

func TestRefreshMapResponseFuncConverterFailureDoesNotCommitOrLoadFull(t *testing.T) {
	convertErr := errors.New("converter rejected candidate")
	response := &control.MapResponse{}
	loader := &recordingControlStateLoader{applyResponse: response, loadError: errors.New("full load must not run")}
	converter := &recordingControlStateConverter{err: convertErr}
	resultCalls := 0
	fn := refreshMapResponseFunc(loader, converter, func(got *control.MapResponse, err error) {
		resultCalls++
		if got != response || !errors.Is(err, convertErr) {
			t.Fatalf("result = (%p, %v)", got, err)
		}
	})

	if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonTopology}}); !errors.Is(err, convertErr) {
		t.Fatalf("refresh error = %v", err)
	}
	if !reflect.DeepEqual(loader.calls, []string{"apply"}) {
		t.Fatalf("loader calls = %v, want [apply]", loader.calls)
	}
	if len(converter.responses) != 1 || resultCalls != 1 {
		t.Fatalf("converter calls=%d result calls=%d", len(converter.responses), resultCalls)
	}
}

func TestRefreshMapResponseFuncDefersFullLoadForStructuredRetryErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "rate limit", err: errors.Join(control.ErrFullReconciliationRequired, &dwn.RateLimitError{RetryAfter: time.Second}), want: dwn.ErrRateLimited},
		{name: "delta hydration HTTP 500", err: errors.Join(control.ErrFullReconciliationRequired, fmt.Errorf("hydrating record: %w", dwn.ErrTransport)), want: dwn.ErrTransport},
		{name: "canceled", err: errors.Join(control.ErrFullReconciliationRequired, context.Canceled), want: context.Canceled},
		{name: "deadline", err: errors.Join(control.ErrFullReconciliationRequired, context.DeadlineExceeded), want: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loader := &recordingControlStateLoader{applyError: test.err, loadError: errors.New("full load must not run")}
			resultCalls := 0
			fn := refreshMapResponseFunc(loader, &recordingControlStateConverter{}, func(got *control.MapResponse, err error) {
				resultCalls++
				if got != nil || !errors.Is(err, test.want) {
					t.Fatalf("result = (%p, %v)", got, err)
				}
			})
			if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonTopology}}); !errors.Is(err, test.want) {
				t.Fatalf("refresh error = %v", err)
			}
			if !reflect.DeepEqual(loader.calls, []string{"apply"}) || resultCalls != 1 {
				t.Fatalf("loader calls=%v result calls=%d", loader.calls, resultCalls)
			}
		})
	}
}

func TestRefreshMapResponseFuncFailurePreservesLastGoodSnapshot(t *testing.T) {
	refreshFailure := errors.New("incremental projector failed")
	loader := &recordingControlStateLoader{loadResponse: &control.MapResponse{}}
	store := &meshSnapshotStore{}
	fn := refreshMapResponseFunc(loader, NewConverter("mesh.test"), store.record)

	if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonStartup}}); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	before := store.load()
	if before == nil || before.Generation != 1 || before.LastError != "" {
		t.Fatalf("initial snapshot = %#v", before)
	}

	loader.applyError = refreshFailure
	if _, err := fn(context.Background(), RefreshBatch{Reasons: []RefreshReason{RefreshReasonTopology}}); !errors.Is(err, refreshFailure) {
		t.Fatalf("incremental refresh error = %v, want %v", err, refreshFailure)
	}
	after := store.load()
	if after.Generation != before.Generation || !after.RefreshedAt.Equal(before.RefreshedAt) {
		t.Fatalf("failure replaced last-good snapshot: before=%#v after=%#v", before, after)
	}
	if !strings.Contains(after.LastError, refreshFailure.Error()) {
		t.Fatalf("LastError = %q, want %q", after.LastError, refreshFailure)
	}
	if !reflect.DeepEqual(loader.calls, []string{"load", "apply"}) {
		t.Fatalf("loader calls = %v", loader.calls)
	}
}
