package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var testPollPolicy = approvalPollPolicy{
	initial:  time.Millisecond,
	max:      2 * time.Millisecond,
	errorMax: 2 * time.Millisecond,
}

func TestParseUpFlagsWait(t *testing.T) {
	f := parseUpFlags([]string{"--wait-timeout", "45m", "--no-wait"})
	if f.waitTimeout != 45*time.Minute {
		t.Fatalf("waitTimeout = %s, want 45m", f.waitTimeout)
	}
	if !f.noWait {
		t.Fatal("expected --no-wait to be parsed")
	}

	f = parseUpFlags(nil)
	if f.waitTimeout != 0 {
		t.Fatalf("default waitTimeout = %s, want 0 (resolved later)", f.waitTimeout)
	}
	if f.noWait {
		t.Fatal("noWait should default to false")
	}
}

func TestApprovalWaitDeadline(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	timeout := 15 * time.Minute

	// No invite expiry: deadline is now+timeout.
	if got := approvalWaitDeadline(now, timeout, ""); !got.Equal(now.Add(timeout)) {
		t.Fatalf("deadline = %s, want %s", got, now.Add(timeout))
	}

	// Invalid expiry is ignored.
	if got := approvalWaitDeadline(now, timeout, "not-a-time"); !got.Equal(now.Add(timeout)) {
		t.Fatalf("deadline = %s, want %s", got, now.Add(timeout))
	}

	// Expiry after the timeout: timeout wins.
	late := now.Add(time.Hour).Format(time.RFC3339)
	if got := approvalWaitDeadline(now, timeout, late); !got.Equal(now.Add(timeout)) {
		t.Fatalf("deadline = %s, want %s", got, now.Add(timeout))
	}

	// Expiry before the timeout: expiry caps the wait.
	early := now.Add(5 * time.Minute).Format(time.RFC3339)
	if got := approvalWaitDeadline(now, timeout, early); !got.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("deadline = %s, want %s", got, now.Add(5*time.Minute))
	}
}

func TestNextApprovalPollDelay(t *testing.T) {
	if got := nextApprovalPollDelay(4*time.Second, 15*time.Second); got != 6*time.Second {
		t.Fatalf("delay = %s, want 6s", got)
	}
	if got := nextApprovalPollDelay(14*time.Second, 15*time.Second); got != 15*time.Second {
		t.Fatalf("delay = %s, want capped 15s", got)
	}
	if got := nextApprovalPollDelay(15*time.Second, 15*time.Second); got != 15*time.Second {
		t.Fatalf("delay = %s, want to stay at cap", got)
	}
}

func TestWaitForApprovalSucceedsAfterRetries(t *testing.T) {
	attempts := 0
	check := func(context.Context) (bool, error) {
		attempts++
		return attempts >= 3, nil
	}
	err := waitForApproval(context.Background(), time.Now().Add(time.Second), &strings.Builder{}, testPollPolicy, check)
	if err != nil {
		t.Fatalf("waitForApproval: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestWaitForApprovalTimesOut(t *testing.T) {
	check := func(context.Context) (bool, error) { return false, nil }
	err := waitForApproval(context.Background(), time.Now().Add(10*time.Millisecond), &strings.Builder{}, testPollPolicy, check)
	if !errors.Is(err, errApprovalWaitTimeout) {
		t.Fatalf("err = %v, want errApprovalWaitTimeout", err)
	}
}

func TestWaitForApprovalTimeoutKeepsLastError(t *testing.T) {
	check := func(context.Context) (bool, error) { return false, fmt.Errorf("dwn unreachable") }
	var out strings.Builder
	err := waitForApproval(context.Background(), time.Now().Add(10*time.Millisecond), &out, testPollPolicy, check)
	if !errors.Is(err, errApprovalWaitTimeout) {
		t.Fatalf("err = %v, want errApprovalWaitTimeout", err)
	}
	if !strings.Contains(err.Error(), "dwn unreachable") {
		t.Fatalf("timeout error should carry the last check error, got %v", err)
	}
	if !strings.Contains(out.String(), "dwn unreachable") {
		t.Fatalf("check failures should be reported to the user, got %q", out.String())
	}
}

func TestWaitForApprovalRecoversFromTransientErrors(t *testing.T) {
	attempts := 0
	check := func(context.Context) (bool, error) {
		attempts++
		if attempts < 3 {
			return false, fmt.Errorf("transient %d", attempts)
		}
		return true, nil
	}
	var out strings.Builder
	err := waitForApproval(context.Background(), time.Now().Add(time.Second), &out, testPollPolicy, check)
	if err != nil {
		t.Fatalf("waitForApproval: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestWaitForApprovalHonorsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	check := func(context.Context) (bool, error) {
		cancel()
		return false, nil
	}
	err := waitForApproval(ctx, time.Now().Add(time.Minute), &strings.Builder{}, testPollPolicy, check)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestApprovalWaitFailureMessages(t *testing.T) {
	adminCtx := adminContext{OwnerDID: "did:example:owner", NetworkRecordID: "net-1"}
	deadline := time.Now()

	// Timeout with an already-expired invite points at creating a new invite.
	expired := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	err := approvalWaitFailure(errApprovalWaitTimeout, approvalWaitJoin, expired, deadline, adminCtx)
	if err == nil || !strings.Contains(err.Error(), "invite expired") {
		t.Fatalf("expected invite-expired guidance, got %v", err)
	}

	// Plain timeout keeps the request pending and offers resume paths. The
	// invite path also mentions anchor-side automatic approval (local-vault
	// networks have no dashboard owner).
	err = approvalWaitFailure(errApprovalWaitTimeout, approvalWaitJoin, "", deadline, adminCtx)
	if err == nil || !strings.Contains(err.Error(), "still pending") || !strings.Contains(err.Error(), "--wait-timeout") {
		t.Fatalf("expected pending/resume guidance, got %v", err)
	}
	if !strings.Contains(err.Error(), "did%3Aexample%3Aowner") && !strings.Contains(err.Error(), "did:example:owner") {
		t.Fatalf("expected dashboard URL with owner DID, got %v", err)
	}
	if !strings.Contains(err.Error(), "keep the anchor node online") {
		t.Fatalf("invite-path timeout should mention the anchor-online path, got %v", err)
	}
	err = approvalWaitFailure(errApprovalWaitTimeout, approvalWaitOwner, "", deadline, adminCtx)
	if err == nil || strings.Contains(err.Error(), "keep the anchor node online") {
		t.Fatalf("owner-path timeout should be dashboard-only, got %v", err)
	}

	// Interrupt explains that re-running resumes.
	err = approvalWaitFailure(context.Canceled, approvalWaitOwner, "", deadline, adminCtx)
	if err == nil || !strings.Contains(err.Error(), "resume") {
		t.Fatalf("expected resume guidance on interrupt, got %v", err)
	}

	// Other errors pass through.
	sentinel := fmt.Errorf("boom")
	if err := approvalWaitFailure(sentinel, approvalWaitJoin, "", deadline, adminCtx); !errors.Is(err, sentinel) {
		t.Fatalf("unexpected wrapping of non-wait errors: %v", err)
	}
}

func TestSetupInteractiveRequiresTTY(t *testing.T) {
	// Under `go test` stdin is not a terminal, so the interactive wizard must
	// refuse cleanly instead of consuming piped input (curl | bash context).
	if stdinIsTerminal() {
		t.Skip("test requires a non-TTY stdin")
	}
	_, err := setupInteractive(context.Background(), upFlags{}, t.TempDir(), nil, "")
	if err == nil || !strings.Contains(err.Error(), "no interactive terminal") {
		t.Fatalf("expected non-TTY refusal, got %v", err)
	}
}
