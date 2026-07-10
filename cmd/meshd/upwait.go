package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/dwn"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/internal/state"
	"github.com/enboxorg/meshd/protocols"
)

// meshd up waits for dashboard approval by default so that a single command
// (install + up <invite>) carries a fresh machine all the way into the mesh.
const (
	defaultApprovalWaitTimeout  = 15 * time.Minute
	sudoRefreshInterval         = time.Minute
	postApprovalRefreshAttempts = 4
	postApprovalRefreshDelay    = 10 * time.Second
)

// approvalPollPolicy controls the poll cadence: pending answers back off to
// max, transient check errors (DWN hiccups, rate limits) back off to errorMax.
type approvalPollPolicy struct {
	initial  time.Duration
	max      time.Duration
	errorMax time.Duration
}

var defaultApprovalPollPolicy = approvalPollPolicy{
	initial:  3 * time.Second,
	max:      15 * time.Second,
	errorMax: time.Minute,
}

var errApprovalWaitTimeout = errors.New("timed out waiting for approval")

// approvalWaitDeadline bounds the wait by the invite expiry when one is known:
// polling past the invite's own lifetime can never succeed.
func approvalWaitDeadline(now time.Time, timeout time.Duration, inviteExpiresAt string) time.Time {
	deadline := now.Add(timeout)
	if inviteExpiresAt == "" {
		return deadline
	}
	expiry, err := time.Parse(time.RFC3339, inviteExpiresAt)
	if err != nil {
		return deadline
	}
	if expiry.Before(deadline) {
		return expiry
	}
	return deadline
}

// waitForApproval polls check until it reports done, the deadline passes, or
// ctx is cancelled. check errors are treated as transient (DWN hiccups, rate
// limits) and retried with a longer backoff than the pending-state cadence.
func waitForApproval(ctx context.Context, deadline time.Time, out io.Writer, policy approvalPollPolicy, check func(context.Context) (bool, error)) error {
	delay := policy.initial
	var lastErr error
	for {
		done, err := check(ctx)
		if err == nil {
			if done {
				return nil
			}
			lastErr = nil
			delay = nextApprovalPollDelay(delay, policy.max)
		} else {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if lastErr == nil || lastErr.Error() != err.Error() {
				fmt.Fprintf(out, "  Approval check failed (will retry): %v\n", err)
			}
			lastErr = err
			delay = nextApprovalPollDelay(delay, policy.errorMax)
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr != nil {
				return fmt.Errorf("%w (last check error: %v)", errApprovalWaitTimeout, lastErr)
			}
			return errApprovalWaitTimeout
		}
		sleep := delay
		if sleep > remaining {
			sleep = remaining
		}
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func nextApprovalPollDelay(current, max time.Duration) time.Duration {
	next := current + current/2
	if next > max {
		return max
	}
	return next
}

// pendingJoinApproved reports whether the anchor has provisioned a node record
// for this identity. It is the read-only subset of the discovery performed by
// cmdNetworkJoin, cheap enough to run in a poll loop.
func pendingJoinApproved(ctx context.Context, ns *state.NetworkState, identity *did.DID) (bool, error) {
	signer := &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey}
	api := dwn.NewDwnAPI(dwn.NewSimpleAgent(ns.AnchorEndpoint, signer))
	nodeDID := ns.EffectiveNodeDID(identity.URI)
	ownerDID := ns.EffectiveOwnerDID(nodeDID)

	nodeRecords, status, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/node",
			ContextID:    ns.NetworkRecordID,
			Recipient:    nodeDID,
		},
		DateSort: "createdDescending",
	}, "")
	if err != nil {
		return false, err
	}
	if status.Code == 200 && len(nodeRecords) > 0 {
		return true, nil
	}

	memberRecords, memStatus, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
		Filter: dwn.RecordsFilter{
			Protocol:     protocols.MeshProtocolURI,
			ProtocolPath: "network/member",
			ContextID:    ns.NetworkRecordID,
			Recipient:    ownerDID,
		},
		DateSort: "createdDescending",
	}, "network/member")
	if err != nil {
		return false, err
	}
	if memStatus.Code != 200 {
		return false, nil
	}
	for _, memberRecord := range memberRecords {
		memberNodes, nodeStatus, err := api.Query(ctx, ns.AnchorDID, dwn.QueryParams{
			Filter: dwn.RecordsFilter{
				Protocol:     protocols.MeshProtocolURI,
				ProtocolPath: "network/member/node",
				ContextID:    ns.NetworkRecordID + "/" + memberRecord.ID,
				Recipient:    nodeDID,
			},
			DateSort: "createdDescending",
		}, "network/member")
		if err != nil {
			return false, err
		}
		if nodeStatus.Code == 200 && len(memberNodes) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// keepSudoFresh pre-validates sudo before the approval wait and keeps the
// timestamp fresh while waiting, so the post-approval TUN elevation runs
// without re-prompting after the user has walked away. The returned stop
// function ends the refresh loop.
func keepSudoFresh(ctx context.Context) (stop func(), err error) {
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return nil, fmt.Errorf("system routing requires administrator privileges, but sudo was not found; run meshd as root or use --no-tun")
	}
	fmt.Fprintln(os.Stderr, "meshd: system routing needs administrator privileges; validating sudo now so the mesh can start unattended once approved.")
	validate := exec.CommandContext(ctx, sudoPath, "-v")
	validate.Stdin = os.Stdin
	validate.Stdout = os.Stdout
	validate.Stderr = os.Stderr
	if err := validate.Run(); err != nil {
		return nil, fmt.Errorf("sudo authentication failed: %w", err)
	}
	// Systems with timestamp_timeout=0 never cache sudo credentials, so the
	// refresh loop cannot keep them fresh — warn instead of promising an
	// unattended start.
	if err := exec.Command(sudoPath, "-n", "-v").Run(); err != nil {
		fmt.Fprintln(os.Stderr, "meshd: sudo does not cache credentials on this system; it will prompt again once the approval arrives.")
	}

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(sudoRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = exec.Command(sudoPath, "-n", "-v").Run()
			}
		}
	}()
	return func() { close(done) }, nil
}

type approvalWaitKind int

const (
	approvalWaitJoin approvalWaitKind = iota
	approvalWaitOwner
)

// awaitMembershipApproval blocks until the pending join (invite) or owner
// request is approved, then returns the refreshed network state. It owns all
// user-facing progress output for the wait.
func awaitMembershipApproval(ctx context.Context, kind approvalWaitKind, f upFlags, stateDir string, ns *state.NetworkState, identity *did.DID, flagProfile string, shouldElevate bool) (*state.NetworkState, error) {
	timeout := f.waitTimeout
	if timeout <= 0 {
		timeout = defaultApprovalWaitTimeout
	}

	inviteExpiresAt := ""
	if f.inviteURL != "" {
		if payload, err := invite.Decode(f.inviteURL); err == nil {
			inviteExpiresAt = payload.ExpiresAt
		}
	}
	deadline := approvalWaitDeadline(time.Now(), timeout, inviteExpiresAt)

	waitCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if shouldElevate {
		stopSudo, err := keepSudoFresh(waitCtx)
		if err != nil {
			return nil, err
		}
		defer stopSudo()
	}

	ownerDID := ns.EffectiveOwnerDID(ns.AnchorDID)
	// The dashboard operates in the network owner's wallet context. For invite
	// joins that is the anchor DID — the local OwnerDID defaults to the
	// joiner's own DID and would produce a URL the owner's wallet rejects.
	adminCtx := adminContext{OwnerDID: ns.AnchorDID, NetworkRecordID: ns.NetworkRecordID}
	fmt.Printf("\nWaiting for approval (timeout %s)...\n", timeout)
	if kind == approvalWaitJoin {
		fmt.Printf("  Approve this device in the dashboard, or keep the anchor node online\n")
		fmt.Printf("  for automatic approval:\n")
	} else {
		fmt.Printf("  Approve this device in the dashboard:\n")
	}
	fmt.Printf("    %s\n", buildAdminURL(defaultAdminDashboardURL, adminCtx))
	fmt.Printf("  meshd continues automatically once approved. Ctrl+C to stop waiting;\n")
	fmt.Printf("  the request stays pending and 'meshd up' resumes it.\n\n")

	var check func(context.Context) (bool, error)
	switch kind {
	case approvalWaitOwner:
		nodeDID := ns.EffectiveNodeDID(identity.URI)
		check = func(ctx context.Context) (bool, error) {
			approval, _, err := mesh.FindOwnerNodeApproval(ctx, ns.AnchorEndpoint, ownerDID, nodeDID, dwnSigner(identity))
			if err != nil {
				return false, err
			}
			return approval != nil, nil
		}
	default:
		check = func(ctx context.Context) (bool, error) {
			return pendingJoinApproved(ctx, ns, identity)
		}
	}

	if err := waitForApproval(waitCtx, deadline, os.Stdout, defaultApprovalPollPolicy, check); err != nil {
		return nil, approvalWaitFailure(err, kind, inviteExpiresAt, deadline, adminCtx)
	}

	// Approval observed: run the existing refresh to persist the full
	// membership state. The refresh re-queries the DWN, so a transient error
	// or a propagation lag right after approval must not discard a successful
	// unattended wait — retry briefly before giving up.
	refresh := func() (*state.NetworkState, error) {
		if kind == approvalWaitOwner {
			refreshed, err := refreshPendingOwnerApproval(ctx, stateDir, ns, identity)
			if err == nil && (refreshed.NetworkRecordID == "" || refreshed.NodeRecordID == "") {
				return nil, fmt.Errorf("approval was detected but no node record was found")
			}
			return refreshed, err
		}
		refreshed, err := refreshPendingJoin(ctx, stateDir, ns, flagProfile, true)
		if err == nil && refreshed.NodeRecordID == "" {
			return nil, fmt.Errorf("approval was detected but no node record was found")
		}
		return refreshed, err
	}
	var refreshed *state.NetworkState
	var refreshErr error
	for attempt := 0; attempt < postApprovalRefreshAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(postApprovalRefreshDelay)
			select {
			case <-waitCtx.Done():
				timer.Stop()
				return nil, approvalWaitFailure(waitCtx.Err(), kind, inviteExpiresAt, deadline, adminCtx)
			case <-timer.C:
			}
			fmt.Printf("  Membership refresh failed (%v); retrying...\n", refreshErr)
		}
		refreshed, refreshErr = refresh()
		if refreshErr == nil {
			return refreshed, nil
		}
	}
	return nil, fmt.Errorf("%w; run 'meshd up' to retry", refreshErr)
}

// approvalWaitFailure turns a wait-loop error into an actionable message.
func approvalWaitFailure(err error, kind approvalWaitKind, inviteExpiresAt string, deadline time.Time, adminCtx adminContext) error {
	dashboardURL := buildAdminURL(defaultAdminDashboardURL, adminCtx)
	approveHint := fmt.Sprintf("approve it in the dashboard (%s)", dashboardURL)
	if kind == approvalWaitJoin {
		approveHint += " or keep the anchor node online"
	}
	if errors.Is(err, errApprovalWaitTimeout) {
		if inviteExpiresAt != "" {
			if expiry, parseErr := time.Parse(time.RFC3339, inviteExpiresAt); parseErr == nil && !time.Now().Before(expiry) {
				return fmt.Errorf("the invite expired at %s before it was approved; create a new invite in the dashboard (%s) and run 'meshd up <new-invite>'", inviteExpiresAt, dashboardURL)
			}
		}
		return fmt.Errorf("%v; the request is still pending — %s and run 'meshd up' to continue, or re-run with --wait-timeout for a longer wait", err, approveHint)
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("interrupted while waiting for approval; the request stays pending — run 'meshd up' to resume")
	}
	return err
}

// resubmitPendingInviteJoin handles `meshd up <invite>` on a machine whose
// earlier join request is still pending. The original invite may have expired
// or been revoked, so an invite with a different token is submitted as a
// fresh request; re-running with the same invite is a no-op. An invite for a
// different network fails fast instead of being silently ignored.
func resubmitPendingInviteJoin(ctx context.Context, inviteURL, stateDir string, ns *state.NetworkState, identity *did.DID, flagProfile string) (*state.NetworkState, error) {
	payload, err := invite.Decode(inviteURL)
	if err != nil {
		return nil, err
	}
	if payload.NetworkID != ns.NetworkRecordID || payload.AnchorDID != ns.AnchorDID {
		return nil, fmt.Errorf("this machine has a pending join request for network %q; run 'meshd network leave' before joining a different network", ns.NetworkName)
	}
	if payload.TokenID == "" && payload.Secret == "" {
		return ns, nil
	}
	if payload.TokenID != "" && payload.TokenID == ns.PendingJoinTokenID {
		return ns, nil
	}
	if err := payload.ValidatePreAuth(); err != nil {
		return nil, err
	}
	if payload.ExpiresAt != "" {
		if expiry, parseErr := time.Parse(time.RFC3339, payload.ExpiresAt); parseErr == nil && !time.Now().Before(expiry) {
			return nil, fmt.Errorf("the invite expired at %s; create a new invite in the dashboard and run 'meshd up <new-invite>'", payload.ExpiresAt)
		}
	}

	meta := resolveIdentityMetadata(flagProfile, identity.URI)
	nodeDID := firstNonEmpty(meta.NodeDID, identity.URI)
	label, _ := os.Hostname()
	if err := mesh.WritePreAuthNodeRequest(ctx, mesh.WritePreAuthNodeRequestParams{
		Invite:            payload,
		NodeDID:           nodeDID,
		MemberDID:         ns.EffectiveOwnerDID(nodeDID),
		DelegateDID:       meta.DelegateDID,
		RequestedBy:       identity.URI,
		Signer:            &dwn.Signer{DID: identity.URI, PrivateKey: identity.SigningKey},
		Label:             label,
		NodeEncryptionKey: identity.EncryptionPrivateKey,
	}); err != nil {
		return nil, err
	}
	fmt.Printf("Join request resubmitted for %q.\n", firstNonEmpty(payload.NetworkName, ns.NetworkName))

	ns.PendingJoinTokenID = payload.TokenID
	if err := state.SaveNetworkState(stateDir, ns); err != nil {
		return nil, fmt.Errorf("saving pending join token: %w", err)
	}
	return ns, nil
}
