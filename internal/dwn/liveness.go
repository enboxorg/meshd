package dwn

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// Application-level WebSocket liveness defaults, mirroring the TypeScript
// client (json-rpc-socket.ts). NAT timeouts, network switches, and system
// sleep kill connections silently — TCP never learns, and a blocked read
// waits forever — so liveness rides on JSON-RPC rpc.ping/pong frames.
const (
	// defaultHeartbeatInterval is the cadence of periodic rpc.ping frames.
	defaultHeartbeatInterval = 30 * time.Second

	// defaultHeartbeatTimeout is how long a heartbeat ping waits for its
	// pong before the connection is declared dead and force-closed.
	defaultHeartbeatTimeout = 10 * time.Second

	// defaultHealthProbeTimeout is the pong deadline of an on-demand
	// CheckHealth probe.
	defaultHealthProbeTimeout = 5 * time.Second
)

// Ping id prefixes. The id doubles as the liveness generation, so heartbeat
// and probe pings are namespaced away from request and subscription UUIDs.
const (
	livenessHeartbeatIDPrefix = "hb-"
	livenessProbeIDPrefix     = "hb-probe-"
)

// heartbeatIntervalOrDefault maps a configured heartbeat interval onto the
// effective one: zero selects the default and negative disables (returns 0).
func heartbeatIntervalOrDefault(interval time.Duration) time.Duration {
	if interval == 0 {
		return defaultHeartbeatInterval
	}
	if interval < 0 {
		return 0
	}
	return interval
}

// livenessConn is the slice of *websocket.Conn the liveness layer needs.
// Narrowed to an interface so the generation discipline is unit-testable
// without a server. Write is safe for concurrent use — coder/websocket
// serializes whole-message writes internally, which is the same discipline
// the subscription goroutine's acks rely on.
type livenessConn interface {
	Write(ctx context.Context, typ websocket.MessageType, p []byte) error
	CloseNow() error
}

// livenessProbe is one in-flight CheckHealth probe. Concurrent probes
// coalesce onto it; healthy is valid once done is closed.
type livenessProbe struct {
	done    chan struct{}
	healthy bool
}

// connLiveness owns the rpc.ping liveness discipline for one WebSocket
// connection: the periodic heartbeat and on-demand health probes. State is
// strictly per-connection — every (re)connect starts a fresh instance, so a
// stale deadline or probe can never outlive its transport.
type connLiveness struct {
	conn             livenessConn
	logger           *slog.Logger
	heartbeatTimeout time.Duration

	mu           sync.Mutex
	closed       bool
	activePingID string         // outstanding heartbeat ping — the active generation
	deadline     *time.Timer    // pong deadline armed for activePingID
	probeID      string         // outstanding health probe ping id
	pending      *livenessProbe // in-flight probe shared by concurrent callers
}

func newConnLiveness(conn livenessConn, logger *slog.Logger, heartbeatTimeout time.Duration) *connLiveness {
	if logger == nil {
		logger = slog.Default()
	}
	if heartbeatTimeout <= 0 {
		heartbeatTimeout = defaultHeartbeatTimeout
	}
	return &connLiveness{
		conn:             conn,
		logger:           logger,
		heartbeatTimeout: heartbeatTimeout,
	}
}

func (l *connLiveness) writePing(ctx context.Context, pingID string) error {
	data, err := json.Marshal(newJsonRpcPing(pingID))
	if err != nil {
		return err
	}
	return l.conn.Write(ctx, websocket.MessageText, data)
}

// heartbeatLoop sends rpc.ping every interval until ctx ends. Run as a
// goroutine per connection.
func (l *connLiveness) heartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.heartbeatTick(ctx)
		}
	}
}

// heartbeatTick sends one heartbeat ping unless the previous one is still
// awaiting its pong. The ping id is the heartbeat generation: only the pong
// carrying the ACTIVE id may clear the armed deadline.
func (l *connLiveness) heartbeatTick(ctx context.Context) {
	l.mu.Lock()
	if l.closed || l.activePingID != "" {
		l.mu.Unlock()
		return
	}
	pingID := livenessHeartbeatIDPrefix + uuid.New().String()
	l.activePingID = pingID
	// Arm the deadline before writing, mirroring probe: a write stalled on a
	// dead-but-unclosed socket would otherwise wedge this goroutine with no
	// deadline armed — the silent-death class the heartbeat exists to catch.
	// On expiry the connection is force-closed, which also unblocks the write.
	l.deadline = time.AfterFunc(l.heartbeatTimeout, func() {
		l.heartbeatDeadlineExpired(pingID)
	})
	l.mu.Unlock()

	if err := l.writePing(ctx, pingID); err != nil {
		// The socket is closing or dead; the read loop owns that failure.
		l.mu.Lock()
		if l.activePingID == pingID {
			l.clearHeartbeatDeadlineLocked()
		}
		l.mu.Unlock()
	}
}

// heartbeatDeadlineExpired force-closes the connection when the ACTIVE
// heartbeat ping missed its pong. The subscription run loop's read-error
// path then backs off and resubscribes with the last cursor. A deadline for
// a superseded generation is a no-op.
func (l *connLiveness) heartbeatDeadlineExpired(pingID string) {
	l.mu.Lock()
	if l.closed || l.activePingID != pingID {
		l.mu.Unlock()
		return
	}
	l.activePingID = ""
	l.deadline = nil
	l.mu.Unlock()

	l.logger.Warn("subscription heartbeat pong missed; closing dead connection",
		slog.Duration("timeout", l.heartbeatTimeout),
	)
	l.conn.CloseNow()
}

// consumePong consumes a JSON-RPC response frame when its id matches the
// ACTIVE heartbeat ping or the in-flight health probe, reporting whether the
// frame was taken. Generation discipline: a late pong for a superseded ping
// id matches nothing, so it mutates no newer heartbeat state.
func (l *connLiveness) consumePong(id string, rpcErr *JsonRpcError) bool {
	if id == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch id {
	case l.activePingID:
		// Mirrors the TS pong handler: any response carrying the active ping
		// id clears the deadline, error payloads included, so a server
		// without an rpc.ping handler degrades to an inert heartbeat instead
		// of a reconnect loop.
		l.clearHeartbeatDeadlineLocked()
		return true
	case l.probeID:
		healthy := rpcErr == nil
		l.resolveProbeLocked(healthy)
		if healthy {
			// A probe-verified connection also defuses any pending heartbeat
			// deadline: armed before a system sleep, it would fire on resume
			// and kill the connection the probe just proved alive. Clearing
			// drops the superseded ping id with it, so its late pong is
			// ignored rather than credited to a newer generation.
			l.clearHeartbeatDeadlineLocked()
		}
		return true
	}
	return false
}

// probe sends one out-of-band rpc.ping and reports whether its pong arrived
// within timeout. Concurrent probes coalesce onto a single in-flight ping
// and share its verdict. A missed pong force-closes the connection so the
// run loop's reconnect path takes over.
func (l *connLiveness) probe(ctx context.Context, timeout time.Duration) bool {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return false
	}
	pending := l.pending
	if pending == nil {
		pending = &livenessProbe{done: make(chan struct{})}
		probeID := livenessProbeIDPrefix + uuid.New().String()
		l.pending = pending
		l.probeID = probeID
		l.mu.Unlock()

		// Arm the deadline before writing: it resolves the probe and closes
		// the connection on expiry, so even a stalled write cannot wedge the
		// waiters below.
		time.AfterFunc(timeout, func() {
			l.failProbe(probeID, "health probe pong missed")
		})
		if err := l.writePing(ctx, probeID); err != nil {
			l.failProbe(probeID, "health probe send failed")
		}
	} else {
		l.mu.Unlock()
	}

	select {
	case <-pending.done:
		return pending.healthy
	case <-ctx.Done():
		return false
	}
}

// failProbe resolves the identified probe as unhealthy and force-closes the
// connection. A probe that already resolved (pong, teardown, or an earlier
// failure) is left alone.
func (l *connLiveness) failProbe(probeID, reason string) {
	l.mu.Lock()
	if l.probeID != probeID {
		l.mu.Unlock()
		return
	}
	l.resolveProbeLocked(false)
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return
	}
	l.logger.Warn("subscription " + reason + "; closing dead connection")
	l.conn.CloseNow()
}

func (l *connLiveness) resolveProbeLocked(healthy bool) {
	if l.pending == nil {
		return
	}
	l.pending.healthy = healthy
	close(l.pending.done)
	l.pending = nil
	l.probeID = ""
}

func (l *connLiveness) clearHeartbeatDeadlineLocked() {
	if l.deadline != nil {
		l.deadline.Stop()
		l.deadline = nil
	}
	l.activePingID = ""
}

// shutdown ends liveness for a torn-down connection: the heartbeat deadline
// is disarmed and an in-flight probe resolves unhealthy — its pong can never
// arrive on a connection that no longer exists.
func (l *connLiveness) shutdown() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.clearHeartbeatDeadlineLocked()
	l.resolveProbeLocked(false)
}
