// Package dwn - subscribe.go manages WebSocket subscriptions to DWN EventLog streams.
//
// The subscription manager maintains persistent WebSocket connections to:
//   - The anchor DWN (for member list changes, ACL updates, relay changes)
//   - Each peer's DWN (for endpoint updates)
//
// It handles:
//   - Automatic reconnection with exponential backoff
//   - Cursor-based catch-up (replays missed events from the EventLog)
//   - EOSE (End-of-Stored-Events) detection for initial sync completion
//   - Fan-out of events to registered handlers
package dwn
