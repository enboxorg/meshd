//go:build windows

package clipboard

import (
	"context"
	"errors"
	"testing"
)

func TestOpenClipboardReturnsCanceledContextBeforeCallingWin32(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := openClipboard(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("openClipboard error = %v, want context.Canceled", err)
	}
}
