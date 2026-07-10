//go:build !darwin && !windows

package clipboard

import (
	"context"
	"fmt"
)

func writeText(context.Context, string) error {
	return fmt.Errorf("desktop clipboard is not supported on this platform")
}
