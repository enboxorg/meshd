package clipboard

import (
	"context"
	"testing"
)

func TestWriteTextRejectsEmptyText(t *testing.T) {
	if err := WriteText(context.Background(), "  "); err == nil {
		t.Fatal("WriteText accepted empty text")
	}
}
