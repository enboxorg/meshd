package didcore

import (
	"testing"
)

func TestResolutionResultWithError(t *testing.T) {
	result := ResolutionResultWithError("notFound")

	if result.ResolutionMetadata.Error != "notFound" {
		t.Errorf("error = %q, want %q", result.ResolutionMetadata.Error, "notFound")
	}
	if result.Document.ID != "" {
		t.Errorf("document ID should be empty, got %q", result.Document.ID)
	}
}

func TestResolutionResultWithDocument(t *testing.T) {
	doc := Document{
		ID: "did:example:123",
	}
	result := ResolutionResultWithDocument(doc)

	if result.Document.ID != "did:example:123" {
		t.Errorf("document ID = %q, want %q", result.Document.ID, "did:example:123")
	}
	if result.ResolutionMetadata.Error != "" {
		t.Errorf("error should be empty, got %q", result.ResolutionMetadata.Error)
	}
}

func TestResolutionResult_GetError(t *testing.T) {
	t.Run("with error", func(t *testing.T) {
		result := ResolutionResultWithError("invalidDid")
		if got := result.GetError(); got != "invalidDid" {
			t.Errorf("GetError() = %q, want %q", got, "invalidDid")
		}
	})

	t.Run("without error", func(t *testing.T) {
		result := ResolutionResultWithDocument(Document{ID: "did:example:123"})
		if got := result.GetError(); got != "" {
			t.Errorf("GetError() = %q, want empty", got)
		}
	})
}

func TestResolutionError(t *testing.T) {
	err := ResolutionError{Code: "methodNotSupported"}
	if err.Error() != "methodNotSupported" {
		t.Errorf("Error() = %q, want %q", err.Error(), "methodNotSupported")
	}

	// Verify it implements error interface
	var _ error = err
}
