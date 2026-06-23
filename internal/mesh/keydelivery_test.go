package mesh

import (
	"testing"

	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
)

func TestContextKeyMatchesContext(t *testing.T) {
	keyForNetwork := &dwncrypto.DerivedPrivateJwk{
		DerivationScheme: dwncrypto.DerivationSchemeProtocolContext,
		DerivationPath:   dwncrypto.BuildProtocolContextDerivation("network-1"),
	}

	tests := []struct {
		name      string
		key       *dwncrypto.DerivedPrivateJwk
		contextID string
		want      bool
	}{
		{
			name:      "empty expected context accepts key",
			key:       keyForNetwork,
			contextID: "",
			want:      true,
		},
		{
			name:      "matching protocol context",
			key:       keyForNetwork,
			contextID: "network-1",
			want:      true,
		},
		{
			name:      "different network context",
			key:       keyForNetwork,
			contextID: "network-2",
			want:      false,
		},
		{
			name: "wrong derivation scheme",
			key: &dwncrypto.DerivedPrivateJwk{
				DerivationScheme: dwncrypto.DerivationSchemeProtocolPath,
				DerivationPath:   []string{dwncrypto.DerivationSchemeProtocolPath, "protocol", "contextKey"},
			},
			contextID: "network-1",
			want:      false,
		},
		{
			name:      "nil key",
			key:       nil,
			contextID: "network-1",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contextKeyMatchesContext(tt.key, tt.contextID); got != tt.want {
				t.Fatalf("contextKeyMatchesContext() = %v, want %v", got, tt.want)
			}
		})
	}
}
