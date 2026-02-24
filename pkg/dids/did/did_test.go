package did

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := map[string]struct {
		input   string
		wantErr bool
		check   func(t *testing.T, d DID)
	}{
		"simple did:dht": {
			input: "did:dht:abc123",
			check: func(t *testing.T, d DID) {
				if d.Method != "dht" {
					t.Errorf("Method = %q, want %q", d.Method, "dht")
				}
				if d.ID != "abc123" {
					t.Errorf("ID = %q, want %q", d.ID, "abc123")
				}
				if d.URI != "did:dht:abc123" {
					t.Errorf("URI = %q, want %q", d.URI, "did:dht:abc123")
				}
			},
		},
		"did:jwk with base64url ID": {
			input: "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwidXNlIjoic2lnIiwieCI6InNNc3J5SDN0ZkVHdFB4dFJGRXBfLXpZX0loRTBfTmFWVWN2Y0dMa2lFRlEifQ",
			check: func(t *testing.T, d DID) {
				if d.Method != "jwk" {
					t.Errorf("Method = %q, want %q", d.Method, "jwk")
				}
			},
		},
		"did:web domain only": {
			input: "did:web:example.com",
			check: func(t *testing.T, d DID) {
				if d.Method != "web" {
					t.Errorf("Method = %q, want %q", d.Method, "web")
				}
				if d.ID != "example.com" {
					t.Errorf("ID = %q, want %q", d.ID, "example.com")
				}
			},
		},
		"did:web with path": {
			input: "did:web:example.com:user:alice",
			check: func(t *testing.T, d DID) {
				if d.Method != "web" {
					t.Errorf("Method = %q, want %q", d.Method, "web")
				}
				if d.ID != "example.com:user:alice" {
					t.Errorf("ID = %q, want %q", d.ID, "example.com:user:alice")
				}
			},
		},
		"did with fragment": {
			input: "did:web:example.com#key-1",
			check: func(t *testing.T, d DID) {
				if d.Fragment != "key-1" {
					t.Errorf("Fragment = %q, want %q", d.Fragment, "key-1")
				}
			},
		},
		"did with query": {
			input: "did:web:example.com?service=agent",
			check: func(t *testing.T, d DID) {
				if d.Query != "service=agent" {
					t.Errorf("Query = %q, want %q", d.Query, "service=agent")
				}
			},
		},
		"did with params": {
			input: "did:web:example.com;service=files;version=2",
			check: func(t *testing.T, d DID) {
				if d.Params["service"] != "files" {
					t.Errorf("Params[service] = %q, want %q", d.Params["service"], "files")
				}
				if d.Params["version"] != "2" {
					t.Errorf("Params[version] = %q, want %q", d.Params["version"], "2")
				}
			},
		},
		"empty string": {
			input:   "",
			wantErr: true,
		},
		"missing method": {
			input:   "did::abc",
			wantErr: true,
		},
		"not a DID": {
			input:   "https://example.com",
			wantErr: true,
		},
		"missing method-specific ID": {
			input:   "did:web:",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d, err := Parse(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, d)
			}
		})
	}
}

func TestDID_URL(t *testing.T) {
	tests := map[string]struct {
		did  DID
		want string
	}{
		"URI only": {
			did:  DID{URI: "did:web:example.com"},
			want: "did:web:example.com",
		},
		"with fragment": {
			did:  DID{URI: "did:web:example.com", Fragment: "key-1"},
			want: "did:web:example.com#key-1",
		},
		"with query": {
			did:  DID{URI: "did:web:example.com", Query: "service=agent"},
			want: "did:web:example.com?service=agent",
		},
		"with path": {
			did:  DID{URI: "did:web:example.com", Path: "/some/path"},
			want: "did:web:example.com//some/path",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := tc.did.URL()
			if got != tc.want {
				t.Errorf("URL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDID_MarshalUnmarshalText(t *testing.T) {
	original := "did:dht:abc123"
	d := MustParse(original)

	text, err := d.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var d2 DID
	if err := d2.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}

	if d2.URI != d.URI {
		t.Errorf("URI mismatch: got %q, want %q", d2.URI, d.URI)
	}
	if d2.Method != d.Method {
		t.Errorf("Method mismatch: got %q, want %q", d2.Method, d.Method)
	}
}

func TestMustParse_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid DID")
		}
	}()
	MustParse("not-a-did")
}

func TestDID_String(t *testing.T) {
	d := MustParse("did:web:example.com")
	if d.String() != "did:web:example.com" {
		t.Errorf("String() = %q, want %q", d.String(), "did:web:example.com")
	}
}
