package meshaddr

import "testing"

func TestAllocateMeshIP(t *testing.T) {
	ip, err := AllocateMeshIP("10.200.0.0/16", "did:jwk:test")
	if err != nil {
		t.Fatalf("AllocateMeshIP: %v", err)
	}
	if !ip.Is4() {
		t.Fatalf("IP = %s, want IPv4", ip)
	}
	if ip.String() == "10.200.0.0" || ip.String() == "10.200.0.1" || ip.String() == "10.200.255.255" {
		t.Fatalf("IP = %s, want usable host address", ip)
	}
}

func TestAllocateMeshIPDeterministic(t *testing.T) {
	a, err := AllocateMeshIP("10.200.0.0/16", "did:jwk:same")
	if err != nil {
		t.Fatalf("AllocateMeshIP first: %v", err)
	}
	b, err := AllocateMeshIP("10.200.0.0/16", "did:jwk:same")
	if err != nil {
		t.Fatalf("AllocateMeshIP second: %v", err)
	}
	if a != b {
		t.Fatalf("AllocateMeshIP not deterministic: %s != %s", a, b)
	}
}
