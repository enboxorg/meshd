package did

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreAndLoad(t *testing.T) {
	dir := t.TempDir()

	d1, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := d1.Store(dir); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// File should exist.
	if !Exists(dir) {
		t.Fatal("Exists returned false after Store")
	}

	// File should be readable only by owner.
	info, err := os.Stat(filepath.Join(dir, stateFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file mode = %o, want 0600", info.Mode().Perm())
	}

	// Load should reconstruct the same DID.
	d2, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d2 == nil {
		t.Fatal("Load returned nil")
	}

	if d1.URI != d2.URI {
		t.Errorf("URIs differ: %q vs %q", d1.URI, d2.URI)
	}
	if string(d1.SigningKey) != string(d2.SigningKey) {
		t.Error("signing keys differ")
	}
	if string(d1.EncryptionPublicKey) != string(d2.EncryptionPublicKey) {
		t.Error("encryption public keys differ")
	}
	if string(d1.EncryptionPrivateKey) != string(d2.EncryptionPrivateKey) {
		t.Error("encryption private keys differ")
	}

	// Signing should work with the loaded key.
	msg := []byte("persistence test")
	sig, err := d2.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !d1.Verify(msg, sig) {
		t.Error("loaded key's signature doesn't verify against original")
	}
}

func TestLoadNonExistent(t *testing.T) {
	dir := t.TempDir()

	if Exists(dir) {
		t.Fatal("Exists should return false for empty dir")
	}

	d, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d != nil {
		t.Fatal("Load should return nil for non-existent file")
	}
}

func TestStoreCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")

	d, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := d.Store(dir); err != nil {
		t.Fatalf("Store: %v", err)
	}

	if !Exists(dir) {
		t.Fatal("file should exist after Store")
	}
}
