package did

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/enboxorg/meshd/internal/vault"
)

func TestStoreAndLoadEncrypted(t *testing.T) {
	dir := t.TempDir()

	d1, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := d1.storeEncryptedWithParams(dir, "password", vault.FastArgon2idParams); err != nil {
		t.Fatalf("storeEncryptedWithParams: %v", err)
	}

	if !EncryptedExists(dir) {
		t.Fatal("EncryptedExists returned false after StoreEncrypted")
	}
	if Exists(dir) {
		t.Fatal("legacy plaintext identity should not exist after StoreEncrypted")
	}

	info, err := os.Stat(filepath.Join(dir, encryptedStateFile))
	if err != nil {
		t.Fatalf("stat encrypted identity: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("encrypted file mode = %o, want 0600", info.Mode().Perm())
	}

	d2, err := LoadEncrypted(dir, "password")
	if err != nil {
		t.Fatalf("LoadEncrypted: %v", err)
	}
	if d2 == nil {
		t.Fatal("LoadEncrypted returned nil")
	}
	if d1.URI != d2.URI {
		t.Fatalf("URI = %q, want %q", d2.URI, d1.URI)
	}
	if string(d1.SigningKey) != string(d2.SigningKey) {
		t.Fatal("signing key changed after encrypted round trip")
	}

	if _, err := LoadEncrypted(dir, "wrong"); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}

func TestMigrateToEncrypted(t *testing.T) {
	dir := t.TempDir()

	d1, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := d1.Store(dir); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if !Exists(dir) {
		t.Fatal("legacy identity should exist before migration")
	}

	if err := migrateToEncryptedWithParams(dir, "password", vault.FastArgon2idParams); err != nil {
		t.Fatalf("migrateToEncryptedWithParams: %v", err)
	}
	if Exists(dir) {
		t.Fatal("legacy plaintext identity still exists after migration")
	}
	if !EncryptedExists(dir) {
		t.Fatal("encrypted identity was not created")
	}

	d2, err := LoadEncrypted(dir, "password")
	if err != nil {
		t.Fatalf("LoadEncrypted: %v", err)
	}
	if d2 == nil || d2.URI != d1.URI {
		t.Fatalf("migrated identity URI = %v, want %s", d2, d1.URI)
	}
}
