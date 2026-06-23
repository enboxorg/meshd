package state

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreAndLoadContextKey(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x42}, 32)

	if err := StoreContextKey(dir, "password", "network-1", key); err != nil {
		t.Fatalf("StoreContextKey: %v", err)
	}
	if !EncryptedSecretsExist(dir) {
		t.Fatal("EncryptedSecretsExist returned false after StoreContextKey")
	}

	data, err := os.ReadFile(filepath.Join(dir, secretsFile))
	if err != nil {
		t.Fatalf("read secrets file: %v", err)
	}
	if bytes.Contains(data, key) ||
		bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(key))) ||
		bytes.Contains(data, []byte("network-1")) {
		t.Fatal("encrypted secrets file contains plaintext key material")
	}

	got, ok, err := LoadContextKey(dir, "password", "network-1")
	if err != nil {
		t.Fatalf("LoadContextKey: %v", err)
	}
	if !ok {
		t.Fatal("context key was not found")
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("context key mismatch\ngot:  %x\nwant: %x", got, key)
	}
}

func TestStoreContextKeyPreservesExistingKeys(t *testing.T) {
	dir := t.TempDir()
	key1 := bytes.Repeat([]byte{0x01}, 32)
	key2 := bytes.Repeat([]byte{0x02}, 32)

	if err := StoreContextKey(dir, "password", "network-1", key1); err != nil {
		t.Fatalf("StoreContextKey network-1: %v", err)
	}
	if err := StoreContextKey(dir, "password", "network-2", key2); err != nil {
		t.Fatalf("StoreContextKey network-2: %v", err)
	}

	got1, ok, err := LoadContextKey(dir, "password", "network-1")
	if err != nil {
		t.Fatalf("LoadContextKey network-1: %v", err)
	}
	if !ok || !bytes.Equal(got1, key1) {
		t.Fatalf("network-1 key mismatch")
	}
	got2, ok, err := LoadContextKey(dir, "password", "network-2")
	if err != nil {
		t.Fatalf("LoadContextKey network-2: %v", err)
	}
	if !ok || !bytes.Equal(got2, key2) {
		t.Fatalf("network-2 key mismatch")
	}
}

func TestLoadContextKeyMissing(t *testing.T) {
	dir := t.TempDir()

	got, ok, err := LoadContextKey(dir, "password", "missing")
	if err != nil {
		t.Fatalf("LoadContextKey: %v", err)
	}
	if ok || got != nil {
		t.Fatalf("missing key returned %x, %v", got, ok)
	}
}

func TestLoadContextKeyWrongPassword(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x42}, 32)

	if err := StoreContextKey(dir, "password", "network-1", key); err != nil {
		t.Fatalf("StoreContextKey: %v", err)
	}
	if _, _, err := LoadContextKey(dir, "wrong", "network-1"); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}
