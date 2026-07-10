package vaultkey

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestAccountForStateDir(t *testing.T) {
	dir := t.TempDir()
	digest := sha256.Sum256([]byte(filepath.Clean(dir)))
	want := accountPrefix + hex.EncodeToString(digest[:])

	got, err := accountForStateDir(dir)
	if err != nil {
		t.Fatalf("accountForStateDir: %v", err)
	}
	if got != want {
		t.Fatalf("accountForStateDir() = %q, want %q", got, want)
	}

	withTraversal := filepath.Join(dir, "child") + string(filepath.Separator) + ".."
	gotTraversal, err := accountForStateDir(withTraversal)
	if err != nil {
		t.Fatalf("accountForStateDir with traversal: %v", err)
	}
	if gotTraversal != got {
		t.Fatalf("equivalent state directories mapped to different accounts: %q != %q", gotTraversal, got)
	}

	other, err := accountForStateDir(t.TempDir())
	if err != nil {
		t.Fatalf("accountForStateDir for other directory: %v", err)
	}
	if other == got {
		t.Fatal("different state directories mapped to the same account")
	}
}

func TestStoreLifecycle(t *testing.T) {
	backend := newMemoryBackend()
	store := New(backend)
	stateDir := t.TempDir()

	if err := store.Set(stateDir, "vault-secret"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get(stateDir)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "vault-secret" {
		t.Fatalf("Get() = %q, want %q", got, "vault-secret")
	}
	if err := store.Delete(stateDir); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(stateDir); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete error = %v, want ErrNotFound", err)
	}

	account, err := accountForStateDir(stateDir)
	if err != nil {
		t.Fatalf("accountForStateDir: %v", err)
	}
	if backend.lastService != ServiceName || backend.lastAccount != account {
		t.Fatalf("backend entry = (%q, %q), want (%q, %q)", backend.lastService, backend.lastAccount, ServiceName, account)
	}
}

func TestStoreNormalizesBackendNotFound(t *testing.T) {
	for _, operation := range []string{"get", "delete"} {
		t.Run(operation, func(t *testing.T) {
			backend := newMemoryBackend()
			backend.err = fmt.Errorf("backend: %w", keyring.ErrNotFound)
			store := New(backend)

			var err error
			switch operation {
			case "get":
				_, err = store.Get(t.TempDir())
			case "delete":
				err = store.Delete(t.TempDir())
			}
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
			if errors.Is(err, keyring.ErrNotFound) {
				t.Fatalf("error leaked backend sentinel: %v", err)
			}
		})
	}
}

func TestStoreWrapsBackendErrors(t *testing.T) {
	backendErr := errors.New("backend unavailable")
	for _, operation := range []string{"get", "set", "delete"} {
		t.Run(operation, func(t *testing.T) {
			backend := newMemoryBackend()
			backend.err = backendErr
			store := New(backend)
			stateDir := t.TempDir()

			var err error
			switch operation {
			case "get":
				_, err = store.Get(stateDir)
			case "set":
				err = store.Set(stateDir, "vault-secret")
			case "delete":
				err = store.Delete(stateDir)
			}
			if !errors.Is(err, backendErr) {
				t.Fatalf("error = %v, want wrapped backend error", err)
			}
		})
	}
}

func TestStoreRejectsEmptyStateDir(t *testing.T) {
	backend := newMemoryBackend()
	store := New(backend)

	if _, err := store.Get(""); err == nil {
		t.Fatal("Get with empty state directory succeeded")
	}
	if err := store.Set("", "vault-secret"); err == nil {
		t.Fatal("Set with empty state directory succeeded")
	}
	if err := store.Delete(""); err == nil {
		t.Fatal("Delete with empty state directory succeeded")
	}
	if backend.calls != 0 {
		t.Fatalf("backend calls = %d, want 0", backend.calls)
	}
}

func TestStoreRejectsEmptyKey(t *testing.T) {
	backend := newMemoryBackend()
	store := New(backend)
	if err := store.Set(t.TempDir(), ""); err == nil {
		t.Fatal("Set accepted an empty vault key")
	}
	if backend.calls != 0 {
		t.Fatalf("backend calls = %d, want 0", backend.calls)
	}
}

func TestNewRejectsNilBackend(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New(nil) did not panic")
		}
	}()
	New(nil)
}

type memoryBackend struct {
	values      map[string]string
	err         error
	calls       int
	lastService string
	lastAccount string
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{values: make(map[string]string)}
}

func (b *memoryBackend) Get(service, account string) (string, error) {
	b.record(service, account)
	if b.err != nil {
		return "", b.err
	}
	value, ok := b.values[entryKey(service, account)]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (b *memoryBackend) Set(service, account, secret string) error {
	b.record(service, account)
	if b.err != nil {
		return b.err
	}
	b.values[entryKey(service, account)] = secret
	return nil
}

func (b *memoryBackend) Delete(service, account string) error {
	b.record(service, account)
	if b.err != nil {
		return b.err
	}
	key := entryKey(service, account)
	if _, ok := b.values[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(b.values, key)
	return nil
}

func (b *memoryBackend) record(service, account string) {
	b.calls++
	b.lastService = service
	b.lastAccount = account
}

func entryKey(service, account string) string {
	return service + "\x00" + account
}
