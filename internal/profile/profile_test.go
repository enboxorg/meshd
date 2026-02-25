package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func withEnboxHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("ENBOX_HOME", dir)
	return dir
}

func TestEnboxHomeDefault(t *testing.T) {
	t.Setenv("ENBOX_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	got := EnboxHome()
	want := filepath.Join(home, ".enbox")
	if got != want {
		t.Errorf("EnboxHome() = %q, want %q", got, want)
	}
}

func TestEnboxHomeOverride(t *testing.T) {
	dir := withEnboxHome(t)
	if got := EnboxHome(); got != dir {
		t.Errorf("EnboxHome() = %q, want %q", got, dir)
	}
}

func TestConfigPathAndProfilesDir(t *testing.T) {
	dir := withEnboxHome(t)
	if got := ConfigPath(); got != filepath.Join(dir, "config.json") {
		t.Errorf("ConfigPath() = %q", got)
	}
	if got := ProfilesDir(); got != filepath.Join(dir, "profiles") {
		t.Errorf("ProfilesDir() = %q", got)
	}
}

func TestDataPath(t *testing.T) {
	dir := withEnboxHome(t)
	got := DataPath("myprofile")
	want := filepath.Join(dir, "profiles", "myprofile", "meshd")
	if got != want {
		t.Errorf("DataPath() = %q, want %q", got, want)
	}
}

func TestValidateName(t *testing.T) {
	valid := []string{"personal", "work", "my-org", "test_123", "A"}
	for _, n := range valid {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", n, err)
		}
	}
	invalid := []string{"", "has space", "a/b", "../sneaky", "a.b", "a@b"}
	for _, n := range invalid {
		if err := ValidateName(n); err == nil {
			t.Errorf("ValidateName(%q) = nil, want error", n)
		}
	}
}

func TestReadConfigDefault(t *testing.T) {
	withEnboxHome(t)
	cfg, err := ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("version = %d, want 1", cfg.Version)
	}
	if len(cfg.Profiles) != 0 {
		t.Errorf("profiles = %d, want 0", len(cfg.Profiles))
	}
}

func TestWriteAndReadConfig(t *testing.T) {
	withEnboxHome(t)
	cfg := &Config{
		Version:        1,
		DefaultProfile: "test",
		Profiles: map[string]*Entry{
			"test": {Name: "test", DID: "did:dht:abc", CreatedAt: "2025-01-01T00:00:00Z"},
		},
	}
	if err := WriteConfig(cfg); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	got, err := ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if got.DefaultProfile != "test" {
		t.Errorf("defaultProfile = %q, want %q", got.DefaultProfile, "test")
	}
	if got.Profiles["test"] == nil {
		t.Fatal("profile 'test' missing")
	}
	if got.Profiles["test"].DID != "did:dht:abc" {
		t.Errorf("DID = %q, want %q", got.Profiles["test"].DID, "did:dht:abc")
	}
}

func TestUpsertProfileFirstIsDefault(t *testing.T) {
	withEnboxHome(t)
	if err := UpsertProfile("first", "did:dht:111"); err != nil {
		t.Fatalf("UpsertProfile: %v", err)
	}

	cfg, _ := ReadConfig()
	if cfg.DefaultProfile != "first" {
		t.Errorf("defaultProfile = %q, want %q", cfg.DefaultProfile, "first")
	}
	if cfg.Profiles["first"] == nil {
		t.Fatal("profile 'first' missing")
	}
}

func TestUpsertProfileSecondDoesNotChangeDefault(t *testing.T) {
	withEnboxHome(t)
	UpsertProfile("first", "did:dht:111")
	if err := UpsertProfile("second", "did:dht:222"); err != nil {
		t.Fatalf("UpsertProfile: %v", err)
	}

	cfg, _ := ReadConfig()
	if cfg.DefaultProfile != "first" {
		t.Errorf("defaultProfile = %q, want %q", cfg.DefaultProfile, "first")
	}
}

func TestUpsertProfileUpdate(t *testing.T) {
	withEnboxHome(t)
	UpsertProfile("test", "did:dht:old")

	cfg1, _ := ReadConfig()
	created := cfg1.Profiles["test"].CreatedAt

	if err := UpsertProfile("test", "did:dht:new"); err != nil {
		t.Fatalf("UpsertProfile update: %v", err)
	}

	cfg2, _ := ReadConfig()
	if cfg2.Profiles["test"].DID != "did:dht:new" {
		t.Errorf("DID not updated")
	}
	if cfg2.Profiles["test"].CreatedAt != created {
		t.Errorf("createdAt changed on update")
	}
}

func TestRemoveProfile(t *testing.T) {
	withEnboxHome(t)
	UpsertProfile("a", "did:dht:a")
	UpsertProfile("b", "did:dht:b")

	if err := RemoveProfile("a"); err != nil {
		t.Fatalf("RemoveProfile: %v", err)
	}

	cfg, _ := ReadConfig()
	if cfg.Profiles["a"] != nil {
		t.Error("profile 'a' should be removed")
	}
	// Default should switch to the remaining profile.
	if cfg.DefaultProfile != "b" {
		t.Errorf("defaultProfile = %q, want %q", cfg.DefaultProfile, "b")
	}
}

func TestRemoveLastProfileClearsDefault(t *testing.T) {
	withEnboxHome(t)
	UpsertProfile("only", "did:dht:only")

	if err := RemoveProfile("only"); err != nil {
		t.Fatalf("RemoveProfile: %v", err)
	}

	cfg, _ := ReadConfig()
	if cfg.DefaultProfile != "" {
		t.Errorf("defaultProfile = %q, want empty", cfg.DefaultProfile)
	}
}

func TestRemoveNonExistent(t *testing.T) {
	withEnboxHome(t)
	err := RemoveProfile("ghost")
	if err == nil {
		t.Fatal("expected error for non-existent profile")
	}
}

func TestResolveFromFlag(t *testing.T) {
	withEnboxHome(t)
	t.Setenv("ENBOX_PROFILE", "")
	got, err := Resolve("flagged")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "flagged" {
		t.Errorf("Resolve = %q, want %q", got, "flagged")
	}
}

func TestResolveFromEnv(t *testing.T) {
	withEnboxHome(t)
	t.Setenv("ENBOX_PROFILE", "envprofile")
	got, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "envprofile" {
		t.Errorf("Resolve = %q, want %q", got, "envprofile")
	}
}

func TestResolveFromDefault(t *testing.T) {
	withEnboxHome(t)
	t.Setenv("ENBOX_PROFILE", "")
	UpsertProfile("def", "did:dht:def")
	UpsertProfile("other", "did:dht:other")

	got, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "def" {
		t.Errorf("Resolve = %q, want %q", got, "def")
	}
}

func TestResolveSingleFallback(t *testing.T) {
	withEnboxHome(t)
	t.Setenv("ENBOX_PROFILE", "")

	// Create a profile but clear the default.
	UpsertProfile("solo", "did:dht:solo")
	cfg, _ := ReadConfig()
	cfg.DefaultProfile = ""
	WriteConfig(cfg)

	got, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "solo" {
		t.Errorf("Resolve = %q, want %q", got, "solo")
	}
}

func TestResolveNoProfiles(t *testing.T) {
	withEnboxHome(t)
	t.Setenv("ENBOX_PROFILE", "")
	_, err := Resolve("")
	if err != ErrNoProfiles {
		t.Errorf("Resolve error = %v, want ErrNoProfiles", err)
	}
}

func TestResolveMultipleAmbiguous(t *testing.T) {
	withEnboxHome(t)
	t.Setenv("ENBOX_PROFILE", "")
	UpsertProfile("a", "did:dht:a")
	UpsertProfile("b", "did:dht:b")

	// Clear the default.
	cfg, _ := ReadConfig()
	cfg.DefaultProfile = ""
	WriteConfig(cfg)

	_, err := Resolve("")
	if err != ErrMultipleProfiles {
		t.Errorf("Resolve error = %v, want ErrMultipleProfiles", err)
	}
}

func TestResolveDataPathWithEnvOverride(t *testing.T) {
	withEnboxHome(t)
	override := t.TempDir()
	t.Setenv("MESHD_STATE_DIR", override)

	got, err := ResolveDataPath("")
	if err != nil {
		t.Fatalf("ResolveDataPath: %v", err)
	}
	if got != override {
		t.Errorf("ResolveDataPath = %q, want %q", got, override)
	}
}

func TestResolveDataPathFromProfile(t *testing.T) {
	dir := withEnboxHome(t)
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("ENBOX_PROFILE", "")
	UpsertProfile("test", "did:dht:test")

	got, err := ResolveDataPath("")
	if err != nil {
		t.Fatalf("ResolveDataPath: %v", err)
	}
	want := filepath.Join(dir, "profiles", "test", "meshd")
	if got != want {
		t.Errorf("ResolveDataPath = %q, want %q", got, want)
	}
}
