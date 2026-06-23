package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/enboxorg/meshd/internal/did"
	"github.com/enboxorg/meshd/internal/invite"
	"github.com/enboxorg/meshd/internal/mesh"
	"github.com/enboxorg/meshd/internal/profile"
	"github.com/enboxorg/meshd/internal/state"
)

func TestParseUpFlagsInviteURL(t *testing.T) {
	u, err := invite.Encode(invite.New("https://dwn.example.com", "did:jwk:anchor", "net", "home", "", "", ""))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	flags := parseUpFlags([]string{u, "--no-tun"})
	if flags.inviteURL != u {
		t.Fatalf("inviteURL = %q, want %q", flags.inviteURL, u)
	}
	if !flags.noTun {
		t.Fatal("expected --no-tun to be parsed")
	}
}

func TestDefaultTUNName(t *testing.T) {
	if got := defaultTUNName("darwin"); got != "utun" {
		t.Fatalf("defaultTUNName(darwin) = %q, want utun", got)
	}
	if got := defaultTUNName("linux"); got != "meshd0" {
		t.Fatalf("defaultTUNName(linux) = %q, want meshd0", got)
	}
}

func TestPeerListMeshIPFallsBackToDeterministicIP(t *testing.T) {
	const peerDID = "did:jwk:test-peer"
	want, err := mesh.AllocateMeshIP("10.200.0.0/16", peerDID)
	if err != nil {
		t.Fatalf("AllocateMeshIP: %v", err)
	}
	if got := peerListMeshIP("10.200.0.0/16", peerDID, ""); got != want.String() {
		t.Fatalf("peerListMeshIP fallback = %q, want %q", got, want)
	}
	if got := peerListMeshIP("10.200.0.0/16", peerDID, "10.200.9.9"); got != "10.200.9.9" {
		t.Fatalf("peerListMeshIP explicit = %q, want explicit record IP", got)
	}
	if got := peerListMeshIP("", peerDID, ""); got != "?" {
		t.Fatalf("peerListMeshIP missing CIDR = %q, want ?", got)
	}
}

func TestPeerListDeviceLabelsSelf(t *testing.T) {
	const selfDID = "did:jwk:self"
	if got := peerListDevice(selfDID, selfDID); got != "this device" {
		t.Fatalf("peerListDevice(self) = %q, want this device", got)
	}
	if got := peerListDevice("did:jwk:peer", selfDID); got != "peer" {
		t.Fatalf("peerListDevice(peer) = %q, want peer", got)
	}
	if got := peerListDevice("", selfDID); got != "peer" {
		t.Fatalf("peerListDevice(empty) = %q, want peer", got)
	}
}

func TestParseUpFlagsTunUsesPlatformDefault(t *testing.T) {
	flags := parseUpFlags([]string{"--tun"})
	want := defaultTUNName(runtime.GOOS)
	if flags.tunName != want {
		t.Fatalf("tunName = %q, want %q", flags.tunName, want)
	}
}

func TestParseUpFlagsForeground(t *testing.T) {
	flags := parseUpFlags([]string{"--foreground"})
	if !flags.foreground {
		t.Fatal("expected --foreground to be parsed")
	}
}

func TestShouldReexecWithSudoForTun(t *testing.T) {
	if !shouldReexecWithSudoForTun(upFlags{}, 501, "darwin", true) {
		t.Fatal("expected interactive non-root darwin up to reexec with sudo")
	}
	if !shouldReexecWithSudoForTun(upFlags{}, 1000, "linux", true) {
		t.Fatal("expected interactive non-root linux up to reexec with sudo")
	}
	if shouldReexecWithSudoForTun(upFlags{}, 0, "linux", true) {
		t.Fatal("did not expect root to reexec with sudo")
	}
	if shouldReexecWithSudoForTun(upFlags{noTun: true}, 1000, "linux", true) {
		t.Fatal("did not expect --no-tun to reexec with sudo")
	}
	if shouldReexecWithSudoForTun(upFlags{}, 1000, "linux", false) {
		t.Fatal("did not expect non-interactive up to reexec with sudo")
	}
	if shouldReexecWithSudoForTun(upFlags{}, 1000, "freebsd", true) {
		t.Fatal("did not expect unsupported OS to reexec with sudo")
	}
}

func TestSudoEnvironmentAssignments(t *testing.T) {
	home := t.TempDir()
	enboxHome := filepath.Join(home, ".enbox-custom")
	t.Setenv("HOME", home)
	t.Setenv("ENBOX_HOME", enboxHome)
	t.Setenv("PATH", "/tmp/test-path")
	t.Setenv("DWN_ENDPOINT", "https://dwn.example")
	t.Setenv("ENBOX_PROFILE", "work")
	t.Setenv("MESHD_STATE_DIR", filepath.Join(home, "state"))
	t.Setenv("MESHD_VAULT_PASSWORD", "secret")
	t.Setenv(vaultPasswordCacheDirEnv, filepath.Join(home, "runtime-cache"))
	t.Setenv(vaultPasswordCacheTTLEnv, "2m")

	assignments := sudoEnvironmentAssignments()
	for _, want := range []string{
		sudoChildEnv + "=1",
		"HOME=" + home,
		"ENBOX_HOME=" + enboxHome,
		"PATH=/tmp/test-path",
		"DWN_ENDPOINT=https://dwn.example",
		"ENBOX_PROFILE=work",
		"MESHD_STATE_DIR=" + filepath.Join(home, "state"),
		vaultPasswordCacheDirEnv + "=" + filepath.Join(home, "runtime-cache"),
		vaultPasswordCacheTTLEnv + "=2m",
	} {
		if !hasString(assignments, want) {
			t.Fatalf("sudoEnvironmentAssignments() missing %q in %v", want, assignments)
		}
	}
	for _, got := range assignments {
		if strings.HasPrefix(got, "MESHD_VAULT_PASSWORD=") {
			t.Fatal("sudoEnvironmentAssignments must not expose MESHD_VAULT_PASSWORD")
		}
	}
}

func TestSudoEnvironmentAssignmentsDefaultsEnboxHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ENBOX_HOME", "")

	assignments := sudoEnvironmentAssignments()
	want := "ENBOX_HOME=" + filepath.Join(home, ".enbox")
	if !hasString(assignments, want) {
		t.Fatalf("sudoEnvironmentAssignments() missing %q in %v", want, assignments)
	}
}

func TestSudoOriginalIDs(t *testing.T) {
	t.Setenv("SUDO_UID", "501")
	t.Setenv("SUDO_GID", "20")

	uid, gid, ok := sudoOriginalIDs()
	if !ok || uid != 501 || gid != 20 {
		t.Fatalf("sudoOriginalIDs() = %d, %d, %v; want 501, 20, true", uid, gid, ok)
	}

	t.Setenv("SUDO_UID", "0")
	if _, _, ok := sudoOriginalIDs(); ok {
		t.Fatal("sudoOriginalIDs() should reject root SUDO_UID")
	}
}

func TestSudoOwnershipRoots(t *testing.T) {
	home := t.TempDir()
	stateDir := filepath.Join(home, "state")
	enboxHome := filepath.Join(home, ".enbox")
	t.Setenv("HOME", home)
	t.Setenv("MESHD_STATE_DIR", stateDir)
	t.Setenv("ENBOX_HOME", enboxHome)

	roots := sudoOwnershipRoots()
	if len(roots) != 1 || roots[0] != stateDir {
		t.Fatalf("sudoOwnershipRoots() = %v, want [%s]", roots, stateDir)
	}

	t.Setenv("MESHD_STATE_DIR", "")
	roots = sudoOwnershipRoots()
	if len(roots) != 1 || roots[0] != enboxHome {
		t.Fatalf("sudoOwnershipRoots() = %v, want [%s]", roots, enboxHome)
	}
}

func TestSudoOwnershipRootsRejectsOutsideHome(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "state")
	t.Setenv("HOME", home)
	t.Setenv("MESHD_STATE_DIR", outside)
	t.Setenv("ENBOX_HOME", "")

	if roots := sudoOwnershipRoots(); len(roots) != 0 {
		t.Fatalf("sudoOwnershipRoots() = %v, want empty for path outside HOME", roots)
	}
	if isSafeSudoOwnershipRoot(home, home) {
		t.Fatal("home itself must not be accepted as an ownership root")
	}
}

func TestEnsureDWNTenantRegistered(t *testing.T) {
	var registeredDID string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/info":
			writeJSON(t, w, map[string]any{
				"registrationRequirements": []string{"provider-auth-v0"},
				"providerAuth": map[string]string{
					"authorizeUrl": server.URL + "/authorize",
					"tokenUrl":     server.URL + "/token",
				},
			})
		case "/authorize":
			writeJSON(t, w, map[string]string{
				"code":  "test-code",
				"state": r.URL.Query().Get("state"),
			})
		case "/token":
			writeJSON(t, w, map[string]string{"registrationToken": "test-token"})
		case "/registration":
			var body struct {
				RegistrationData struct {
					DID string `json:"did"`
				} `json:"registrationData"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decoding registration body: %v", err)
			}
			registeredDID = body.RegistrationData.DID
			writeJSON(t, w, map[string]string{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	identity := &did.DID{URI: "did:jwk:test"}
	if err := ensureDWNTenantRegistered(context.Background(), server.URL, identity); err != nil {
		t.Fatalf("ensureDWNTenantRegistered: %v", err)
	}
	if registeredDID != identity.URI {
		t.Fatalf("registered DID = %q, want %q", registeredDID, identity.URI)
	}
}

func TestEnsureDWNTenantRegisteredNoopWithoutEndpoint(t *testing.T) {
	if err := ensureDWNTenantRegistered(context.Background(), "", &did.DID{URI: "did:jwk:test"}); err != nil {
		t.Fatalf("ensureDWNTenantRegistered empty endpoint: %v", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encoding response: %v", err)
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestParseNetworkCreateArgs(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "")

	name, endpoint := parseNetworkCreateArgs([]string{"home", "--endpoint", "https://dwn.example.com"})
	if name != "home" {
		t.Fatalf("name = %q, want home", name)
	}
	if endpoint != "https://dwn.example.com" {
		t.Fatalf("endpoint = %q, want https://dwn.example.com", endpoint)
	}
}

func TestParseNetworkCreateArgsUsesEndpointEnv(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "https://env.example.com")

	name, endpoint := parseNetworkCreateArgs([]string{"home"})
	if name != "home" {
		t.Fatalf("name = %q, want home", name)
	}
	if endpoint != "https://env.example.com" {
		t.Fatalf("endpoint = %q, want https://env.example.com", endpoint)
	}
}

func TestParseNetworkJoinArgs(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "")

	endpoint, anchorDID, networkID, preauth := parseNetworkJoinArgs([]string{
		"--endpoint", "https://dwn.example.com",
		"--anchor", "did:jwk:anchor",
		"--network", "net",
		"--preauth",
	})
	if endpoint != "https://dwn.example.com" {
		t.Fatalf("endpoint = %q, want https://dwn.example.com", endpoint)
	}
	if anchorDID != "did:jwk:anchor" {
		t.Fatalf("anchorDID = %q, want did:jwk:anchor", anchorDID)
	}
	if networkID != "net" {
		t.Fatalf("networkID = %q, want net", networkID)
	}
	if !preauth {
		t.Fatal("preauth = false, want true")
	}
}

func TestParseNetworkJoinArgsUsesEndpointEnv(t *testing.T) {
	t.Setenv("DWN_ENDPOINT", "https://env.example.com")

	endpoint, anchorDID, networkID, preauth := parseNetworkJoinArgs([]string{
		"--anchor", "did:jwk:anchor",
		"--network", "net",
	})
	if endpoint != "https://env.example.com" {
		t.Fatalf("endpoint = %q, want https://env.example.com", endpoint)
	}
	if anchorDID != "did:jwk:anchor" {
		t.Fatalf("anchorDID = %q, want did:jwk:anchor", anchorDID)
	}
	if networkID != "net" {
		t.Fatalf("networkID = %q, want net", networkID)
	}
	if preauth {
		t.Fatal("preauth = true, want false")
	}
}

func resetVaultPasswordCache(t *testing.T) {
	t.Helper()
	previous := cachedVaultPassword
	previousStateDir := cachedVaultPasswordStateDir
	cachedVaultPassword = ""
	cachedVaultPasswordStateDir = ""
	t.Setenv(vaultPasswordCacheDirEnv, t.TempDir())
	t.Setenv(vaultPasswordCacheTTLEnv, "")
	t.Cleanup(func() {
		cachedVaultPassword = previous
		cachedVaultPasswordStateDir = previousStateDir
	})
}

func TestVaultPasswordCachePersistsAcrossCLIInvocations(t *testing.T) {
	resetVaultPasswordCache(t)

	stateDir := t.TempDir()
	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := identity.StoreEncrypted(stateDir, "test-password"); err != nil {
		t.Fatalf("StoreEncrypted: %v", err)
	}

	rememberVaultPassword(stateDir, "test-password", true)
	cachePath, err := vaultPasswordCachePath(stateDir)
	if err != nil {
		t.Fatalf("vaultPasswordCachePath: %v", err)
	}
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("stat vault password cache: %v", err)
	}
	if info.Mode().Perm() != vaultPasswordCacheFileMode {
		t.Fatalf("cache mode = %v, want %v", info.Mode().Perm(), vaultPasswordCacheFileMode)
	}

	cachedVaultPassword = ""
	cachedVaultPasswordStateDir = ""
	loaded, err := loadIdentity(stateDir)
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if loaded.URI != identity.URI {
		t.Fatalf("loaded DID = %q, want %q", loaded.URI, identity.URI)
	}
}

func TestEnsureIdentityForCommandCreatesDefaultProfile(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	stateDir, identity, err := ensureIdentityForCommand(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	if identity == nil || identity.URI == "" {
		t.Fatal("identity was not created")
	}
	if !strings.HasPrefix(stateDir, home) {
		t.Fatalf("stateDir = %q, want under %q", stateDir, home)
	}
	if !did.EncryptedExists(stateDir) {
		t.Fatal("identity was not stored in encrypted vault")
	}
	if did.Exists(stateDir) {
		t.Fatal("legacy plaintext identity should not be created")
	}

	cfg, err := profile.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.DefaultProfile != "default" {
		t.Fatalf("DefaultProfile = %q, want default", cfg.DefaultProfile)
	}
	if cfg.Profiles["default"] == nil {
		t.Fatal("default profile was not saved")
	}
}

func TestEnsureIdentityForCommandUsesResolvedDefaultProfile(t *testing.T) {
	resetVaultPasswordCache(t)

	home := t.TempDir()
	t.Setenv("ENBOX_HOME", home)
	t.Setenv("ENBOX_PROFILE", "")
	t.Setenv("MESHD_STATE_DIR", "")
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	if err := profile.UpsertProfile("work", "did:jwk:placeholder"); err != nil {
		t.Fatalf("UpsertProfile: %v", err)
	}

	stateDir, identity, err := ensureIdentityForCommand(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ensureIdentityForCommand: %v", err)
	}
	if identity == nil || identity.URI == "" {
		t.Fatal("identity was not created")
	}
	if stateDir != profile.DataPath("work") {
		t.Fatalf("stateDir = %q, want %q", stateDir, profile.DataPath("work"))
	}
	if !did.EncryptedExists(stateDir) {
		t.Fatal("identity was not stored in encrypted vault")
	}

	cfg, err := profile.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if cfg.DefaultProfile != "work" {
		t.Fatalf("DefaultProfile = %q, want work", cfg.DefaultProfile)
	}
	if cfg.Profiles["work"].DID != identity.URI {
		t.Fatalf("profile DID = %q, want %q", cfg.Profiles["work"].DID, identity.URI)
	}
}

func TestLoadLocalContextKeyMigratesLegacyContextKey(t *testing.T) {
	resetVaultPasswordCache(t)

	dir := t.TempDir()
	t.Setenv("MESHD_VAULT_PASSWORD", "test-password")

	identity, err := did.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := identity.StoreEncrypted(dir, "test-password"); err != nil {
		t.Fatalf("StoreEncrypted: %v", err)
	}

	key := bytes.Repeat([]byte{0x42}, 32)
	ns := &state.NetworkState{
		NetworkRecordID: "network-1",
		ContextKey:      base64.StdEncoding.EncodeToString(key),
	}
	if err := state.SaveNetworkState(dir, ns); err != nil {
		t.Fatalf("SaveNetworkState: %v", err)
	}

	source, ok, err := loadLocalContextKeyForCLI(dir, ns, newEncryptionKeyManager(identity))
	if err != nil {
		t.Fatalf("loadLocalContextKeyForCLI: %v", err)
	}
	if !ok {
		t.Fatal("context key was not loaded")
	}
	if source != "legacy cache (migrated)" {
		t.Fatalf("source = %q, want migrated legacy cache", source)
	}

	stored, ok, err := state.LoadContextKey(dir, "test-password", "network-1")
	if err != nil {
		t.Fatalf("LoadContextKey: %v", err)
	}
	if !ok || !bytes.Equal(stored, key) {
		t.Fatalf("encrypted context key mismatch")
	}
	reloaded, err := state.LoadNetworkState(dir)
	if err != nil {
		t.Fatalf("LoadNetworkState: %v", err)
	}
	if reloaded.ContextKey != "" {
		t.Fatalf("legacy ContextKey = %q, want empty", reloaded.ContextKey)
	}
}
