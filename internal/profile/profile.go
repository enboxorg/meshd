// Package profile implements the shared Enbox identity profile system.
//
// Enbox apps share a single identity store at ~/.enbox/. A profile is a
// named identity (DID + keys + app-specific state) that any enbox CLI
// can use. This is analogous to AWS CLI named profiles (~/.aws/).
//
// Storage layout:
//
//	~/.enbox/
//	  config.json                   # global config (profiles index)
//	  profiles/
//	    <name>/
//	      meshd/                    # meshd-specific state
//	        identity.json           # Ed25519 private key + DID URI
//	        network.json            # network membership state
//
// Override base path with ENBOX_HOME env var.
//
// Profile resolution precedence:
//  1. --profile <name> CLI flag
//  2. ENBOX_PROFILE env var
//  3. config.json defaultProfile
//  4. If exactly one profile exists, use it
//  5. Otherwise: error
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Sentinel errors.
var (
	ErrNoProfiles       = errors.New("no profiles configured; run 'meshd auth login' to create one")
	ErrProfileNotFound  = errors.New("profile not found")
	ErrMultipleProfiles = errors.New("multiple profiles exist; use --profile or set a default with 'meshd auth use <name> --default'")
	ErrInvalidName      = errors.New("profile name must match [a-zA-Z0-9_-]+")
	ErrDuplicateName    = errors.New("profile already exists")
)

// validName matches profile names that are filesystem-safe.
var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Config is the top-level ~/.enbox/config.json structure.
type Config struct {
	Version        int                 `json:"version"`
	DefaultProfile string              `json:"defaultProfile"`
	Profiles       map[string]*Entry   `json:"profiles"`
}

// Entry is a single profile entry in config.json.
type Entry struct {
	Name      string `json:"name"`
	DID       string `json:"did"`
	CreatedAt string `json:"createdAt"`
}

// EnboxHome returns the base directory for enbox data.
// Respects ENBOX_HOME env var, otherwise defaults to ~/.enbox.
func EnboxHome() string {
	if d := os.Getenv("ENBOX_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".enbox")
}

// ConfigPath returns the path to config.json.
func ConfigPath() string {
	return filepath.Join(EnboxHome(), "config.json")
}

// ProfilesDir returns the path to the profiles directory.
func ProfilesDir() string {
	return filepath.Join(EnboxHome(), "profiles")
}

// DataPath returns the meshd-specific data directory for a profile.
func DataPath(name string) string {
	return filepath.Join(ProfilesDir(), name, "meshd")
}

// ValidateName checks that a profile name is filesystem-safe.
func ValidateName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return nil
}

// ReadConfig reads ~/.enbox/config.json.
// Returns a default empty config if the file does not exist.
func ReadConfig() (*Config, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{
				Version:  1,
				Profiles: make(map[string]*Entry),
			}, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]*Entry)
	}
	return &cfg, nil
}

// WriteConfig writes ~/.enbox/config.json atomically.
func WriteConfig(cfg *Config) error {
	dir := EnboxHome()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	target := ConfigPath()
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming config: %w", err)
	}
	return nil
}

// UpsertProfile adds or updates a profile entry in config.json.
// If this is the first profile, it becomes the default.
func UpsertProfile(name, did string) error {
	if err := ValidateName(name); err != nil {
		return err
	}

	cfg, err := ReadConfig()
	if err != nil {
		return err
	}

	isNew := cfg.Profiles[name] == nil
	entry := &Entry{
		Name:      name,
		DID:       did,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if !isNew {
		// Preserve original createdAt on updates.
		entry.CreatedAt = cfg.Profiles[name].CreatedAt
		entry.DID = did
	}

	cfg.Profiles[name] = entry

	// First profile becomes the default.
	if len(cfg.Profiles) == 1 || cfg.DefaultProfile == "" {
		cfg.DefaultProfile = name
	}

	return WriteConfig(cfg)
}

// RemoveProfile removes a profile entry from config.json.
// Does NOT delete the profile data directory.
func RemoveProfile(name string) error {
	cfg, err := ReadConfig()
	if err != nil {
		return err
	}

	if cfg.Profiles[name] == nil {
		return fmt.Errorf("%w: %q", ErrProfileNotFound, name)
	}

	delete(cfg.Profiles, name)

	// Update default if we just removed it.
	if cfg.DefaultProfile == name {
		cfg.DefaultProfile = ""
		for k := range cfg.Profiles {
			cfg.DefaultProfile = k
			break
		}
	}

	return WriteConfig(cfg)
}

// Resolve determines the active profile name using the standard precedence:
//  1. flagProfile (from --profile CLI flag)
//  2. ENBOX_PROFILE env var
//  3. config.json defaultProfile
//  4. If exactly one profile exists, use it
//  5. Otherwise: error
func Resolve(flagProfile string) (string, error) {
	// 1. CLI flag.
	if flagProfile != "" {
		return flagProfile, nil
	}

	// 2. Env var.
	if env := os.Getenv("ENBOX_PROFILE"); env != "" {
		return env, nil
	}

	// 3-5. From config.
	cfg, err := ReadConfig()
	if err != nil {
		return "", err
	}

	if len(cfg.Profiles) == 0 {
		return "", ErrNoProfiles
	}

	// 3. Default profile.
	if cfg.DefaultProfile != "" {
		if cfg.Profiles[cfg.DefaultProfile] != nil {
			return cfg.DefaultProfile, nil
		}
		// Default points to a removed profile; fall through.
	}

	// 4. Single profile fallback.
	if len(cfg.Profiles) == 1 {
		for k := range cfg.Profiles {
			return k, nil
		}
	}

	// 5. Ambiguous.
	return "", ErrMultipleProfiles
}

// ResolveDataPath resolves the active profile and returns its meshd data
// directory. This is the primary entry point for commands that need state.
//
// If MESHD_STATE_DIR is set, it takes absolute precedence (bypasses profiles).
func ResolveDataPath(flagProfile string) (string, error) {
	if d := os.Getenv("MESHD_STATE_DIR"); d != "" {
		return d, nil
	}

	name, err := Resolve(flagProfile)
	if err != nil {
		return "", err
	}
	return DataPath(name), nil
}
