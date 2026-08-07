package restless

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// .restless/settings.json discovery. Implements CONTRACT.md section 12.

type RedactSettings struct {
	Headers     []string `json:"headers"`
	BodyKeys    []string `json:"bodyKeys"`
	QueryParams []string `json:"queryParams"`
}

type APIEntry struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	RequestIDPrefix string          `json:"requestIdPrefix"`
	Redact          *RedactSettings `json:"redact"`
}

type Settings struct {
	Version int        `json:"version"`
	APIs    []APIEntry `json:"apis"`
}

var (
	settingsOnce   sync.Once
	cachedSettings *Settings
)

// FindSettingsFile walks up to the filesystem root, first hit wins
// (CONFIG-010).
func FindSettingsFile(startDir string) string {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return ""
	}
	for {
		candidate := filepath.Join(dir, ".restless", "settings.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// LoadSettings reads the file at most once per process, caching the negative
// result too (CONFIG-011). A missing or malformed file yields nil and never
// prevents construction (CONFIG-012).
func LoadSettings() *Settings {
	settingsOnce.Do(func() {
		cwd, err := os.Getwd()
		if err != nil {
			return
		}
		path := FindSettingsFile(cwd)
		if path == "" {
			return
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		var parsed Settings
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return
		}
		cachedSettings = &parsed
	})
	return cachedSettings
}

// ResolveAPI picks the entry to use (CONFIG-013, CONFIG-014).
//
// Returns an error rather than guessing when several APIs are defined and
// none was named: guessing would silently apply the wrong redaction list.
func ResolveAPI(settings *Settings, name string) (*APIEntry, error) {
	if settings == nil || len(settings.APIs) == 0 {
		return nil, nil
	}
	if name != "" {
		for i := range settings.APIs {
			if settings.APIs[i].Name == name {
				return &settings.APIs[i], nil
			}
		}
		for i := range settings.APIs {
			if settings.APIs[i].ID == name {
				return &settings.APIs[i], nil
			}
		}
		return nil, fmt.Errorf(
			"restless: no API named %q in .restless/settings.json (found: %s)",
			name, strings.Join(apiNames(settings), ", "))
	}
	if len(settings.APIs) == 1 {
		return &settings.APIs[0], nil
	}
	return nil, fmt.Errorf(
		"restless: .restless/settings.json has multiple APIs (%s) - pass "+
			"WithAPI(\"<name>\") to New() to pick one", strings.Join(apiNames(settings), ", "))
}

func apiNames(s *Settings) []string {
	names := make([]string, 0, len(s.APIs))
	for _, api := range s.APIs {
		names = append(names, api.Name)
	}
	return names
}
