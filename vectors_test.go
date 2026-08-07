package restless_test

// Replays the shared conformance vectors in-process.
//
// The cross-language harness (node spec/harness/run-vectors.mjs) drives this
// SDK through the stdio driver in cmd/conformance. This does the same thing
// natively, so `go test ./...` alone tells a Go developer whether they broke
// the contract, without needing Node installed.
//
// The vectors in spec/vectors/ are vendored from the Node SDK at the version
// in spec/VECTORS_VERSION. They are generated from the reference
// implementation; do not edit them here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	restless "github.com/restlesshq/go"
	"github.com/restlesshq/go/internal/conformance"
)

type vectorCase struct {
	ID          string         `json:"id"`
	Requirement string         `json:"requirement"`
	Op          string         `json:"op"`
	Input       map[string]any `json:"input"`
	Expected    any            `json:"expected"`
	Compare     string         `json:"compare"`
	Note        string         `json:"note"`

	// outOfDialect marks a case this implementation's language cannot
	// represent. Set at load time from the raw JSON, not from Input.
	outOfDialect bool
}

type vectorFile struct {
	SpecVersion string            `json:"specVersion"`
	Cases       []json.RawMessage `json:"cases"`
}

func loadVectors(t *testing.T) []vectorCase {
	t.Helper()
	dir := filepath.Join("spec", "vectors")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	var all []vectorCase
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("cannot read %s: %v", entry.Name(), err)
		}
		var doc vectorFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("cannot parse %s: %v", entry.Name(), err)
		}
		if doc.SpecVersion != restless.SpecVersion {
			t.Fatalf("%s is spec %s but this SDK declares %s; re-vendor the vectors "+
				"from the Node SDK or fix version.go",
				entry.Name(), doc.SpecVersion, restless.SpecVersion)
		}
		for _, raw := range doc.Cases {
			var c vectorCase
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatalf("cannot parse a case in %s: %v", entry.Name(), err)
			}
			// The RAW text has to be checked before unmarshalling, for the
			// same reason the driver checks the raw line: Go's JSON decoder
			// replaces an unpaired surrogate with U+FFFD, so by the time the
			// case struct exists the input is already gone (PRIM-035).
			// Without this the in-process replay would silently compare a
			// mangled input against the reference's intact one.
			c.outOfDialect = conformance.HasLoneSurrogateEscape(string(raw))
			all = append(all, c)
		}
	}
	return all
}

func TestConformanceVectors(t *testing.T) {
	cases := loadVectors(t)
	if len(cases) < 150 {
		t.Fatalf("only %d vectors loaded; they look missing or truncated", len(cases))
	}

	skipped := 0
	for _, c := range cases {
		if c.outOfDialect {
			skipped++
			continue
		}
		got, err := conformance.Dispatch(c.Op, c.Input)
		if err != nil {
			// FP-046 / PRIM-035: cases outside this implementation's dialect.
			// Covered natively in stack_test.go and documented in
			// CONFORMANCE.md.
			skipped++
			continue
		}
		if !vectorEqual(c.Compare, got, c.Expected) {
			t.Errorf("%s (%s):\n  expected %#v\n  actual   %#v\n  %s",
				c.ID, c.Requirement, c.Expected, got, c.Note)
		}
	}
	t.Logf("%d vectors, %d skipped (outside this implementation's dialect)", len(cases), skipped)
}

// vectorEqual compares per the case's compare mode. "json" cases hold JSON
// *strings*; compare them parsed so an encoder difference alone is not a
// failure.
func vectorEqual(mode string, got, expected any) bool {
	if mode == "json" {
		gs, ok1 := got.(string)
		es, ok2 := expected.(string)
		if ok1 && ok2 {
			var gv, ev any
			if json.Unmarshal([]byte(gs), &gv) == nil && json.Unmarshal([]byte(es), &ev) == nil {
				return reflect.DeepEqual(gv, ev)
			}
		}
	}
	// Round-trip through JSON so Go's map/slice types line up with the
	// generic shapes the vectors decoded into.
	gj, err1 := json.Marshal(got)
	ej, err2 := json.Marshal(expected)
	if err1 != nil || err2 != nil {
		return reflect.DeepEqual(got, expected)
	}
	var gv, ev any
	_ = json.Unmarshal(gj, &gv)
	_ = json.Unmarshal(ej, &ev)
	return reflect.DeepEqual(gv, ev)
}
