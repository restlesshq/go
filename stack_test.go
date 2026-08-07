package restless_test

// Go-dialect stack frame tests.
//
// CONTRACT.md FP-044 makes stack frame PARSING per-language and FP-046
// requires each SDK to cover its own dialect in its own suite. The shared
// vectors carry v8-shaped stacks, which this SDK reports as an unsupported
// dialect and the harness records as skipped; these are the cases that
// replace them.
//
// Only the OUTPUT shape is contract surface, so what is asserted here is
// exactly FP-040 through FP-045.

import (
	"strings"
	"testing"

	restless "github.com/restlesshq/go"
)

// A real runtime/debug.Stack() shape: function on one line, file indented
// on the next.
const goStack = `goroutine 42 [running]:
runtime/debug.Stack()
	/usr/local/go/src/runtime/debug/stack.go:24 +0x64
github.com/acme/proj/src/db.FindByID(0x14000112000)
	/Users/dev/proj/src/db/users.go:12 +0x1c
github.com/acme/proj/src/routes.Handler(0x14000112000)
	/Users/dev/proj/src/routes/users.go:42 +0x40
net/http.(*conn).serve(0x14000130000)
	/usr/local/go/src/net/http/server.go:2092 +0x5a8
`

func TestTopUserFrameSkipsRuntime(t *testing.T) {
	// FP-043: nearest the throw site, skipping runtime and stdlib frames.
	// Go's debug.Stack() puts the innermost frame FIRST, like a v8 stack and
	// unlike a Python traceback, so this walks forwards.
	file, fn, ok := restless.TopUserFrame(goStack)
	if !ok {
		t.Fatal("no frame found")
	}
	if file != "src/db/users.go" || fn != "FindByID" {
		t.Errorf("got %s:%s, want src/db/users.go:FindByID", file, fn)
	}
}

func TestTopUserFrameNotTheEntryPoint(t *testing.T) {
	// The regression this ordering exists to prevent: returning the
	// outermost frame would give net/http's conn.serve for every panic in
	// the process, collapsing every 500 into one fingerprint group.
	_, fn, _ := restless.TopUserFrame(goStack)
	if fn == "serve" || fn == "Handler" {
		t.Errorf("picked an outer frame (%s); FP-043 wants the throw site", fn)
	}
}

func TestTopUserFrameEmpty(t *testing.T) {
	if _, _, ok := restless.TopUserFrame(""); ok {
		t.Error("empty stack should yield no frame")
	}
}

func TestTopUserFrameV8IsUnparseable(t *testing.T) {
	// A v8 stack has no "\tfile.go:N" frames, so the ladder falls through
	// rather than guessing.
	v8 := "Error: boom\n    at findById (/proj/src/db/users.js:12:34)"
	if _, _, ok := restless.TopUserFrame(v8); ok {
		t.Error("a v8 stack should not parse as a Go stack")
	}
}

func TestProjectRelativeStripsMachinePrefix(t *testing.T) {
	// FP-042: dev and prod must produce the same key.
	if got := restless.ProjectRelative("/Users/dev/proj/src/db/users.go"); got != "src/db/users.go" {
		t.Errorf("got %q", got)
	}
	if got := restless.ProjectRelative("/opt/render/project/src/db/users.go"); got != "src/db/users.go" {
		t.Errorf("got %q", got)
	}
}

func TestProjectRelativeTakesTheLastProjectDir(t *testing.T) {
	// FP-042 takes the LAST project dir, not the first, and this is the case
	// the distinction exists for: Docker's conventional WORKDIR /app and
	// Heroku both root the deployment at /app. Under a first-match rule the
	// deploy root IS the match and survives into the key, so a container
	// build and a laptop produce DIFFERENT fingerprints for the same file,
	// which defeats the only thing the requirement is for.
	if got := restless.ProjectRelative("/app/src/db/users.go"); got != "src/db/users.go" {
		t.Errorf("got %q, want src/db/users.go", got)
	}
	laptop := restless.ProjectRelative("/Users/dev/proj/src/db/users.go")
	docker := restless.ProjectRelative("/app/src/db/users.go")
	render := restless.ProjectRelative("/opt/render/project/src/db/users.go")
	if laptop != docker || laptop != render {
		t.Errorf("same file, different keys: laptop=%q docker=%q render=%q",
			laptop, docker, render)
	}
}

func TestProjectRelativeNestedLayoutCollapses(t *testing.T) {
	// The accepted trade for last-match: a nested project dir collapses to
	// the innermost one. Far rarer than an /app root, and the result is
	// still machine-independent, which is the property being protected.
	if got := restless.ProjectRelative("/a/src/b/src/c.go"); got != "src/c.go" {
		t.Errorf("got %q, want src/c.go", got)
	}
}

func TestProjectRelativeFallback(t *testing.T) {
	if got := restless.ProjectRelative("/opt/weird/place/thing.go"); got != "place/thing.go" {
		t.Errorf("got %q", got)
	}
}

func TestStackStrategyKeyShape(t *testing.T) {
	// FP-040
	fp := restless.ComputeFingerprint(restless.CapturedError{
		Status: 500, Method: "GET", Route: "/users", StackTrace: goStack,
	})
	if fp.Strategy != "stack" {
		t.Fatalf("strategy = %q, want stack", fp.Strategy)
	}
	if fp.Key != "500:src/db/users.go:FindByID" {
		t.Errorf("key = %q", fp.Key)
	}
}

func TestStackStrategyIgnoresLineNumbers(t *testing.T) {
	// FP-041: adding a line above the panic must not split the group.
	shifted := strings.ReplaceAll(goStack, "users.go:12", "users.go:77")
	a := restless.ComputeFingerprint(restless.CapturedError{Status: 500, Route: "/users", StackTrace: goStack})
	b := restless.ComputeFingerprint(restless.CapturedError{Status: 500, Route: "/users", StackTrace: shifted})
	if a.Key != b.Key {
		t.Errorf("line number changed the key: %q vs %q", a.Key, b.Key)
	}
}

func TestStackStrategyNotUsedBelow500(t *testing.T) {
	// FP-010: the stack strategy is 5xx only.
	fp := restless.ComputeFingerprint(restless.CapturedError{
		Status: 400, Method: "GET", Route: "/users", StackTrace: goStack,
	})
	if fp.Strategy == "stack" {
		t.Error("stack strategy fired on a 4xx")
	}
}

func TestStackStrategyFallsThroughWithoutUserFrame(t *testing.T) {
	onlyRuntime := "goroutine 1 [running]:\nruntime/debug.Stack()\n\t/usr/local/go/src/runtime/debug/stack.go:24 +0x64\n"
	fp := restless.ComputeFingerprint(restless.CapturedError{
		Status: 500, Method: "GET", Route: "/users", StackTrace: onlyRuntime,
	})
	if fp.Strategy != "route-only" {
		t.Errorf("strategy = %q, want route-only", fp.Strategy)
	}
}

func TestTwoPanicsInDifferentFunctionsDoNotCollide(t *testing.T) {
	other := strings.ReplaceAll(goStack, "FindByID", "DeleteByID")
	other = strings.ReplaceAll(other, "db/users.go", "db/admin.go")
	a := restless.ComputeFingerprint(restless.CapturedError{Status: 500, Route: "/users", StackTrace: goStack})
	b := restless.ComputeFingerprint(restless.CapturedError{Status: 500, Route: "/users", StackTrace: other})
	if a.Key == b.Key {
		t.Errorf("distinct panics share a fingerprint: %q", a.Key)
	}
}
