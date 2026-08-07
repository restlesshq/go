package restless

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// Stable identifiers for HTTP error responses. Implements CONTRACT.md
// section 5.
//
// The SDK computes a fingerprint at capture time and ships it; the ingest
// stores it, the dashboard groups by it, and a customer attaches a recovery
// message to a group. Nothing downstream re-derives it, so every SDK must
// agree exactly.
//
// Regex note: Go's regexp is RE2, which has no lookahead, lookbehind or
// backreferences (PRIM-004). Every pattern the contract defines was written
// to avoid them, so this file is a direct transliteration - normalizeRoute
// in particular is a whole-segment test rather than a scan, which is exactly
// why it ports at all.

// Fingerprint is the identity of an error response.
type Fingerprint struct {
	Strategy string `json:"strategy"`
	Key      string `json:"key"`
	// Reason is human-facing prose and explicitly NOT contract surface
	// (FP-003); it is never compared for conformance.
	Reason string `json:"reason"`
}

// CapturedError is the input to Fingerprint computation.
type CapturedError struct {
	Status          int
	Method          string
	Route           string
	ResponseHeaders map[string]string
	ResponseBody    any
	StackTrace      string
}

var codeFields = []string{"code", "error_code", "errorCode", "type"}

var nestedCodePaths = [][]string{
	{"error", "code"},
	{"error", "type"},
	{"error", "error_code"},
}

// FP-015. A code must look like an identifier, not a sentence or a UUID.
var codePattern = regexp.MustCompile(`\A[a-zA-Z][a-zA-Z0-9_.\-]*\z`)

// FP-030. Whole-segment tests, fully anchored.
var (
	segUUID    = regexp.MustCompile(`\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z`)
	segNumeric = regexp.MustCompile(`\A[0-9]+\z`)
	segLongHex = regexp.MustCompile(`\A[0-9a-fA-F]{16,}\z`)
)

// FP-020 steps 2 through 7. The whitespace and word classes are spelled out
// rather than using \s and \w: Go's are ASCII-only, which is right for \w
// and wrong for \s (PRIM-001, PRIM-002).
//
// Written as RAW string literals (backticks) so the escapes reach RE2
// verbatim: `\x{00a0}` is regex syntax, not Go string syntax, and in an
// interpreted literal it is a compile error.
const (
	wsClass   = `\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`
	wordClass = `A-Za-z0-9_`
)

var (
	reURL         = regexp.MustCompile(`https?://[^` + wsClass + `]+`)
	reEmail       = regexp.MustCompile(`[^` + wsClass + `]+@[^` + wsClass + `]+\.[^` + wsClass + `]+`)
	reQuoted      = regexp.MustCompile("['\"`][^'\"`]*['\"`]")
	reDigitWord   = regexp.MustCompile(`\b[` + wordClass + `-]*[0-9][` + wordClass + `-]*\b`)
	rePunctuation = regexp.MustCompile(`[^` + wordClass + wsClass + `-]`)
	reWSRun       = regexp.MustCompile(`[` + wsClass + `]+`)
)

// FP-042
var projectDirPattern = regexp.MustCompile(`/(?:src|lib|app|api|routes|controllers|handlers)/.+$`)

// FP-044. Go stack frames from runtime/debug.Stack() look like:
//
//	github.com/acme/proj/db.FindByID(0x14000112000, ...)
//		/Users/dev/proj/src/db/users.go:12 +0x1c
//
// so the function is on one line and the file on the next.
var goFrameFile = regexp.MustCompile(`^\s+(\S+\.go):\d+`)

// Frames that are not user code. The Node reference skips node_modules,
// node:internal and its own package; these are the Go equivalents.
//
// The SDK's own frames are matched by package prefix WITH the trailing
// separator. Without it, "github.com/restlesshq/go" also matches
// "github.com/restlesshq/go_test", so the SDK's own test suite would have
// every frame skipped and silently fall through to route-only.
var skipFrameFuncMarkers = []string{
	"runtime/debug.Stack",
	"runtime.gopanic",
}

// sdkDir is the directory this package's source lives in, resolved once at
// init from the compiler-recorded path.
//
// The SDK's own frames MUST be matched by file, not by function name. Go
// renames closures when it inlines them, and the enclosing package wins:
// the middleware's deferred recover shows up as
//
//	github.com/restlesshq/go_test.TestX.(*Client).Middleware.func6.func7.1
//	main.main.(*Client).Middleware.func1.1
//
// depending on who instantiated it. A "github.com/restlesshq/go." prefix
// match misses both, so a panic fingerprinted to the SDK's own middleware
// instead of the customer's panicking function - which would have collapsed
// every panic in the process into one group. The FILE path is stable.
var sdkDir = func() string {
	if _, file, _, ok := runtime.Caller(0); ok {
		if idx := strings.LastIndex(file, "/"); idx != -1 {
			return file[:idx+1]
		}
	}
	return ""
}()

func looksLikeCode(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" || runeLen(s) > 64 {
		return "", false
	}
	if !codePattern.MatchString(s) {
		return "", false
	}
	return s, true
}

// FP-017. Header names are case-insensitive.
func readHeaderCode(headers map[string]string) (string, bool) {
	for name, value := range headers {
		if strings.EqualFold(name, "x-restless-error-code") {
			return looksLikeCode(value)
		}
	}
	return "", false
}

// bodyField reads a field from either representation the body may be in:
// the ordered form from our own parser, or a plain map when a caller built
// the value in Go.
func bodyField(body any, key string) (any, bool) {
	switch v := body.(type) {
	case *jsonObject:
		return v.get(key)
	case map[string]any:
		val, ok := v[key]
		return val, ok
	}
	return nil, false
}

// FP-016. Field names matched EXACTLY, unlike redaction keys.
func readBodyCode(body any) (string, bool) {
	for _, field := range codeFields {
		if val, ok := bodyField(body, field); ok {
			if code, ok := looksLikeCode(val); ok {
				return code, true
			}
		}
	}
	for _, path := range nestedCodePaths {
		var cursor any = body
		for _, part := range path {
			val, ok := bodyField(cursor, part)
			if !ok {
				cursor = nil
				break
			}
			cursor = val
		}
		if code, ok := looksLikeCode(cursor); ok {
			return code, true
		}
	}
	return "", false
}

// ProjectRelative makes a source path machine-independent (FP-042).
func ProjectRelative(file string) string {
	if m := projectDirPattern.FindString(file); m != "" {
		return m[1:]
	}
	parts := strings.Split(file, "/")
	if len(parts) <= 2 {
		return strings.Join(parts, "/")
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

// TopUserFrame returns the frame nearest the throw site that is not vendor
// or runtime code (FP-043, FP-044).
//
// Walks FORWARDS. Go's debug.Stack() puts the innermost frame first, like a
// v8 stack and unlike a Python traceback - FP-043 is a semantic requirement
// ("nearest the throw site"), not a positional one, and the direction has to
// be checked per language. Walking backwards here would return net/http's
// conn.serve for every panic in the process, collapsing every 500 into one
// fingerprint group.
func TopUserFrame(stack string) (file, fn string, ok bool) {
	if stack == "" {
		return "", "", false
	}
	lines := strings.Split(stack, "\n")
	lastFunc := ""
	for _, line := range lines {
		if m := goFrameFile.FindStringSubmatch(line); m != nil {
			if skipFrameFile(m[1]) || skipFrameFunc(lastFunc) {
				lastFunc = ""
				continue
			}
			name := funcName(lastFunc)
			if name == "" {
				name = "anonymous" // FP-045
			}
			return ProjectRelative(m[1]), name, true
		}
		// Not a file line, so it is the function line for the frame below.
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "\t") {
			lastFunc = strings.TrimSpace(line)
		} else if strings.HasPrefix(line, "goroutine ") {
			lastFunc = ""
		}
	}
	return "", "", false
}

// goroot is resolved once. Matching the standard library by its install
// path is portable; hardcoding "/usr/local/go" is not - a Homebrew Go lives
// under /opt/homebrew, and a CI image somewhere else again.
var goroot = runtime.GOROOT()

func skipFrameFile(file string) bool {
	if goroot != "" && strings.HasPrefix(file, goroot) {
		return true
	}
	if sdkDir == "" || !strings.HasPrefix(file, sdkDir) {
		return false
	}
	// A _test.go file in the SDK's own directory is standing in for consumer
	// code, not shipping as SDK code, so it must NOT be skipped - otherwise
	// this package cannot test its own panic capture at all. A real consumer
	// never has files under sdkDir, so the carve-out cannot affect them.
	return !strings.HasSuffix(file, "_test.go")
}

// funcName reduces a Go stack function line to the symbol within its
// package: "github.com/acme/proj/db.FindByID(0x...)" becomes "FindByID",
// "main.handler.func1" becomes "handler.func1".
//
// Taking only the text after the LAST dot looked right until a closure
// appeared: "Middleware.func1.1" reduced to "1", which is not a function
// name and groups nothing usefully.
func funcName(line string) string {
	name := line
	if idx := strings.Index(name, "("); idx != -1 && !strings.HasPrefix(name, "(") {
		name = name[:idx]
	}
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		name = name[idx+1:] // drop the package path
	}
	if idx := strings.Index(name, "."); idx != -1 {
		name = name[idx+1:] // drop the package name
	}
	return strings.TrimSuffix(name, "(...)")
}

func skipFrameFunc(fn string) bool {
	for _, marker := range skipFrameFuncMarkers {
		if strings.Contains(fn, marker) {
			return true
		}
	}
	return false
}

// NormalizeRoute replaces id-like path segments with :id (FP-030..032).
func NormalizeRoute(route string) string {
	if route == "" {
		return "/"
	}
	segments := strings.Split(route, "/")
	// FP-031: index 0 is the text BEFORE the first slash and is never
	// normalized. Preserved deliberately so stored fingerprints stay stable.
	for i := 1; i < len(segments); i++ {
		seg := segments[i]
		if segUUID.MatchString(seg) || segNumeric.MatchString(seg) || segLongHex.MatchString(seg) {
			segments[i] = ":id"
		}
	}
	return strings.Join(segments, "/")
}

// NormalizeMessage applies the FP-020 steps in exactly the contract's order.
func NormalizeMessage(msg string) string {
	if msg == "" {
		return ""
	}
	// PRIM-020: Unicode FULL lowercase (see text.go fullLower). Since
	// This is the SDK's only fold -
	// denylist name normalization goes through the same helper.
	s := fullLower(msg)
	s = reURL.ReplaceAllString(s, " ")
	s = reEmail.ReplaceAllString(s, " ")
	s = reQuoted.ReplaceAllString(s, " ")
	s = reDigitWord.ReplaceAllString(s, " ")
	s = rePunctuation.ReplaceAllString(s, " ")
	s = reWSRun.ReplaceAllString(s, " ")
	s = strings.TrimFunc(s, func(r rune) bool { return wsChars[r] })

	var tokens []string
	for _, tok := range strings.Split(s, " ") {
		if runeLen(tok) > 1 {
			tokens = append(tokens, tok)
		}
		if len(tokens) == 6 {
			break
		}
	}
	return strings.Join(tokens, "-")
}

// FP-018
func extractMessage(body any) string {
	if body == nil {
		return ""
	}
	if s, ok := body.(string); ok {
		return s
	}
	if val, ok := bodyField(body, "message"); ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	nested, ok := bodyField(body, "error")
	if !ok {
		return ""
	}
	if s, ok := nested.(string); ok {
		return s
	}
	if val, ok := bodyField(nested, "message"); ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// ComputeFingerprint runs the FP-010 strategy ladder; the first strategy to
// yield a key wins.
func ComputeFingerprint(err CapturedError) Fingerprint {
	method := err.Method
	if method == "" {
		method = "GET" // FP-011
	}

	// FP-012, FP-013. 404 is intercepted before the code strategies: a
	// generic not_found code is identical on every route, so grouping 404s
	// by code is useless for recovery. The two buckets need opposite advice.
	if err.Status == 404 {
		norm := ""
		if err.Route != "" {
			norm = NormalizeRoute(err.Route)
		}
		if strings.ContainsAny(norm, ":{") {
			return Fingerprint{
				Strategy: "resource",
				Key:      "404:resource",
				Reason:   fmt.Sprintf("404 on a parameterized route (%s %s); the addressed resource was not found", method, norm),
			}
		}
		reason := "404 on a path that matched no route; the endpoint does not exist"
		if norm != "" {
			reason = fmt.Sprintf("404 on %s %s; no resource at this path", method, norm)
		}
		return Fingerprint{Strategy: "endpoint", Key: "404:endpoint", Reason: reason}
	}

	if code, ok := readHeaderCode(err.ResponseHeaders); ok {
		return Fingerprint{
			Strategy: "header",
			Key:      fmt.Sprintf("%d:%s", err.Status, code),
			Reason:   fmt.Sprintf("x-restless-error-code header: %q", code),
		}
	}

	if code, ok := readBodyCode(err.ResponseBody); ok {
		return Fingerprint{
			Strategy: "body-code",
			Key:      fmt.Sprintf("%d:%s", err.Status, code),
			Reason:   fmt.Sprintf("code field in body: %q", code),
		}
	}

	if err.Status >= 500 && err.StackTrace != "" {
		if file, fn, ok := TopUserFrame(err.StackTrace); ok {
			return Fingerprint{
				Strategy: "stack",
				Key:      fmt.Sprintf("%d:%s:%s", err.Status, file, fn),
				Reason:   fmt.Sprintf("top user frame: %s in %s", fn, file),
			}
		}
	}

	route := NormalizeRoute(err.Route)
	if msg := NormalizeMessage(extractMessage(err.ResponseBody)); msg != "" {
		return Fingerprint{
			Strategy: "message",
			Key:      fmt.Sprintf("%d:%s:%s:%s", err.Status, method, route, msg),
			Reason:   fmt.Sprintf("message normalized to %q", msg),
		}
	}

	return Fingerprint{
		Strategy: "route-only",
		Key:      fmt.Sprintf("%d:%s:%s", err.Status, method, route),
		Reason:   "no usable code or message; falling back to status + route",
	}
}
