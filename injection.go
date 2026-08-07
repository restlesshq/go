package restless

import (
	"regexp"
	"strings"
)

// What the SDK adds to the customer's own error responses. Implements
// CONTRACT.md section 10.

var (
	slugSeparators = regexp.MustCompile(`[/{}:]+`)
	slugIllegal    = regexp.MustCompile(`[^a-zA-Z0-9-]`)
	slugDashes     = regexp.MustCompile(`-+`)
)

// RecoverySlug builds the legible slug for the dig-in URL from method plus
// route pattern: "GET /car/{id}" becomes "get-car-id" (INJECT-005).
//
// The server resolves it back to an OpenAPI operation by applying the same
// scheme, so this MUST stay in sync with recoverySlug in the app's recovery
// route (INJECT-007).
func RecoverySlug(method, path string) string {
	m := strings.ToLower(method)
	p := strings.TrimSpace(path)
	if m == "" || p == "" {
		return "unknown"
	}
	flat := slugSeparators.ReplaceAllString(p, "-")
	flat = slugIllegal.ReplaceAllString(flat, "")
	flat = slugDashes.ReplaceAllString(flat, "-")
	flat = strings.Trim(flat, "-")
	if flat == "" {
		return m
	}
	return m + "-" + flat
}

// DebugInjection is what the adapter should layer onto an error response.
type DebugInjection struct {
	Headers map[string]string
	// Mutate rewrites a parsed JSON body. Nil when nothing should change.
	Mutate func(body any) any
}

// BuildDebugInjection assembles the headers and body mutation for a 4xx/5xx
// (INJECT-001..006).
func BuildDebugInjection(status int, requestID, baseURL, prefix, recovery, method, path, docsURL string) DebugInjection {
	if status < 400 { // INJECT-001
		return DebugInjection{}
	}

	display := FormatRequestID(requestID, prefix)
	// INJECT-006. Server-learned docs origin when we have one, else the
	// configured base URL. One-batch staleness window after a domain change.
	logHost := docsURL
	if logHost == "" {
		logHost = baseURL
	}
	logURL := logHost + "/logs/" + requestID
	debugCmd := "npx api debug " + display

	slug := RecoverySlug(method, path)
	digIn := "For the accepted parameters and next steps, fetch " +
		logHost + "/p/" + requestID + "/" + slug + ".md"
	// INJECT-004. The dig-in line always ships; a cached recovery message
	// precedes it, separated by a blank line.
	recoveryText := digIn
	if recovery != "" {
		recoveryText = recovery + "\n\n" + digIn
	}

	return DebugInjection{
		Headers: map[string]string{
			"x-log-url": logURL,
			"x-debug":   debugCmd,
		},
		Mutate: func(body any) any {
			// INJECT-003. Objects only; an array or scalar body is left
			// alone because there is nowhere sensible to attach debug.
			obj, ok := body.(*jsonObject)
			if !ok {
				return body
			}
			debug := newJSONObject()
			debug.set("log", logURL)
			debug.set("cli", debugCmd)
			debug.set("recovery", recoveryText)
			obj.set("debug", debug)
			return obj
		},
	}
}

// ApplyInternalBodyMods rewrites a JSON response body. Never errors: on any
// problem the original body comes back unchanged (SAFETY-001).
func ApplyInternalBodyMods(body, contentType string, mutate func(any) any) string {
	if body == "" || mutate == nil {
		return body
	}
	if !isJSONContentType(contentType) { // INJECT-003
		return body
	}
	parsed, err := parseOrderedJSON([]byte(body))
	if err != nil {
		return body
	}
	out, err := marshalOrderedJSON(mutate(parsed))
	if err != nil {
		return body
	}
	return out
}
