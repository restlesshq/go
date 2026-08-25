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

// DebugInjection is what the adapter should layer onto a response.
type DebugInjection struct {
	Headers map[string]string
	// Mutate rewrites a parsed JSON body. Nil when nothing should change.
	Mutate func(body any) any
}

// BuildDebugInjection assembles the debug headers, and on a 4xx/5xx the body
// mutation as well (INJECT-001..006).
//
// portalURL is the project's public portal origin, published by the server.
// It is NOT the ingest base URL, which serves /v1/* and would 404 both paths,
// and there is deliberately no fallback to it: with no portal origin we emit
// x-debug alone. A caller cannot tell a broken URL from a missing one, and one
// fetched 404 teaches an agent to stop following the link (INJECT-006).
// DebugHeaders are the debug response headers (INJECT-002). They ship on every
// status, so an adapter must be able to set them before it commits a 2xx
// header block, without knowing anything else about the response.
//
// x-log-url is omitted with no portal origin; x-debug carries no URL, so it
// always ships.
func DebugHeaders(requestID, prefix, portalURL string) map[string]string {
	out := map[string]string{"x-debug": "npx api debug " + FormatRequestID(requestID, prefix)}
	if portalURL != "" {
		out["x-log-url"] = portalURL + "/logs/" + requestID
	}
	return out
}

func BuildDebugInjection(status int, requestID, prefix, recovery, method, path, portalURL string) DebugInjection {
	headers := DebugHeaders(requestID, prefix, portalURL)

	// INJECT-001. The body object is 4xx/5xx only: a successful body is the
	// caller's data, not ours to reshape. With no portal origin there is no
	// URL to put in one either (INJECT-006).
	if status < 400 || portalURL == "" {
		return DebugInjection{Headers: headers}
	}

	debugCmd := headers["x-debug"]
	logURL := headers["x-log-url"]

	slug := RecoverySlug(method, path)
	digIn := "For the accepted parameters and next steps, fetch " +
		portalURL + "/p/" + requestID + "/" + slug + ".md"
	// INJECT-004. The dig-in line always ships; a cached recovery message
	// precedes it, separated by a blank line.
	recoveryText := digIn
	if recovery != "" {
		recoveryText = recovery + "\n\n" + digIn
	}

	return DebugInjection{
		Headers: headers,
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
