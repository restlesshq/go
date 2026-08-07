// Package conformance is the shared operation table behind the conformance
// driver.
//
// Both cmd/conformance (the stdio driver the cross-language harness drives)
// and vectors_test.go (the in-process replay) go through this one file, so
// it is impossible for the vectors to describe behaviour the driver does not
// exhibit. Internal: never part of the public API.
package conformance

import (
	"encoding/json"
	"fmt"
	"strings"

	restless "github.com/restlesshq/go"
)

// UnsupportedDialect marks an input this implementation's language cannot
// represent or parse. The harness records it as a skip, not a failure.
// See CONTRACT.md FP-046 and PRIM-035.
type UnsupportedDialect struct{ Msg string }

func (e UnsupportedDialect) Error() string { return e.Msg }

// --- input helpers -------------------------------------------------------

func str(in map[string]any, key string) string {
	if v, ok := in[key].(string); ok {
		return v
	}
	return ""
}

func strs(in map[string]any, key string) []string {
	raw, ok := in[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func headers(in map[string]any, key string) map[string]string {
	raw, ok := in[key].(map[string]any)
	if !ok {
		return map[string]string{}
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func num(in map[string]any, key string) int {
	switch v := in[key].(type) {
	case float64:
		return int(v)
	case json.Number:
		var n int
		fmt.Sscanf(v.String(), "%d", &n)
		return n
	}
	return 0
}

// strPtr distinguishes "absent/null" from "empty string", which HAR-011
// depends on: a nil body reports bodySize -1, an empty one reports 0.
func strPtr(in map[string]any, key string) *string {
	v, present := in[key]
	if !present || v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

// Dispatch runs one conformance operation.
func Dispatch(op string, in map[string]any) (any, error) {
	switch op {
	case "mask":
		return nilIfEmpty(restless.Mask(str(in, "apiKey"))), nil

	case "redactValue":
		return restless.RedactValue(str(in, "value")), nil
	case "redactHeaders":
		return restless.RedactHeaders(headers(in, "headers"), strs(in, "extra")), nil
	case "redactUrl":
		return restless.RedactURL(str(in, "url"), strs(in, "extra")), nil
	case "redactBody":
		body := strPtr(in, "body")
		if body == nil {
			return nil, nil
		}
		// NOT nilIfEmpty: an empty string is a VALUE here, distinct from an
		// absent body. Only a nil input maps to null.
		return restless.RedactBody(*body, str(in, "contentType"), strs(in, "extra")), nil
	case "truncateBody":
		body := strPtr(in, "body")
		if body == nil {
			return nil, nil
		}
		return restless.TruncateBody(*body, num(in, "maxBytes")), nil

	case "fingerprint":
		return opFingerprint(in)
	case "normalizeRoute":
		return restless.NormalizeRoute(str(in, "route")), nil
	case "normalizeMessage":
		return restless.NormalizeMessage(str(in, "message")), nil
	case "projectRelative":
		return restless.ProjectRelative(str(in, "file")), nil

	case "formatRequestId":
		return restless.FormatRequestID(str(in, "rawId"), str(in, "prefix")), nil
	case "stripRequestIdPrefix":
		return restless.StripRequestIDPrefix(str(in, "requestId")), nil
	case "requestIdHeaders":
		hasKey, _ := in["hasApiKey"].(bool)
		return restless.RequestIDResponseHeaders(
			str(in, "ourId"), headers(in, "incomingHeaders"), str(in, "prefix"), hasKey), nil

	case "recoverySlug":
		return restless.RecoverySlug(str(in, "method"), str(in, "path")), nil

	case "harEntry":
		return opHarEntry(in)
	}
	return nil, fmt.Errorf("unknown op: %s", op)
}

// nilIfEmpty maps Go's zero value to JSON null. The protocol represents
// absence as null, and Go has no separate "undefined" to lean on.
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func opFingerprint(in map[string]any) (any, error) {
	stack := ""
	switch v := in["stackTrace"].(type) {
	case string:
		stack = v
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		stack = strings.Join(parts, "\n")
	}
	if stack != "" && looksLikeV8(stack) {
		return nil, UnsupportedDialect{
			"unsupported stack dialect: v8 (this SDK parses Go stacks; FP-044)"}
	}

	fp := restless.ComputeFingerprint(restless.CapturedError{
		Status:          num(in, "status"),
		Method:          str(in, "method"),
		Route:           str(in, "route"),
		ResponseHeaders: headers(in, "responseHeaders"),
		ResponseBody:    in["responseBody"],
		StackTrace:      stack,
	})
	// FP-003: `reason` is prose, not contract surface.
	return map[string]string{"strategy": fp.Strategy, "key": fp.Key}, nil
}

// hasLoneSurrogateEscape reports whether raw JSON text contains a
// \uD800-\uDFFF escape that is not part of a valid surrogate PAIR.
//
// Applied to the whole incoming LINE. Rather than guess, the driver declares
// such an input out of dialect and the harness records it as skipped.
// HasLoneSurrogateEscape reports whether raw JSON text contains a
// \uD800-\uDFFF escape that is not part of a valid surrogate PAIR.
func HasLoneSurrogateEscape(s string) bool {
	for i := 0; i+5 < len(s)+1; i++ {
		if i+6 > len(s) || s[i] != '\\' || s[i+1] != 'u' {
			continue
		}
		hi, ok := parseHex4(s[i+2 : i+6])
		if !ok {
			continue
		}
		if hi >= 0xD800 && hi <= 0xDBFF {
			// A high surrogate is fine only if a low one follows immediately.
			if i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
				if lo, ok := parseHex4(s[i+8 : i+12]); ok && lo >= 0xDC00 && lo <= 0xDFFF {
					i += 11
					continue
				}
			}
			return true
		}
		if hi >= 0xDC00 && hi <= 0xDFFF {
			return true // a low surrogate with no high one before it
		}
	}
	return false
}

func parseHex4(s string) (int, bool) {
	if len(s) != 4 {
		return 0, false
	}
	value := 0
	for i := 0; i < 4; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			value = value<<4 | int(c-'0')
		case c >= 'a' && c <= 'f':
			value = value<<4 | int(c-'a'+10)
		case c >= 'A' && c <= 'F':
			value = value<<4 | int(c-'A'+10)
		default:
			return 0, false
		}
	}
	return value, true
}

func looksLikeV8(stack string) bool {
	for _, line := range strings.Split(stack, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "at ") {
			return true
		}
	}
	return false
}

func opHarEntry(in map[string]any) (any, error) {
	captured, ok := in["captured"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("harEntry: missing captured")
	}
	req, _ := captured["request"].(map[string]any)
	res, _ := captured["response"].(map[string]any)

	entry := restless.ToHarEntry(restless.CapturedRequest{
		RequestID:       str(captured, "requestId"),
		StartedAt:       str(captured, "startedAt"),
		Duration:        num(captured, "duration"),
		RoutePattern:    str(captured, "routePattern"),
		Method:          str(req, "method"),
		URL:             str(req, "url"),
		RequestHeaders:  headers(req, "headers"),
		RequestBody:     strPtr(req, "body"),
		Status:          num(res, "status"),
		ResponseHeaders: headers(res, "headers"),
		ResponseBody:    strPtr(res, "body"),
	})
	return entry, nil
}
