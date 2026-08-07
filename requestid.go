package restless

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
)

// Request identifiers. Implements CONTRACT.md section 6.

var (
	uuidPattern     = regexp.MustCompile(`\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z`)
	prefixedPattern = regexp.MustCompile(`\A[A-Za-z0-9]{1,7}-([\s\S]+)\z`)
)

// NewRequestID returns an RFC 4122 v4 UUID from crypto/rand.
//
// REQID-002: deliberately NOT time-ordered. Request ids appear in
// user-visible URLs and logs and must not leak ordering or timing, which
// rules out v1/v6/v7, ULID and Snowflake.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not something an observability SDK should
		// panic over, but a predictable id would be worse than none.
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// FormatRequestID applies the display prefix. REQID-004: the RAW uuid is
// what goes on the wire and into log URLs.
func FormatRequestID(rawID, prefix string) string {
	if prefix == "" {
		return rawID
	}
	return prefix + "-" + rawID
}

// StripRequestIDPrefix reverses FormatRequestID. Safe when no prefix is
// present (REQID-005).
func StripRequestIDPrefix(requestID string) string {
	m := prefixedPattern.FindStringSubmatch(requestID)
	if m != nil && uuidPattern.MatchString(m[1]) {
		return m[1]
	}
	return requestID
}

// IsValidRequestID reports whether raw is one of our ids, prefixed or not.
func IsValidRequestID(raw string) bool {
	return uuidPattern.MatchString(StripRequestIDPrefix(raw))
}

// RequestIDResponseHeaders returns the single id header for this response.
//
// REQID-010: if the incoming request already carried x-request-id we emit
// our own x-restless-id instead, so an existing chain set by a client or
// proxy is never clobbered. We never REUSE the incoming value: our id is
// always freshly minted so one UUID identifies exactly one log.
//
// REQID-011: with no API key resolved the value is the literal
// "missing-key", which the setup CLI keys off to tell "your server is up but
// RESTLESS_KEY never loaded" apart from "the request silently dropped".
func RequestIDResponseHeaders(ourID string, incoming map[string]string, prefix string, hasAPIKey bool) map[string]string {
	value := "missing-key"
	if hasAPIKey {
		value = FormatRequestID(ourID, prefix)
	}
	name := "x-request-id"
	for k, v := range incoming {
		if strings.EqualFold(k, "x-request-id") && v != "" {
			name = "x-restless-id"
			break
		}
	}
	return map[string]string{name: value}
}
