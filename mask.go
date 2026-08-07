package restless

import (
	"crypto/sha512"
	"encoding/base64"
	"regexp"
	"strings"
)

// Masking of end-user API keys. Implements CONTRACT.md section 3.
//
// This is the lookup key the ingest and dashboard index on, so it must be
// byte-identical to every other SDK and to the server's own mask().

// MASK-011. Setup-time placeholders that must not become real-looking masks.
// Matched exactly and case-sensitively.
var placeholderKeys = map[string]bool{
	"API_KEY_HERE": true,
	"YOUR_API_KEY": true,
	"YOUR_KEY":     true,
	"REPLACE_ME":   true,
}

// PRIM-005: fully anchored. Go's $ matches only at end of text (no \n
// leniency like Python's), but \A..\z is spelled out so the intent survives
// a future refactor.
var redactedSentinel = regexp.MustCompile(`\A<REDACTED:[0-9]+(?::[^>]*)?>\z`)

// Mask hashes an end-user API key into the shared cross-SDK format:
//
//	sha512-<standard base64 of sha512(utf8(key))>?<last 4 code points>
//
// Returns "" when there is no usable key.
//
// Pass the raw header value straight through. Never substitute a placeholder
// such as "anonymous": its last 4 characters would become the mask tail and
// cluster unrelated callers together (MASK-010).
func Mask(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	if placeholderKeys[apiKey] {
		return ""
	}
	// MASK-012 / MASK-013. Idempotent for our own output, and a value the
	// SDK already redacted passes through rather than being hashed.
	if strings.HasPrefix(apiKey, "sha512-") {
		return apiKey
	}
	if redactedSentinel.MatchString(apiKey) {
		return apiKey
	}

	// MASK-004. Hash the UTF-8 encoding, with invalid sequences mapped to
	// U+FFFD so the digest matches Node's Buffer.from(s, "utf8") (PRIM-013).
	sum := sha512.Sum512(toUTF8(apiKey))

	// MASK-003. STANDARD base64 with padding, not base64.RawURLEncoding.
	digest := base64.StdEncoding.EncodeToString(sum[:])

	// MASK-006. Last 4 CODE POINTS. apiKey[len(apiKey)-4:] would slice bytes
	// and split a multi-byte character.
	return "sha512-" + digest + "?" + lastRunes(apiKey, 4)
}
