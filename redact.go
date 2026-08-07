package restless

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Redaction of sensitive values. Implements CONTRACT.md section 4.
//
// Runs at the single choke point before anything enters the upload queue;
// no adapter bypasses it.

// REDACT-001. Values shorter than this get no tail preview.
const (
	tailMinLength = 8
	tailChars     = 4
)

// MaxBodyBytes is the REDACT-030 cap: 256 KiB, measured in UTF-8 bytes.
const MaxBodyBytes = 256 * 1024

// REDACT-011
var defaultHeaderDenylist = []string{
	"authorization", "cookie", "set-cookie",
	"proxy-authorization", "x-api-key", "x-auth-token",
}

// REDACT-012
var defaultBodyKeyDenylist = []string{
	"password", "pass", "pwd", "token", "secret", "apikey",
	"accesstoken", "refreshtoken", "idtoken", "sessionid",
	"ssn", "creditcard", "ccnumber", "cvv", "cvc",
}

// REDACT-013 uses the same list as REDACT-012.
var defaultQueryParamDenylist = defaultBodyKeyDenylist

// REDACT-016. Headers carrying an auth-scheme prefix. For these the scheme
// word survives so a debugger can see Bearer vs Basic vs custom at a glance;
// only the credential is replaced.
var schemePrefixHeaders = map[string]bool{
	"authorization":      true,
	"proxyauthorization": true,
}

// RedactOptions extends the built-in denylists. It can only ever ADD
// (REDACT-014); the defaults are always applied.
type RedactOptions struct {
	Headers     []string
	BodyKeys    []string
	QueryParams []string
}

// RedactValue replaces a value with the length/tail sentinel (REDACT-001).
//
// Length and tail are in CODE POINTS (REDACT-002). Using len() here would
// report 4 for a single emoji where JS reports 2 and Python reports 1.
func RedactValue(value string) string {
	n := runeLen(value)
	if n < tailMinLength {
		return fmt.Sprintf("<REDACTED:%d>", n)
	}
	return fmt.Sprintf("<REDACTED:%d:%s>", n, lastRunes(value, tailChars))
}

// normalizeName applies REDACT-010: full Unicode lowercase (PRIM-020), then
// drop - and _.
//
// Full Unicode, not an ASCII fold, and that is a SECURITY property rather
// than a cosmetic one. Normalization is what decides whether a value gets
// redacted, so the safe direction is to fold MORE aggressively: a header
// "x-api-Key" or a body key "toKen" spelled with U+212A KELVIN SIGN
// lowercases to a denylisted name and must be redacted. An ASCII-only fold
// leaves it unmatched and ships the secret in plaintext.
//
// An ASCII-only fold is the easy mistake here and every port made it once.
//
// The '-'/'_' strip stays byte-wise. Both are ASCII, and a UTF-8 byte in a
// multi-byte sequence is always >= 0x80, so no continuation byte can be
// mistaken for one.
func normalizeName(name string) string {
	lowered := fullLower(name)
	var b strings.Builder
	b.Grow(len(lowered))
	for i := 0; i < len(lowered); i++ {
		if c := lowered[i]; c != '-' && c != '_' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func buildDenySet(defaults, extra []string) map[string]bool {
	deny := make(map[string]bool, len(defaults)+len(extra))
	for _, name := range defaults {
		deny[normalizeName(name)] = true
	}
	for _, name := range extra {
		deny[normalizeName(name)] = true
	}
	return deny
}

// wsChars is the PRIM-002 whitespace set, enumerated as ESCAPES.
//
// Not a stylistic choice: Go refuses to compile a source file containing
// a literal U+FEFF anywhere but the first byte ("illegal byte order mark"),
// and the other 24 are invisible or indistinguishable from a plain space,
// so a duplicate would silently collapse the map instead of failing.
//
// Go's regexp \s is ASCII-only, narrower than this set, so the scheme split
// below scans the map rather than using a pattern.
var wsChars = map[rune]bool{
	'\t': true, '\n': true, '\v': true, '\f': true, '\r': true, ' ': true,
	'\u00a0': true, '\u1680': true, '\u2000': true, '\u2001': true, '\u2002': true, '\u2003': true, '\u2004': true,
	'\u2005': true, '\u2006': true, '\u2007': true, '\u2008': true, '\u2009': true, '\u200a': true, '\u2028': true,
	'\u2029': true, '\u202f': true, '\u205f': true, '\u3000': true, '\ufeff': true,
}

// splitAuthScheme splits "Bearer <credential>" into its three parts, or
// reports false when there is no scheme prefix to preserve (REDACT-016).
//
// An explicit scan over runes rather than a regex: the obvious pattern
// `^(\S+)(\s+)(\S.*)$` is not portable (JS's `.` excludes CR where Python's
// DOTALL includes it), and Go's `\s` is a different set again.
func splitAuthScheme(value string) (scheme, gap, credential string, ok bool) {
	runes := []rune(value)
	i := 0
	for i < len(runes) && !wsChars[runes[i]] {
		i++
	}
	// No whitespace at all, or the value starts with it: nothing to preserve.
	if i == 0 || i >= len(runes) {
		return "", "", "", false
	}
	j := i
	for j < len(runes) && wsChars[runes[j]] {
		j++
	}
	if j >= len(runes) { // whitespace but no credential after it
		return "", "", "", false
	}
	return string(runes[:i]), string(runes[i:j]), string(runes[j:]), true
}

// RedactHeaders returns a new map; it never mutates the input (REDACT-019).
func RedactHeaders(headers map[string]string, extra []string) map[string]string {
	deny := buildDenySet(defaultHeaderDenylist, extra)
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		norm := normalizeName(key)
		if !deny[norm] {
			out[key] = value
			continue
		}
		if schemePrefixHeaders[norm] {
			if scheme, gap, credential, ok := splitAuthScheme(value); ok {
				out[key] = scheme + gap + RedactValue(credential)
				continue
			}
		}
		out[key] = RedactValue(value)
	}
	return out
}

// ---------------------------------------------------------------------------
// Query strings
// ---------------------------------------------------------------------------

// REDACT-028. The RFC 3986 unreserved set, named explicitly because no two
// languages' builtins agree: net/url.QueryEscape turns a space into '+' and
// leaves a different set alone than JS encodeURIComponent or Python quote.
func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
}

func percentEncode(value string) string {
	var b strings.Builder
	for _, c := range toUTF8(value) {
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexValue(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// percentDecode decodes one query component: '+' is a space, %XX is a byte
// (REDACT-029).
//
// Iterates CODE POINTS, matching the reference. PRIM-006: the two hex digits
// are validated explicitly rather than handed to a parser, because parsers
// differ in what they accept.
func percentDecode(value string) string {
	runes := []rune(value)
	var raw []byte
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '+' {
			raw = append(raw, ' ')
			continue
		}
		if r == '%' && i+2 < len(runes) {
			hi, lo := runes[i+1], runes[i+2]
			if hi < 128 && lo < 128 && isHexDigit(byte(hi)) && isHexDigit(byte(lo)) {
				raw = append(raw, hexValue(byte(hi))<<4|hexValue(byte(lo)))
				i += 2
				continue
			}
		}
		raw = append(raw, toUTF8(string(r))...)
	}
	// Invalid UTF-8 in the decoded bytes becomes U+FFFD rather than an error.
	return string([]rune(string(raw)))
}

// RedactURL replaces denylisted query values in place (REDACT-025).
//
// Scheme, host, port, path, parameter order, separators and fragment come
// through byte for byte. Deliberately does NOT use net/url: parsing and
// re-serializing normalizes the URL in ways no two languages agree on, and
// url.Values collapses repeated parameters into one (REDACT-027).
func RedactURL(rawURL string, extra []string) string {
	deny := buildDenySet(defaultQueryParamDenylist, extra)

	q := strings.Index(rawURL, "?")
	if q == -1 {
		return rawURL
	}
	head := rawURL[:q+1]
	rest := rawURL[q+1:]

	query, tail := rest, ""
	if hash := strings.Index(rest, "#"); hash != -1 {
		query, tail = rest[:hash], rest[hash:]
	}
	if query == "" {
		return rawURL
	}

	parts := strings.Split(query, "&")
	for i, pair := range parts {
		eq := strings.Index(pair, "=")
		if eq == -1 {
			continue // not a key/value pair; leave it alone
		}
		rawKey, rawVal := pair[:eq], pair[eq+1:]
		if deny[normalizeName(percentDecode(rawKey))] {
			parts[i] = rawKey + "=" + percentEncode(RedactValue(percentDecode(rawVal)))
		}
	}
	return head + strings.Join(parts, "&") + tail
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

// containsDeniedKey walks the PARSED value, never the raw text (REDACT-021),
// so every SDK reaches the same verdict using its own JSON parser.
func containsDeniedKey(value any, deny map[string]bool) bool {
	switch v := value.(type) {
	case *jsonObject:
		for _, key := range v.keys {
			if deny[normalizeName(key)] {
				return true
			}
			if containsDeniedKey(v.vals[key], deny) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if containsDeniedKey(item, deny) {
				return true
			}
		}
	}
	return false
}

func redactJSONValue(value any, deny map[string]bool) any {
	switch v := value.(type) {
	case *jsonObject:
		out := newJSONObject()
		for _, key := range v.keys {
			val := v.vals[key]
			if deny[normalizeName(key)] {
				switch inner := val.(type) {
				case nil:
					out.set(key, nil)
				case string:
					out.set(key, RedactValue(inner))
				default:
					// REDACT-004: a non-string secret loses its shape too.
					out.set(key, "<REDACTED>")
				}
				continue
			}
			out.set(key, redactJSONValue(val, deny))
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactJSONValue(item, deny)
		}
		return out
	default:
		return value
	}
}

func isJSONContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "application/json")
}

// RedactBody redacts sensitive keys in a JSON body (REDACT-020..024).
//
// When the body carries nothing to redact the caller's ORIGINAL string comes
// back byte for byte. Re-serializing is lossy in every language and in
// different ways, and it is where SDKs diverge from each other; skipping it
// for the overwhelming majority of bodies removes the divergence rather than
// trying to specify it away.
func RedactBody(body, contentType string, extra []string) string {
	if body == "" {
		return body
	}
	if !isJSONContentType(contentType) {
		return body
	}
	parsed, err := parseOrderedJSON([]byte(body))
	if err != nil {
		return body // REDACT-024: unparseable passes through, never errors
	}
	deny := buildDenySet(defaultBodyKeyDenylist, extra)
	if !containsDeniedKey(parsed, deny) {
		return body
	}
	out, err := marshalOrderedJSON(redactJSONValue(parsed, deny))
	if err != nil {
		return body
	}
	return out
}

// TruncateBody caps a body at maxBytes UTF-8 bytes, cutting on a character
// boundary and appending the marker (REDACT-030..032).
func TruncateBody(body string, maxBytes int) string {
	if body == "" {
		return body
	}
	buf := toUTF8(body)
	if len(buf) <= maxBytes {
		return body
	}
	kept := truncateUTF8(buf, maxBytes)
	return fmt.Sprintf("%s\n[...TRUNCATED: original %d bytes]", string(kept), len(buf))
}

// compile-time assertion that json is used (parseOrderedJSON lives in
// orderedjson.go and owns the import there).
var _ = json.Number("")
