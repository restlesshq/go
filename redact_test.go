package restless_test

// Regression tests for REDACT-010 name normalization.
//
// These pin a SECURITY bug, so they are spelled out natively rather than left
// to the shared vectors alone: the vectors are re-vendored wholesale on every
// spec bump, and a future re-vendor that dropped the unicode-fold cases would
// silently take the guard with it.
//
// An ASCII-only name fold is the easy mistake here, because the reference has
// always used full Unicode lowercase (PRIM-020). While this SDK implemented
// the ASCII fold, a key spelled with U+212A KELVIN SIGN did not match the
// denylist and its value was uploaded in plaintext.

import (
	"strings"
	"testing"

	restless "github.com/restlesshq/go"
)

// kelvinToken is "toKen" with U+212A KELVIN SIGN in place of the ASCII K.
// Full Unicode lowercase maps U+212A to U+006B, so this IS the denylisted
// name "token" (REDACT-012) and the value MUST be redacted.
const (
	kelvinToken  = "toKen"
	kelvinAPIKey = "x-api-Key"
	secretValue  = "supersecretvalue"
	redactedTail = "<REDACTED:16:alue>"
)

func TestKelvinSignBodyKeyIsRedacted(t *testing.T) {
	body := `{"` + kelvinToken + `":"` + secretValue + `"}`
	got := restless.RedactBody(body, "application/json", nil)
	if strings.Contains(got, secretValue) {
		t.Fatalf("SECURITY: U+212A key leaked the secret.\n  in:  %s\n  out: %s", body, got)
	}
	want := `{"` + kelvinToken + `":"` + redactedTail + `"}`
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestKelvinSignHeaderIsRedacted(t *testing.T) {
	got := restless.RedactHeaders(map[string]string{kelvinAPIKey: secretValue}, nil)
	if got[kelvinAPIKey] == secretValue {
		t.Fatalf("SECURITY: U+212A header %q leaked the secret", kelvinAPIKey)
	}
	if got[kelvinAPIKey] != redactedTail {
		t.Fatalf("expected %s, got %s", redactedTail, got[kelvinAPIKey])
	}
}

func TestKelvinSignQueryParamIsRedacted(t *testing.T) {
	// REDACT-013 reuses the body-key list, and REDACT-029 percent-decodes the
	// name before normalizing, so the escaped form has to fold the same way.
	raw := "https://x.test/a?%74%6F%E2%84%AA%65%6E=" + secretValue
	got := restless.RedactURL(raw, nil)
	if strings.Contains(got, secretValue) {
		t.Fatalf("SECURITY: U+212A query param leaked the secret.\n  in:  %s\n  out: %s", raw, got)
	}
}

func TestLongSIsNotFoldedToS(t *testing.T) {
	// The other half of REDACT-010: the rule is a lowercase FOLD, not a fuzzy
	// match. U+017F LATIN SMALL LETTER LONG S is already lowercase, so it does
	// NOT become "s" and "ſet-cookie" is not the denylisted "set-cookie".
	// Without this, an over-eager fix (casefold, or NFKC) would pass the
	// KELVIN tests above and still diverge from the reference.
	const name = "ſet-cookie"
	got := restless.RedactHeaders(map[string]string{name: "sid=abcdefgh"}, nil)
	if got[name] != "sid=abcdefgh" {
		t.Fatalf("%q must not match set-cookie; got %s", name, got[name])
	}
}

func TestDottedCapitalIUsesFullMapping(t *testing.T) {
	// PRIM-020's other special case, which now reaches name normalization too
	// because REDACT-010 shares fullLower. U+0130 FULL-lowercases to
	// "i" + U+0307, so "sessİonid" keeps a combining dot and does not match
	// "sessionid" - and the reference agrees. Go's plain strings.ToLower is
	// SIMPLE mapping and yields a bare "i", which would redact a value the
	// reference leaves alone. Same helper, same answer, in both directions.
	const name = "sessİonid"
	got := restless.RedactHeaders(map[string]string{name: "abcdefgh"}, []string{"sessionid"})
	if got[name] != "abcdefgh" {
		t.Fatalf("%q keeps a combining dot under full lowercase and must not match sessionid; got %s",
			name, got[name])
	}
}
