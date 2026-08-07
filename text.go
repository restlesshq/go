package restless

import (
	"strings"
	"unicode/utf8"
)

// Text handling that matches the reference implementation exactly.
//
// This file exists because Go indexes strings by BYTE, where JavaScript
// indexes by UTF-16 code unit and Python by code point. The contract counts
// in code points (PRIM-010) and in UTF-8 bytes (PRIM-011), and never in the
// host language's native unit, so every count and slice in this SDK goes
// through a helper here rather than using len() or s[a:b] directly.
//
//	"🙂"            len() == 4      runeLen() == 1      utf8Len() == 4
//	"日本語"          len() == 9      runeLen() == 3      utf8Len() == 9
//
// Using len() for the redaction sentinel would report 4 for a single emoji
// where JS reports 2 and Python reports 1 - three SDKs, three answers, for
// the same secret.

// runeLen counts Unicode code points (PRIM-010).
func runeLen(s string) int {
	return utf8.RuneCountInString(s)
}

// utf8Len counts UTF-8 bytes (PRIM-011).
//
// Go strings are arbitrary byte slices and may hold invalid UTF-8, so this
// is not always the same as the length of the re-encoded runes. toUTF8
// normalizes that case; see PRIM-013.
func utf8Len(s string) int {
	return len(toUTF8(s))
}

// lastRunes returns the final n code points, never splitting a character
// (PRIM-012). Go cannot produce an unpaired surrogate the way JS can, but a
// naive s[len(s)-4:] would still slice into the middle of a multi-byte
// sequence and yield a broken string.
func lastRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return string(runes)
	}
	return string(runes[len(runes)-n:])
}

// toUTF8 encodes to UTF-8, mapping anything that is not a valid encoding to
// U+FFFD (PRIM-013).
//
// Go has no surrogates to worry about - a Go string is bytes, and []rune
// conversion already maps each invalid byte to utf8.RuneError. That happens
// to be exactly the behaviour the contract wants, and exactly what Node's
// Buffer.from(s, "utf8") does with an unpaired surrogate. It is Python that
// needs the explicit work here, because its "replace" error handler emits a
// one-byte '?' on encode instead.
//
// The fast path matters: this is called for every captured body.
func toUTF8(s string) []byte {
	if utf8.ValidString(s) {
		return []byte(s)
	}
	return []byte(string([]rune(s)))
}

// truncateUTF8 cuts b to at most maxBytes, backing off to the nearest
// character boundary so the kept prefix is always well-formed (REDACT-031).
func truncateUTF8(b []byte, maxBytes int) []byte {
	if len(b) <= maxBytes {
		return b
	}
	end := maxBytes
	// Walk back off any UTF-8 continuation byte (0b10xxxxxx).
	for end > 0 && b[end]&0xC0 == 0x80 {
		end--
	}
	return b[:end]
}

// fullLower applies Unicode FULL lowercase mapping (PRIM-020).
//
// strings.ToLower is SIMPLE case mapping, which is not the same thing and
// diverges from both other SDKs:
//
//	         "\u0130"  (LATIN CAPITAL LETTER I WITH DOT ABOVE)
//	JS       -> "i" + U+0307   (2 code points, full mapping)
//	Python   -> "i" + U+0307   (2 code points, full mapping)
//	Go       -> "i"            (1 code point,  simple mapping)
//
// That one character changes a fingerprint: the combining dot is stripped as
// punctuation, leaving a bare "i" that the length filter then drops, so JS
// and Python key on "stanbul" where a naive Go port keys on "istanbul".
//
// U+0130 is the ONLY unconditional lowercase special case in Unicode's
// SpecialCasing data; the rest are locale-specific (tr, az, lt), which
// PRIM-020 excludes. So handling it explicitly is the whole of the gap.
//
// Final_Sigma is deliberately NOT implemented. The reference lowercases a
// word-final capital sigma to U+03C2 where strings.ToLower gives U+03C3, but
// PRIM-021 records that difference as non-normative and unobservable through
// every algorithm in the contract: FP-020 step 6 replaces both sigma forms
// with a space before either can reach a token (Greek is not in WORD), and no
// sigma folds into an ASCII denylist name for REDACT-010. Implementing it
// would be dead code.
//
// Used for both message normalization (FP-020) and denylist name
// normalization (REDACT-010): one fold, used everywhere, per REDACT-010.
func fullLower(s string) string {
	if strings.ContainsRune(s, '\u0130') {
		s = strings.ReplaceAll(s, "\u0130", "i\u0307")
	}
	return strings.ToLower(s)
}
