package restless

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// An order-preserving, precision-preserving JSON representation.
//
// This file is the price of admission for Go, and it is why porting to Go
// was worth doing: encoding/json violates three separate contract
// requirements by default, and all three fail SILENTLY.
//
//  1. PRIM-031 (key order). Unmarshalling into map[string]any loses order,
//     and Marshal then re-emits keys SORTED. A redacted body would come back
//     with its fields rearranged, matching no other SDK.
//
//  2. PRIM-033 (no lossy round trips). Numbers decode to float64, so an
//     int64 id above 2^53 is silently truncated - the same corruption the
//     REDACT-020 passthrough was added to eliminate in the reference.
//     json.Number keeps the literal text instead.
//
//  3. PRIM-032 (literal UTF-8). Marshal HTML-escapes <, > and & by default,
//     so the redaction sentinel `<REDACTED:14:ter2>` would go on the wire as
//     `<REDACTED:14:ter2>`. The dashboard pattern-matches that
//     sentinel (REDACT-003), so this would break the UI for Go users only.
//
// Only bodies that actually contain a secret are ever re-serialized
// (REDACT-020), so this path is rare - but when it runs it has to be right.

// jsonObject is a JSON object that remembers the order its keys arrived in.
type jsonObject struct {
	keys []string
	vals map[string]any
}

func newJSONObject() *jsonObject {
	return &jsonObject{vals: map[string]any{}}
}

func (o *jsonObject) set(key string, val any) {
	if _, seen := o.vals[key]; !seen {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = val
}

func (o *jsonObject) get(key string) (any, bool) {
	v, ok := o.vals[key]
	return v, ok
}

// parseOrderedJSON decodes into the representation above.
//
// Uses the token stream rather than Unmarshal because Unmarshal has already
// thrown away the ordering and the number text by the time it hands anything
// back.
func parseOrderedJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	value, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	// Reject trailing content, so "{}garbage" is treated as unparseable and
	// passes through untouched rather than being silently accepted.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing content after JSON value")
	}
	return value, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return parseFromToken(dec, tok)
}

func parseFromToken(dec *json.Decoder, tok json.Token) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := newJSONObject()
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj.set(key, val)
			}
			if _, err := dec.Token(); err != nil { // closing }
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // closing ]
				return nil, err
			}
			return arr, nil
		}
		return nil, errors.New("unexpected delimiter")
	default:
		// string, json.Number, bool, or nil - all kept as-is.
		return tok, nil
	}
}

// marshalOrderedJSON writes the value back out under PRIM-030 (compact
// separators), PRIM-031 (insertion order) and PRIM-032 (literal UTF-8).
func marshalOrderedJSON(value any) (string, error) {
	var b strings.Builder
	if err := writeJSONValue(&b, value); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeJSONValue(b *strings.Builder, value any) error {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJSONString(b, v)
	case json.Number:
		// The literal text as it appeared in the input. This is what keeps
		// 9007199254740993 exact and `1.0` rendered as `1.0`.
		b.WriteString(v.String())
	case float64:
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	case int:
		b.WriteString(strconv.Itoa(v))
	case int64:
		b.WriteString(strconv.FormatInt(v, 10))
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJSONValue(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *jsonObject:
		b.WriteByte('{')
		for i, key := range v.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, key)
			b.WriteByte(':')
			if err := writeJSONValue(b, v.vals[key]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		// Anything else came from our own code, not from parsed input, so
		// fall back to the stdlib with HTML escaping disabled.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return err
		}
		b.Write(bytes.TrimRight(buf.Bytes(), "\n"))
	}
	return nil
}

// writeJSONString escapes exactly what JSON.stringify escapes: the quote,
// the backslash, and control characters below U+0020. Everything else,
// including all non-ASCII, is emitted literally (PRIM-032).
//
// Notably it does NOT escape <, > or & - see the header comment.
func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				b.WriteString(`\u`)
				const hex = "0123456789abcdef"
				b.WriteByte('0')
				b.WriteByte('0')
				b.WriteByte(hex[(r>>4)&0xF])
				b.WriteByte(hex[r&0xF])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// marshalCompact is the wire-payload encoder: compact, no HTML escaping.
// Used for anything built from our own structs, where field order is fixed
// by the struct definition rather than by map iteration.
func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
