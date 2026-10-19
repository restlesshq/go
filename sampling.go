package restless

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Sampling: per-endpoint control over how much of each request is sent.
// Implements CONTRACT.md section 12.1 (SAMPLE).
//
// Everything in this file is pure. The middleware draws u once per request
// and feeds it to DecideSampling; tests and the conformance driver feed a
// fixed one.

type samplingKind uint8

const (
	modeUnset samplingKind = iota
	modeOn
	modeOff
	modeErrors
	modeRate
)

// SamplingMode is one endpoint's mode. Use SampleOn, SampleOff, SampleErrors
// or SampleRate. The zero value means "not set": as Sampling.Default it
// leaves the settings file's default in place.
type SamplingMode struct {
	kind samplingKind
	rate float64
}

var (
	// SampleOn sends every request in full. It is the default.
	SampleOn = SamplingMode{kind: modeOn}
	// SampleOff sends nothing for the endpoint, errors included.
	SampleOff = SamplingMode{kind: modeOff}
	// SampleErrors sends only responses with status >= 400.
	SampleErrors = SamplingMode{kind: modeErrors}
)

// SampleRate sends that fraction of successful requests in full and the rest
// without bodies. Errors are always sent in full. r must be in [0, 1]; it is
// quantized to a multiple of 0.0001, and anything else falls back to
// SampleOn (SAMPLE-002, SAMPLE-003).
func SampleRate(r float64) SamplingMode { return SamplingMode{kind: modeRate, rate: r} }

// String renders the mode as it is written in configuration.
func (m SamplingMode) String() string {
	switch m.kind {
	case modeOff:
		return "off"
	case modeErrors:
		return "errors"
	case modeRate:
		return strconv.FormatFloat(m.rate, 'g', -1, 64)
	}
	return "on"
}

// Rate reports the rate of a rate mode.
func (m SamplingMode) Rate() (float64, bool) { return m.rate, m.kind == modeRate }

// MarshalJSON emits the configuration spelling: a string, or a number for a
// rate.
func (m SamplingMode) MarshalJSON() ([]byte, error) {
	if m.kind == modeRate {
		return json.Marshal(m.rate)
	}
	return json.Marshal(m.String())
}

// Sampling is the configuration passed to WithSampling. It has the same
// shape as the `sampling` block in .restless/settings.json.
//
// Routes are keyed by "<METHOD> <route pattern>", e.g. "GET /pets/{id}", with
// "*" for any method. ":id" and "{id}" are the same parameter.
type Sampling struct {
	Default SamplingMode
	Routes  map[string]SamplingMode
}

// SamplingOutcome is what happens to one request (SAMPLE-030).
type SamplingOutcome string

const (
	// SamplingFull captures and uploads the request as without sampling.
	SamplingFull SamplingOutcome = "full"
	// SamplingStub uploads the request without bodies, marked sampled.
	SamplingStub SamplingOutcome = "stub"
	// SamplingDrop uploads and injects nothing.
	SamplingDrop SamplingOutcome = "drop"
)

// SamplingConfig is a merged, validated configuration. Rates are already
// quantized (SAMPLE-002).
type SamplingConfig struct {
	def    SamplingMode
	routes map[string]SamplingMode
}

// rateSteps is the quantization grid for rates (SAMPLE-002).
const rateSteps = 10000

var samplingParam = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

// rateStepsOf computes k = floor(r * 10000 + 0.5) in IEEE 754 double
// precision (SAMPLE-002).
//
// The float64 conversion is deliberate: the Go spec lets a compiler fuse
// x*y+z into one FMA instruction (arm64 does), which skips rounding the
// product. The contract specifies two roundings, as JavaScript performs
// them. A search around every half step found no rate in [0, 1] where
// fusion moves the result, but the conversion makes that a guarantee rather
// than an observation.
func rateStepsOf(r float64) float64 {
	return math.Floor(float64(r*rateSteps) + 0.5)
}

// normalizeMode validates one raw mode (SAMPLE-001..003). raw is a value as
// decoded by parseOrderedJSON, or a float64 from typed configuration. The
// second result is false for an invalid mode; the caller falls back to "on".
func normalizeMode(raw any) (SamplingMode, bool) {
	var r float64
	switch v := raw.(type) {
	case string:
		switch v {
		case "on":
			return SampleOn, true
		case "off":
			return SampleOff, true
		case "errors":
			return SampleErrors, true
		}
		return SampleOn, false
	case json.Number:
		// strconv.ParseFloat rounds correctly, as JSON.parse does. Out of
		// range comes back as +-Inf, which is rejected below like JS's
		// Infinity.
		f, err := strconv.ParseFloat(v.String(), 64)
		if err != nil && !isRangeErr(err) {
			return SampleOn, false
		}
		r = f
	case float64:
		r = v
	default:
		return SampleOn, false
	}
	if math.IsNaN(r) || math.IsInf(r, 0) || r < 0 || r > 1 {
		return SampleOn, false
	}
	steps := rateStepsOf(r)
	// A rate that rounds to 1 IS "on": one spelling, so the dashboard and
	// the hash never see two.
	if steps >= rateSteps {
		return SampleOn, true
	}
	return SamplingMode{kind: modeRate, rate: steps / rateSteps}, true
}

func isRangeErr(err error) bool {
	ne, ok := err.(*strconv.NumError)
	return ok && ne.Err == strconv.ErrRange
}

// normalizeSamplingPath applies SAMPLE-011 and checks the SAMPLE-010 path
// rule. Matching is byte-wise and every accepted byte is printable ASCII, so
// it agrees with the UTF-16 reference on every input.
func normalizeSamplingPath(path string) (string, bool) {
	p := samplingParam.ReplaceAllString(path, "{${1}}")
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	if len(p) == 0 || p[0] != '/' {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return "", false
		}
	}
	return p, true
}

// normalizeRouteKey applies SAMPLE-010: "get  /pets/:id/" becomes
// "GET /pets/{id}".
func normalizeRouteKey(key string) (string, bool) {
	trimmed := strings.Trim(key, " ")
	space := strings.IndexByte(trimmed, ' ')
	if space == -1 {
		return "", false
	}
	method := trimmed[:space]
	if !validSamplingMethod(method) {
		return "", false
	}
	path, ok := normalizeSamplingPath(strings.TrimLeft(trimmed[space:], " "))
	if !ok {
		return "", false
	}
	return asciiUpper(method) + " " + path, true
}

func validSamplingMethod(m string) bool {
	if m == "*" {
		return true
	}
	if m == "" {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

// asciiUpper uppercases a-z only. strings.ToUpper would also map non-ASCII
// letters, which no other SDK does to a method.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

type samplingSource struct {
	name  string
	value any // parseOrderedJSON output, or nil for absent
}

// normalizeSampling merges the sources in order, later winning
// (SAMPLE-013, SAMPLE-014), and validates every value. It never panics:
// bad input degrades to "on", or is ignored for a bad key, and is described
// in the returned warnings for the debug log.
func normalizeSampling(sources ...samplingSource) (SamplingConfig, []string) {
	var warnings []string
	cfg := SamplingConfig{def: SampleOn, routes: map[string]SamplingMode{}}

	for _, src := range sources {
		if src.value == nil {
			continue
		}
		obj, ok := src.value.(*jsonObject)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("sampling (%s): expected an object, ignored", src.name))
			continue
		}
		if def, present := obj.get("default"); present {
			mode, ok := normalizeMode(def)
			if !ok {
				warnings = append(warnings, fmt.Sprintf(
					"sampling.default (%s): invalid mode %s, using \"on\"", src.name, describeRaw(def)))
			}
			cfg.def = mode
		}

		routes, present := obj.get("routes")
		if !present || routes == nil {
			continue
		}
		robj, ok := routes.(*jsonObject)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("sampling.routes (%s): expected an object, ignored", src.name))
			continue
		}
		for _, rawKey := range robj.keys {
			key, ok := normalizeRouteKey(rawKey)
			if !ok {
				warnings = append(warnings, fmt.Sprintf(
					"sampling.routes (%s): invalid route key %q, ignored", src.name, rawKey))
				continue
			}
			rawMode := robj.vals[rawKey]
			mode, ok := normalizeMode(rawMode)
			if !ok {
				warnings = append(warnings, fmt.Sprintf(
					"sampling.routes[%q] (%s): invalid mode %s, using \"on\"", rawKey, src.name, describeRaw(rawMode)))
			}
			cfg.routes[key] = mode
		}
	}
	return cfg, warnings
}

func describeRaw(v any) string {
	if out, err := marshalOrderedJSON(v); err == nil {
		return out
	}
	return fmt.Sprintf("%v", v)
}

// parseSamplingJSON decodes one raw `sampling` value with key order
// preserved, which SAMPLE-013 needs. Empty input is absent; unparseable input
// is reported and treated as absent.
func parseSamplingJSON(name string, raw []byte) (samplingSource, string) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return samplingSource{name: name}, ""
	}
	value, err := parseOrderedJSON(raw)
	if err != nil {
		return samplingSource{name: name}, fmt.Sprintf("sampling (%s): unparseable, ignored", name)
	}
	return samplingSource{name: name, value: value}, ""
}

// toSource converts typed configuration into the same shape the settings
// file decodes to, so both go through one validator.
//
// A Go map has no order, so routes are taken in sorted key order: when two
// keys normalize to the same one (SAMPLE-013), the later in byte order wins.
// That is deterministic, which map iteration order would not be.
func (s *Sampling) toSource() samplingSource {
	if s == nil {
		return samplingSource{name: "code"}
	}
	obj := newJSONObject()
	if s.Default.kind != modeUnset {
		obj.set("default", s.Default.raw())
	}
	if s.Routes != nil {
		keys := make([]string, 0, len(s.Routes))
		for k := range s.Routes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		routes := newJSONObject()
		for _, k := range keys {
			routes.set(k, s.Routes[k].raw())
		}
		obj.set("routes", routes)
	}
	return samplingSource{name: "code", value: obj}
}

// raw is the configuration-file value for a typed mode. An unset mode is
// null, which is invalid and falls back to "on".
func (m SamplingMode) raw() any {
	switch m.kind {
	case modeUnset:
		return nil
	case modeRate:
		return m.rate
	}
	return m.String()
}

// NormalizeSamplingJSON merges a settings-file and a code configuration,
// each raw JSON (nil, empty or `null` meaning absent), exactly as a client
// does (SAMPLE-014). It never fails: the second result lists what was
// rejected. Used by the conformance driver.
func NormalizeSamplingJSON(settings, code []byte) (SamplingConfig, []string) {
	s, w1 := parseSamplingJSON("settings", settings)
	c, w2 := parseSamplingJSON("code", code)
	var warnings []string
	for _, w := range []string{w1, w2} {
		if w != "" {
			warnings = append(warnings, w)
		}
	}
	cfg, more := normalizeSampling(s, c)
	return cfg, append(warnings, more...)
}

// Default is the mode for requests no route matches.
func (c SamplingConfig) Default() SamplingMode { return c.def }

// RouteKeys returns the normalized route keys, sorted by bytes.
func (c SamplingConfig) RouteKeys() []string {
	keys := make([]string, 0, len(c.routes))
	for k := range c.routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Route returns the mode stored under a normalized key.
func (c SamplingConfig) Route(key string) (SamplingMode, bool) {
	m, ok := c.routes[key]
	return m, ok
}

// Mode resolves one request's mode (SAMPLE-020..022). route is the matched
// pattern, "" when the router reported none.
func (c SamplingConfig) Mode(method, route string) SamplingMode {
	if route != "" {
		if path, ok := normalizeSamplingPath(route); ok {
			if m, ok := c.routes[asciiUpper(method)+" "+path]; ok {
				return m
			}
			if m, ok := c.routes["* "+path]; ok {
				return m
			}
		}
	}
	return c.def
}

// Canonical is the SAMPLE-040 text form. false for the default
// configuration, which has none (SAMPLE-041).
func (c SamplingConfig) Canonical() (string, bool) {
	if (c.def.kind == modeOn || c.def.kind == modeUnset) && len(c.routes) == 0 {
		return "", false
	}
	var b strings.Builder
	b.WriteString("default\t" + modeToken(c.def) + "\n")
	// Keys are printable ASCII (SAMPLE-010), so sort.Strings is byte order
	// and matches every other SDK.
	for _, k := range c.RouteKeys() {
		b.WriteString(k + "\t" + modeToken(c.routes[k]) + "\n")
	}
	return b.String(), true
}

// Hash is the lowercase-hex SHA-256 of the canonical form, or "" for the
// default configuration (SAMPLE-040, SAMPLE-041).
func (c SamplingConfig) Hash() string {
	canonical, ok := c.Canonical()
	if !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// modeToken renders a mode for the canonical form. A rate is built from its
// integer step count, never from float formatting: 0.1 is "0.1000".
func modeToken(m SamplingMode) string {
	if m.kind != modeRate {
		return m.String()
	}
	steps := int(rateStepsOf(m.rate))
	return fmt.Sprintf("0.%04d", steps)
}

// DecideSampling is the outcome for a mode and a final status (SAMPLE-030,
// SAMPLE-031). u is uniform in [0, 1), drawn once per request.
func DecideSampling(mode SamplingMode, status int, u float64) SamplingOutcome {
	if mode.kind == modeOff {
		return SamplingDrop
	}
	isError := status >= 400
	if mode.kind == modeErrors {
		if isError {
			return SamplingFull
		}
		return SamplingDrop
	}
	if mode.kind != modeRate || isError {
		return SamplingFull
	}
	if u < mode.rate {
		return SamplingFull
	}
	return SamplingStub
}
