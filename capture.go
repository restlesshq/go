package restless

import (
	"encoding/json"
	"net/http"
	"time"
)

// The capture engine: the single choke point every adapter goes through.
// Implements CONTRACT.md sections 10, 11 and 13.

// RequestInfo is what the setup callback receives.
//
// It carries the live *http.Request, so a caller can read anything their
// middleware attached (context values, session, parsed auth) exactly as they
// normally would.
type RequestInfo struct {
	Request *http.Request
	// Route is the templated route pattern when the adapter could determine
	// one, e.g. "/pets/{id}".
	Route string
}

// Header is a convenience for the common case of reading one header.
func (r *RequestInfo) Header(name string) string {
	if r.Request == nil {
		return ""
	}
	return r.Request.Header.Get(name)
}

// NowISO formats the current time per PRIM-040: exactly three fractional
// digits and a literal Z.
//
// Go's time.RFC3339Nano would emit nanoseconds AND strip trailing zeros, so
// the same instant could serialize with a different number of digits from
// one request to the next. The ingest parses this permissively and silently
// falls back to server time when it cannot, so a wrong format loses real
// request timing with no error anywhere in the system.
func NowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

type resolvedSetup struct {
	APIKey string
	Owner  OwnerDetails
	Block  *Block
	Extra  map[string]any
}

// Engine is the shared state behind a Client.
type Engine struct {
	Uploader      *Uploader
	Blocklist     *Blocklist
	EnrichCache   *EnrichCache
	RecoveryCache *RecoveryCache

	redact          RedactOptions
	callback        SetupFunc
	requestIDPrefix string

	portalURL string
	portalMu  chan struct{} // 1-buffered, used as a lightweight mutex
	baseURL   string
}

func NewEngine(apiKey, baseURL, requestIDPrefix string, redact RedactOptions, transport Transport) *Engine {
	e := &Engine{
		Blocklist:       NewBlocklist(),
		EnrichCache:     NewEnrichCache(),
		RecoveryCache:   NewRecoveryCache(),
		redact:          redact,
		requestIDPrefix: requestIDPrefix,
		baseURL:         baseURL,
		portalMu:        make(chan struct{}, 1),
	}
	e.portalMu <- struct{}{}
	e.Uploader = NewUploader(apiKey, baseURL, requestIDPrefix, transport, e.handleServerResponse)
	return e
}

func (e *Engine) SetCallback(cb SetupFunc) { e.callback = cb }

func (e *Engine) BaseURL() string         { return e.baseURL }
func (e *Engine) RequestIDPrefix() string { return e.requestIDPrefix }
func (e *Engine) HasAPIKey() bool         { return e.Uploader.HasAPIKey() }

// PortalURL is the server-published portal origin every injected URL is built
// on. Empty before the first upload round-trip, and then nothing is emitted
// rather than a guess (INJECT-006).
func (e *Engine) PortalURL() string {
	<-e.portalMu
	url := e.portalURL
	e.portalMu <- struct{}{}
	return url
}

func (e *Engine) setPortalURL(url string) {
	<-e.portalMu
	e.portalURL = url
	e.portalMu <- struct{}{}
}

// handleServerResponse acts on the three channels piggybacked onto an upload
// response (WIRE-021..023).
func (e *Engine) handleServerResponse(body []byte, batchFingerprints []string) {
	var parsed struct {
		NeedsEnrichment  []string           `json:"needsEnrichment"`
		RecoveryMessages map[string]*string `json:"recoveryMessages"`
		// The wire key stays docsUrl: every already-deployed SDK reads it, so
		// renaming would strand them all with no portal origin (WIRE-023).
		DocsURL string `json:"docsUrl"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return // non-JSON is fine
	}

	for _, key := range parsed.NeedsEnrichment { // CACHE-006
		e.EnrichCache.Invalidate(key)
	}

	if parsed.DocsURL != "" {
		trimmed := parsed.DocsURL
		for len(trimmed) > 0 && trimmed[len(trimmed)-1] == '/' {
			trimmed = trimmed[:len(trimmed)-1]
		}
		e.setPortalURL(trimmed)
	}

	for _, key := range batchFingerprints {
		if msg, ok := parsed.RecoveryMessages[key]; ok && msg != nil {
			e.RecoveryCache.Set(key, *msg) // CACHE-011
			continue
		}
		// CACHE-012 with CACHE-013: negative-cache what the server did not
		// answer, but never clobber a positive entry we already hold.
		if !e.RecoveryCache.Known(key) {
			e.RecoveryCache.SetAbsent(key)
		}
	}
}

// LookupRecovery is the synchronous hot-path read (CACHE-010).
func (e *Engine) LookupRecovery(fingerprintKey string) string {
	return e.RecoveryCache.Lookup(fingerprintKey)
}

// Resolve runs the user's setup callback and applies the enrich cache
// (SETUP-001..005, CACHE-001..007, SAFETY-002).
func (e *Engine) Resolve(info *RequestInfo) (result resolvedSetup) {
	if e.callback == nil {
		return resolvedSetup{}
	}
	// SAFETY-002. A panicking callback must not reach the handler.
	defer func() {
		if r := recover(); r != nil {
			debugLog("setup callback panicked: %v", r)
			result = resolvedSetup{}
		}
	}()

	setup := e.callback(info)
	out := resolvedSetup{APIKey: setup.APIKey, Block: setup.Block, Extra: setup.Extra}
	if setup.Owner == nil {
		return out
	}

	ownerID := setup.Owner.ID
	base := OwnerDetails{}
	if ownerID != "" {
		base["id"] = ownerID
	}
	cacheKey := ownerID
	if cacheKey == "" {
		cacheKey = setup.APIKey
	}

	if setup.Owner.Enrich != nil && ownerID != "" && cacheKey != "" {
		if cached, ok := e.EnrichCache.Get(cacheKey); ok {
			out.Owner = merge(base, cached)
			return out
		}
		if enriched := e.callEnrich(setup.Owner.Enrich, ownerID); enriched != nil {
			e.EnrichCache.Set(cacheKey, enriched)
			out.Owner = merge(base, enriched)
			return out
		}
	}

	// CACHE-007. Ship the bare id so the dashboard can still group by it.
	out.Owner = base
	return out
}

// callEnrich isolates the user callback so a panic in it is contained
// (CACHE-005, SAFETY-003). Failures are NOT cached; the next request retries.
func (e *Engine) callEnrich(enrich func(string) OwnerDetails, ownerID string) (result OwnerDetails) {
	defer func() {
		if r := recover(); r != nil {
			debugLog("enrich panicked for %s: %v", ownerID, r)
			result = nil
		}
	}()
	return enrich(ownerID)
}

func merge(base, extra OwnerDetails) OwnerDetails {
	out := make(OwnerDetails, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// ComputeFingerprint fingerprints an error response (FP-002: errors only).
func (e *Engine) ComputeFingerprint(c CapturedRequest) *Fingerprint {
	if c.Status < 400 {
		return nil
	}
	var body any
	if c.ResponseBody != nil {
		if parsed, err := parseOrderedJSON([]byte(*c.ResponseBody)); err == nil {
			body = parsed
		} else {
			body = *c.ResponseBody // fingerprint() handles a raw string too
		}
	}
	fp := ComputeFingerprint(CapturedError{
		Status:          c.Status,
		Method:          c.Method,
		Route:           c.RoutePattern,
		ResponseHeaders: c.ResponseHeaders,
		ResponseBody:    body,
		StackTrace:      c.StackTrace,
	})
	return &fp
}

// Record is the single choke point: redact, truncate, fingerprint, enqueue.
func (e *Engine) Record(c CapturedRequest) {
	// SAFETY-001. Nothing in here may reach the caller.
	defer func() {
		if r := recover(); r != nil {
			debugLog("record panicked: %v", r)
		}
	}()

	c.URL = RedactURL(c.URL, e.redact.QueryParams)
	c.RequestHeaders = RedactHeaders(c.RequestHeaders, e.redact.Headers)
	c.ResponseHeaders = RedactHeaders(c.ResponseHeaders, e.redact.Headers)

	if c.RequestBody != nil {
		// REDACT-033: truncation runs AFTER redaction, so a secret cannot
		// survive by sitting past the byte limit.
		body := TruncateBody(
			RedactBody(*c.RequestBody, c.RequestHeaders["content-type"], e.redact.BodyKeys),
			MaxBodyBytes)
		c.RequestBody = &body
	}
	if c.ResponseBody != nil {
		body := TruncateBody(
			RedactBody(*c.ResponseBody, c.ResponseHeaders["content-type"], e.redact.BodyKeys),
			MaxBodyBytes)
		c.ResponseBody = &body
	}

	// INJECT-010. Reuse the fingerprint the adapter already computed for its
	// recovery lookup rather than repeating the work.
	if c.ErrorFingerprint == nil && c.Status >= 400 {
		c.ErrorFingerprint = e.ComputeFingerprint(c)
	}

	e.Uploader.Push(c)
}

// Flush uploads the queued batch and waits for it.
func (e *Engine) Flush() {
	e.Uploader.Flush()
	e.Uploader.Wait()
}
