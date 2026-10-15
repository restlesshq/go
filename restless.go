// Package restless captures API traffic and sends it to Restless.
//
// It wraps any net/http handler, so it works with the standard library,
// chi, gorilla/mux, Echo and Gin.
//
//	client, _ := restless.New(os.Getenv("RESTLESS_KEY"))
//	client.Setup(func(r *restless.RequestInfo) restless.SetupResult {
//	    return restless.SetupResult{
//	        APIKey: restless.Mask(r.Header("Authorization")),
//	        Owner: &restless.Owner{
//	            ID:     workspaceID(r.Request),
//	            Enrich: func(id string) restless.OwnerDetails { ... },
//	        },
//	    }
//	})
//	http.ListenAndServe(":8080", client.Middleware()(mux))
//
// Conformance: implements version 1.1.0 of the Restless SDK Contract at
// level L2. Run the shared harness against ./cmd/conformance to verify.
package restless

import (
	"encoding/json"
	"fmt"
	"os"
)

// Client is the public handle. Construct one per process.
type Client struct {
	engine *Engine
}

// Option configures a Client.
type Option func(*config)

type config struct {
	api       string
	redact    RedactOptions
	baseURL   string
	transport Transport
	sampling  *Sampling
}

// WithAPI names the API to use from .restless/settings.json. Required when
// the file defines more than one (CONFIG-013).
func WithAPI(name string) Option { return func(c *config) { c.api = name } }

// WithRedact extends the built-in denylists. Additive only: the defaults
// are always applied (REDACT-014).
func WithRedact(r RedactOptions) Option { return func(c *config) { c.redact = r } }

// WithSampling sends less for high-traffic endpoints. Each endpoint is
// SampleOn (the default: everything in full), SampleOff (nothing),
// SampleErrors (only status >= 400), or SampleRate(r): that fraction of
// successful requests in full and the rest without bodies. Errors are never
// sampled.
//
//	restless.WithSampling(restless.Sampling{
//	    Routes: map[string]restless.SamplingMode{
//	        "GET /health":  restless.SampleOff,
//	        "GET /pets":    restless.SampleRate(0.1),
//	        "* /pets/{id}": restless.SampleErrors,
//	    },
//	})
//
// Merged with `sampling` in .restless/settings.json; this option wins per
// route, and a Default set here replaces the file's. An invalid value never
// fails construction: it falls back to SampleOn, reported under
// DEBUG=restless.
func WithSampling(s Sampling) Option { return func(c *config) { c.sampling = &s } }

// WithBaseURL overrides the ingest URL.
func WithBaseURL(url string) Option { return func(c *config) { c.baseURL = url } }

// WithTransport swaps the HTTP call. Intended for tests.
func WithTransport(t Transport) Option { return func(c *config) { c.transport = t } }

// New constructs a client.
//
// Returns an error only for a genuinely ambiguous configuration (several
// APIs defined in .restless/settings.json and none named). A missing API key
// is NOT an error: capture still runs and only upload is disabled, so
// dropping the SDK into a project without a key configured cannot break it
// (CONFIG-002).
func New(apiKey string, opts ...Option) (*Client, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	// CONFIG-001. Explicit key wins, then RESTLESS_KEY, then README_API_KEY.
	resolved := apiKey
	if resolved == "" {
		resolved = os.Getenv("RESTLESS_KEY")
	}
	if resolved == "" {
		resolved = os.Getenv("README_API_KEY")
	}
	if resolved == "" && !IsTestRun() {
		fmt.Fprintln(os.Stderr,
			"[restless] no API key found - set RESTLESS_KEY in your environment or "+
				"pass it to restless.New(). Captured requests will not be uploaded.")
	}

	entry, err := ResolveAPI(LoadSettings(), cfg.api)
	if err != nil {
		return nil, err
	}
	return newClient(resolved, entry, cfg), nil
}

// newClient builds the client from a resolved key and settings entry. Split
// from New so tests can supply the entry without a settings file on disk.
func newClient(resolved string, entry *APIEntry, cfg *config) *Client {
	requestIDPrefix := ""
	redact := cfg.redact
	var settingsSampling json.RawMessage
	if entry != nil {
		settingsSampling = entry.Sampling
		requestIDPrefix = entry.RequestIDPrefix
		if entry.Redact != nil {
			// REDACT-015. Settings and options are BOTH additive on top of
			// the built-in defaults.
			redact.Headers = append(append([]string{}, entry.Redact.Headers...), redact.Headers...)
			redact.BodyKeys = append(append([]string{}, entry.Redact.BodyKeys...), redact.BodyKeys...)
			redact.QueryParams = append(append([]string{}, entry.Redact.QueryParams...), redact.QueryParams...)
		}
	}

	// SAMPLE-014. Code wins over the settings file, per route. A bad value
	// never fails construction: it falls back to "on" and says so under
	// DEBUG.
	settingsSource, warning := parseSamplingJSON("settings", settingsSampling)
	if warning != "" {
		debugLog("%s", warning)
	}
	sampling, warnings := normalizeSampling(settingsSource, cfg.sampling.toSource())
	for _, w := range warnings {
		debugLog("%s", w)
	}

	engine := NewEngine(
		resolved, ResolveBaseURL(cfg.baseURL), requestIDPrefix, redact, cfg.transport)
	engine.configureSampling(sampling)
	return &Client{engine: engine}
}

// MustNew is New, panicking on a configuration error. Appropriate at
// program start, where a misconfigured SDK should be loud.
func MustNew(apiKey string, opts ...Option) *Client {
	client, err := New(apiKey, opts...)
	if err != nil {
		panic(err)
	}
	return client
}

// Setup registers the per-request callback.
//
// Keep it CHEAP: read straight off the request. Anything expensive belongs
// in Owner.Enrich, which runs once per owner id and then caches.
func (c *Client) Setup(fn SetupFunc) { c.engine.SetCallback(fn) }

// Mask hashes an end-user API key. Exposed on the client for symmetry with
// the other SDKs; the package-level Mask is identical.
func (c *Client) Mask(apiKey string) string { return Mask(apiKey) }

// Flush force-uploads the queued batch and waits for it. Call before process
// exit if you care about in-flight captures.
func (c *Client) Flush() { c.engine.Flush() }

// Engine exposes the internals. Adapters need it; application code does not.
func (c *Client) Engine() *Engine { return c.engine }
