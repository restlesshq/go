package restless

// Test-only hooks. Compiled into the package only under `go test`.

// SetSamplingRand replaces the draw of u (SAMPLE-031) so a test can pick
// the outcome of a rate.
func SetSamplingRand(c *Client, f func() float64) { c.engine.random = f }

// NewWithEntry builds a client as New does, from a settings entry rather
// than a file found on disk.
func NewWithEntry(apiKey string, entry *APIEntry, opts ...Option) *Client {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}
	return newClient(apiKey, entry, cfg)
}
