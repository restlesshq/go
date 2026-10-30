package restless

import "time"

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

// SetUploadTiming shortens the upload timeout (WIRE-028) and the retry
// backoff base (WIRE-026) so a test does not wait seconds.
func SetUploadTiming(u *Uploader, timeout, retryBase time.Duration) {
	u.timeout = timeout
	u.retryBase = retryBase
}
