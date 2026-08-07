package restless

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Batched uploader. Implements CONTRACT.md sections 8 (wire format) and 9
// (batching).
//
// Never returns an error to callers. Upload failures go to stderr under the
// debug flag and are otherwise swallowed: observability must not break the
// request path (SAFETY-004).

const (
	DefaultBaseURL = "https://ingress.restless.ai" // WIRE-005
	batchSize      = 10                            // BATCH-001
	flushInterval  = 5 * time.Second               // BATCH-002
	maxQueue       = 1000                          // BATCH-004
)

// CONFIG-004
func debugEnabled() bool {
	flag := os.Getenv("DEBUG")
	if flag == "*" || flag == "restless" {
		return true
	}
	for _, tok := range strings.FieldsFunc(flag, func(r rune) bool { return r == ',' || r == ' ' }) {
		if tok == "restless" {
			return true
		}
	}
	return false
}

func debugLog(format string, args ...any) {
	if debugEnabled() {
		fmt.Fprintf(os.Stderr, "[restless] "+format+"\n", args...)
	}
}

// ResolveBaseURL applies CONFIG-003.
func ResolveBaseURL(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("RESTLESS_BASE_URL"); env != "" {
		return env
	}
	return DefaultBaseURL
}

// IsTestRun implements BATCH-008 for Go.
//
// The Node reference keys on NODE_ENV=test, VITEST and JEST_WORKER_ID.
// `go test` compiles a binary whose name ends in ".test" and registers
// -test.* flags, which is the idiomatic detection here.
func IsTestRun() bool {
	if os.Getenv("RESTLESS_ENV") == "test" {
		return true
	}
	if strings.HasSuffix(os.Args[0], ".test") {
		return true
	}
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-test.") {
			return true
		}
	}
	return false
}

func isLocalhost(baseURL string) bool {
	return strings.Contains(baseURL, "//localhost") || strings.Contains(baseURL, "//127.0.0.1")
}

// BATCH-003. Keep the customer developer loop and self-hosted setups
// low-latency; batch only in production against a remote ingest.
func shouldFlushImmediately(baseURL string) bool {
	env := os.Getenv("RESTLESS_ENV")
	if env == "" {
		env = os.Getenv("ENV")
	}
	if env != "production" {
		return true
	}
	return isLocalhost(baseURL)
}

// Transport lets tests swap the HTTP call. Returns the response body.
type Transport func(url string, body []byte, headers map[string]string) ([]byte, error)

type Uploader struct {
	apiKey          string
	baseURL         string
	requestIDPrefix string
	transport       Transport
	onResponse      func(body []byte, batchFingerprints []string)

	mu    sync.Mutex
	queue []CapturedRequest
	timer *time.Timer
	wg    sync.WaitGroup
}

func NewUploader(apiKey, baseURL, requestIDPrefix string, transport Transport, onResponse func([]byte, []string)) *Uploader {
	if transport == nil {
		transport = httpPost
	}
	u := &Uploader{
		apiKey:          apiKey,
		baseURL:         strings.TrimRight(baseURL, "/"),
		requestIDPrefix: requestIDPrefix,
		transport:       transport,
		onResponse:      onResponse,
	}
	u.warnIfInsecure()
	return u
}

// WIRE-006. One-shot warning: the project key and every captured header
// would otherwise ship in the clear with no signal at all.
func (u *Uploader) warnIfInsecure() {
	if strings.HasPrefix(u.baseURL, "http://") && !isLocalhost(u.baseURL) {
		fmt.Fprintf(os.Stderr,
			"[restless] RESTLESS_BASE_URL=%s is plain HTTP - your API key and every "+
				"captured header will be transmitted unencrypted. Use https:// or localhost.\n",
			u.baseURL)
	}
}

func (u *Uploader) HasAPIKey() bool { return u.apiKey != "" }

func (u *Uploader) Push(captured CapturedRequest) {
	// BATCH-008
	if IsTestRun() && os.Getenv("RESTLESS_SETUP_MODE") != "1" {
		return
	}

	u.mu.Lock()
	// BATCH-004. Drop the OLDEST: the newest entries are the ones an
	// operator is actively debugging.
	if len(u.queue) >= maxQueue {
		u.queue = u.queue[1:]
		debugLog("queue at %d - dropping oldest captured request", maxQueue)
	}
	u.queue = append(u.queue, captured)
	flushNow := shouldFlushImmediately(u.baseURL) || len(u.queue) >= batchSize
	if !flushNow && u.timer == nil {
		u.timer = time.AfterFunc(flushInterval, func() { u.flushAsync() })
	}
	u.mu.Unlock()

	if flushNow {
		u.flushAsync()
	}
}

// SAFETY-008. Uploads never block the request path.
func (u *Uploader) flushAsync() {
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.Flush()
	}()
}

// Flush uploads the queued batch synchronously.
func (u *Uploader) Flush() {
	u.mu.Lock()
	if u.timer != nil {
		u.timer.Stop()
		u.timer = nil
	}
	if len(u.queue) == 0 {
		u.mu.Unlock()
		return
	}
	// BATCH-007. No key means drop the batch; never retry, never accumulate.
	if u.apiKey == "" {
		debugLog("no API key - dropping batch")
		u.queue = nil
		u.mu.Unlock()
		return
	}
	batch := u.queue
	u.queue = nil
	u.mu.Unlock()

	var fingerprints []string
	seen := map[string]bool{}
	for _, c := range batch {
		if c.ErrorFingerprint == nil {
			continue
		}
		if key := c.ErrorFingerprint.Key; key != "" && !seen[key] {
			seen[key] = true
			fingerprints = append(fingerprints, key)
		}
	}

	payload := make([]wireEntry, 0, len(batch))
	for _, c := range batch {
		payload = append(payload, buildWireEntry(c))
	}

	body, err := marshalCompact(payload)
	if err != nil {
		debugLog("encode failed: %v", err)
		return
	}

	url := u.baseURL + "/v1/request" // WIRE-001
	debugLog("uploading %d entries to %s", len(batch), url)

	respBody, err := u.transport(url, body, map[string]string{
		"Content-Type":            "application/json",   // WIRE-002
		"Authorization":           "Bearer " + u.apiKey, // WIRE-003
		"X-Restless-Spec-Version": SpecVersion,          // META-002
	})
	if err != nil {
		debugLog("upload error: %v", err)
		return
	}
	// WIRE-020. A non-JSON or unparseable response is ignored, not an error.
	if len(respBody) > 0 && u.onResponse != nil {
		u.onResponse(respBody, fingerprints)
	}
}

// Wait blocks until in-flight uploads finish. Intended for tests and for a
// clean process shutdown.
func (u *Uploader) Wait() { u.wg.Wait() }

func httpPost(url string, body []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	// WIRE-024. Never retried, never raised.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		debugLog("upload failed: %d %s", resp.StatusCode, truncateForLog(buf.String()))
		return nil, nil
	}
	return buf.Bytes(), nil
}

func truncateForLog(s string) string {
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

// ---------------------------------------------------------------------------
// Wire payload (WIRE-010..018)
// ---------------------------------------------------------------------------
//
// Structs rather than maps, deliberately: encoding/json emits struct fields
// in DECLARATION order but sorts map keys, so a map here would produce a
// payload ordered differently from every other SDK.

type wireGroup struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Emails []string `json:"emails"`
}

type wireCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type wireLog struct {
	Version string      `json:"version"`
	Creator wireCreator `json:"creator"`
	Entries []HarEntry  `json:"entries"`
}

type wireRequest struct {
	Log wireLog `json:"log"`
}

type wireEntry struct {
	ID               string       `json:"_id"`
	RoutePattern     string       `json:"routePattern,omitempty"`
	ErrorFingerprint *Fingerprint `json:"errorFingerprint,omitempty"`
	Group            wireGroup    `json:"group"`
	APIKey           string       `json:"apiKey,omitempty"`
	ProjectID        string       `json:"projectId,omitempty"`
	ClientIPAddress  string       `json:"clientIPAddress"`
	Development      bool         `json:"development"`
	Request          wireRequest  `json:"request"`
}

func buildWireEntry(c CapturedRequest) wireEntry {
	var apiKey, ownerID, label string
	var emails []string
	if c.User != nil {
		apiKey = c.User.APIKey
		if c.User.Owner != nil {
			if v, ok := c.User.Owner["id"].(string); ok {
				ownerID = v
			}
			if v, ok := c.User.Owner["label"].(string); ok {
				label = v
			}
			emails = normalizeEmails(c.User.Owner["email"])
		}
	}

	// WIRE-012. owner id, else the masked key, else "anonymous".
	groupID := ownerID
	if groupID == "" {
		groupID = apiKey
	}
	if groupID == "" {
		groupID = "anonymous"
	}

	return wireEntry{
		ID:               c.RequestID, // WIRE-011: raw uuid, no prefix
		RoutePattern:     c.RoutePattern,
		ErrorFingerprint: c.ErrorFingerprint, // WIRE-017: absent on success
		Group:            wireGroup{ID: groupID, Label: label, Emails: emails},
		APIKey:           apiKey,      // WIRE-014
		ProjectID:        ownerID,     // WIRE-015
		ClientIPAddress:  "127.0.0.1", // WIRE-018, reserved
		Development:      false,       // WIRE-018, reserved
		Request: wireRequest{Log: wireLog{
			Version: "1.2",
			Creator: wireCreator{Name: SDKName, Version: SDKVersion}, // WIRE-016
			Entries: []HarEntry{ToHarEntry(c)},
		}},
	}
}

// WIRE-013. Always an array on the wire, whether the user's enrich returned
// a single string or a list.
func normalizeEmails(raw any) []string {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return []string{}
		}
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{}
}

var _ = json.Marshal
