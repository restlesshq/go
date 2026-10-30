package restless

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Batched uploader. Implements CONTRACT.md sections 8 (wire format) and 9
// (batching).
//
// Never returns an error to callers. Upload failures go to stderr under the
// debug flag and are otherwise swallowed: observability must not break the
// request path (SAFETY-004).

const (
	DefaultBaseURL   = "https://ingress.restless.ai" // WIRE-005
	batchSize        = 10                            // BATCH-001
	flushInterval    = 5 * time.Second               // BATCH-002
	maxQueue         = 1000                          // BATCH-004
	maxInFlight      = 4                             // BATCH-009
	maxUploadEntries = 100                           // BATCH-010
	uploadTimeout    = 10 * time.Second              // WIRE-028
	maxRetries       = 2                             // WIRE-026
	retryBase        = time.Second                   // WIRE-026
	maxRetryDelay    = 10 * time.Second              // WIRE-026
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

// Transport lets tests swap the HTTP call. Returns the response body. Only
// the default transport reports the statuses WIRE-026 retries.
type Transport func(url string, body []byte, headers map[string]string) ([]byte, error)

// statusError is a non-2xx upload response. Only 503 and 429 are retried.
type statusError struct {
	status     int
	retryAfter string
	body       string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("upload failed: %d %s", e.status, truncateForLog(e.body))
}

type Uploader struct {
	apiKey          string
	baseURL         string
	requestIDPrefix string
	transport       Transport
	onResponse      func(body []byte, batchFingerprints []string)
	// samplingHash is stamped on every upload as x-restless-sampling
	// (SAMPLE-052). Empty when sampling is not configured, and then no
	// header is sent at all.
	samplingHash string

	// Fields rather than constants so tests can shorten the waits.
	timeout   time.Duration
	retryBase time.Duration

	mu       sync.Mutex
	queue    []CapturedRequest
	timer    *time.Timer
	inFlight int        // BATCH-009, counting an upload waiting to retry
	settled  *sync.Cond // broadcast on mu whenever an upload finishes
	wg       sync.WaitGroup
}

func NewUploader(apiKey, baseURL, requestIDPrefix string, transport Transport, onResponse func([]byte, []string)) *Uploader {
	u := &Uploader{
		apiKey:          apiKey,
		baseURL:         strings.TrimRight(baseURL, "/"),
		requestIDPrefix: requestIDPrefix,
		transport:       transport,
		onResponse:      onResponse,
		timeout:         uploadTimeout,
		retryBase:       retryBase,
	}
	u.settled = sync.NewCond(&u.mu)
	if u.transport == nil {
		u.transport = u.post
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
	defer u.mu.Unlock()
	// BATCH-004. Drop the OLDEST: the newest entries are the ones an
	// operator is actively debugging.
	if len(u.queue) >= maxQueue {
		u.queue = u.queue[1:]
		debugLog("queue at %d - dropping oldest captured request", maxQueue)
	}
	u.queue = append(u.queue, captured)

	switch {
	case shouldFlushImmediately(u.baseURL):
		u.pumpLocked(true)
	case len(u.queue) >= batchSize:
		u.pumpLocked(false)
	case u.timer == nil:
		u.startTimerLocked()
	}
}

func (u *Uploader) startTimerLocked() {
	var t *time.Timer
	t = time.AfterFunc(flushInterval, func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		// A Flush may have replaced or stopped this timer while it was firing.
		if u.timer == t {
			u.timer = nil
		}
		u.pumpLocked(true)
	})
	u.timer = t
}

func (u *Uploader) stopTimerLocked() {
	if u.timer != nil {
		u.timer.Stop()
		u.timer = nil
	}
}

// pumpLocked starts uploads while a BATCH-009 slot is free. Without partial
// only full batches go, and a remainder waits for the timer (BATCH-010).
func (u *Uploader) pumpLocked(partial bool) {
	// BATCH-007. No key means drop the batch; never retry, never accumulate.
	if u.apiKey == "" {
		if len(u.queue) > 0 {
			debugLog("no API key - dropping batch")
		}
		u.queue = nil
		return
	}
	for u.inFlight < maxInFlight && len(u.queue) > 0 && (partial || len(u.queue) >= batchSize) {
		n := min(len(u.queue), maxUploadEntries)
		batch := u.queue[:n:n]
		u.queue = u.queue[n:]
		u.inFlight++
		u.wg.Add(1)
		// SAFETY-008. Uploads never block the request path.
		go u.upload(batch)
	}
	if len(u.queue) == 0 {
		u.queue = nil
	}
}

func (u *Uploader) upload(batch []CapturedRequest) {
	defer func() {
		// SAFETY-001. A panicking transport or response hook must not reach the host.
		if r := recover(); r != nil {
			debugLog("upload panicked: %v", r)
		}
		u.mu.Lock()
		u.inFlight--
		u.afterUploadLocked()
		u.settled.Broadcast()
		u.mu.Unlock()
		u.wg.Done()
	}()
	u.send(batch)
}

// afterUploadLocked hands a freed slot to what is waiting, or makes sure a
// remainder smaller than a batch still has a timer.
func (u *Uploader) afterUploadLocked() {
	if len(u.queue) == 0 {
		return
	}
	immediate := shouldFlushImmediately(u.baseURL)
	if immediate || len(u.queue) >= batchSize {
		u.pumpLocked(immediate)
	} else if u.timer == nil {
		u.startTimerLocked()
	}
}

// Flush uploads everything queued, four at a time, and returns once all of
// it and anything already in flight has settled, retries included (BATCH-005).
func (u *Uploader) Flush() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopTimerLocked()
	for len(u.queue) > 0 || u.inFlight > 0 {
		u.pumpLocked(true)
		if u.inFlight == 0 {
			break // BATCH-007: no key, pump dropped the queue
		}
		u.settled.Wait()
	}
	u.stopTimerLocked()
}

// send runs one upload, holding its slot through any retries. It retries
// only what the ingest certainly did not store (WIRE-026, WIRE-027).
func (u *Uploader) send(batch []CapturedRequest) {
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
	headers := map[string]string{
		"Content-Type":            "application/json",   // WIRE-002
		"Authorization":           "Bearer " + u.apiKey, // WIRE-003
		"X-Restless-Spec-Version": SpecVersion,          // META-002
	}
	if u.samplingHash != "" {
		headers["x-restless-sampling"] = u.samplingHash // SAMPLE-052
	}

	for retry := 0; ; retry++ {
		if retry == 0 {
			debugLog("uploading %d entries to %s", len(batch), url)
		} else {
			debugLog("uploading %d entries to %s (retry %d)", len(batch), url, retry)
		}
		respBody, err := u.transport(url, body, headers)
		if err == nil {
			// WIRE-020. A non-JSON or unparseable response is ignored, not an error.
			if len(respBody) > 0 && u.onResponse != nil {
				u.onResponse(respBody, fingerprints)
			}
			return
		}
		wait, retryable := u.retryWait(err, retry)
		if !retryable || retry >= maxRetries {
			debugLog("upload error: %v", err)
			return
		}
		debugLog("upload refused (%v); retrying in %s", err, wait.Round(time.Millisecond))
		time.Sleep(wait)
	}
}

// retryWait reports whether err may be retried (WIRE-026) and how long to
// wait first. Everything else is dropped (WIRE-024, WIRE-027).
func (u *Uploader) retryWait(err error, retry int) (time.Duration, bool) {
	var se *statusError
	if errors.As(err, &se) {
		if se.status != http.StatusServiceUnavailable && se.status != http.StatusTooManyRequests {
			return 0, false
		}
		return retryDelay(se.retryAfter, retry, u.retryBase), true
	}
	if notSent(err) {
		return retryDelay("", retry, u.retryBase), true
	}
	return 0, false
}

// retryDelay is the server's Retry-After (seconds or an HTTP date), else
// jittered exponential backoff, capped either way (WIRE-026).
func retryDelay(retryAfter string, retry int, base time.Duration) time.Duration {
	if h := strings.TrimSpace(retryAfter); h != "" {
		if secs, err := strconv.ParseFloat(h, 64); err == nil {
			if !math.IsNaN(secs) && !math.IsInf(secs, 0) && secs >= 0 {
				return time.Duration(min(secs, maxRetryDelay.Seconds()) * float64(time.Second))
			}
		} else if at, err := http.ParseTime(h); err == nil {
			if d := time.Until(at); d >= 0 {
				return min(d, maxRetryDelay)
			}
		}
	}
	backoff := float64(base) * math.Pow(2, float64(retry)) * (0.5 + rand.Float64())
	return time.Duration(min(backoff, float64(maxRetryDelay)))
}

// notSent reports a connection failure where nothing reached the ingest, so
// a retry cannot duplicate a stored batch. A timeout never qualifies (WIRE-028).
func notSent(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// SendSamplingReport POSTs the sampling config report (SAMPLE-050) on its
// own goroutine and calls done when it has finished, whatever happened. The
// same gates as an upload apply: nothing under a test runner or without a
// project key (SAMPLE-051). Never blocks and never panics into the caller.
func (u *Uploader) SendSamplingReport(body []byte, done func()) {
	if (IsTestRun() && os.Getenv("RESTLESS_SETUP_MODE") != "1") || u.apiKey == "" {
		done()
		return
	}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		defer done()
		defer func() {
			if r := recover(); r != nil {
				debugLog("sampling report panicked: %v", r)
			}
		}()
		url := u.baseURL + "/v1/sampling"
		_, err := u.transport(url, body, map[string]string{
			"Content-Type":            "application/json",   // WIRE-002
			"Authorization":           "Bearer " + u.apiKey, // WIRE-003
			"X-Restless-Spec-Version": SpecVersion,          // META-002
		})
		if err != nil {
			debugLog("sampling report error: %v", err)
			return
		}
		debugLog("sampling report sent")
	}()
}

// Wait blocks until in-flight uploads finish. Intended for tests and for a
// clean process shutdown.
func (u *Uploader) Wait() { u.wg.Wait() }

var uploadClient = &http.Client{}

// post is the default Transport. The deadline covers the whole exchange,
// response body included (WIRE-028).
func (u *Uploader) post(url string, body []byte, headers map[string]string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), u.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := uploadClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &statusError{
			status:     resp.StatusCode,
			retryAfter: resp.Header.Get("Retry-After"),
			body:       string(buf),
		}
	}
	return buf, nil
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
	Sampled          bool         `json:"sampled,omitempty"` // WIRE-030: true or absent
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
		Sampled:          c.Sampled,
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
