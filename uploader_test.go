package restless_test

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	restless "github.com/restlesshq/go"
)

// Upload backpressure (CONTRACT.md 1.3.0): the BATCH-009 cap, BATCH-010
// backlog draining, WIRE-026 retries, WIRE-027 non-retries, WIRE-028 timeout.

func captured(id string) restless.CapturedRequest {
	return restless.CapturedRequest{
		RequestID: id,
		StartedAt: "2026-10-30T00:00:00.000Z",
		Method:    "GET",
		URL:       "http://api.test/pets",
		Status:    200,
	}
}

func entriesIn(t *testing.T, body []byte) int {
	t.Helper()
	var batch []json.RawMessage
	if err := json.Unmarshal(body, &batch); err != nil {
		t.Errorf("upload body is not a JSON array: %v", err) // called off the test goroutine
		return -1
	}
	return len(batch)
}

// waitFor polls until cond holds, since uploads start on their own goroutines.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// ingestStub records each upload body; newIngest's handler picks the reply.
type ingestStub struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (s *ingestStub) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

func newIngest(t *testing.T, handle func(n int, w http.ResponseWriter, r *http.Request)) (*ingestStub, *httptest.Server) {
	t.Helper()
	stub := &ingestStub{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		stub.mu.Lock()
		stub.bodies = append(stub.bodies, body)
		n := len(stub.bodies)
		stub.mu.Unlock()
		handle(n, w, r)
	}))
	t.Cleanup(srv.Close)
	return stub, srv
}

func refuse(status int) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(status)
		_, _ = w.Write([]byte("busy"))
	}
}

func newUploader(t *testing.T, baseURL string, transport restless.Transport) *restless.Uploader {
	t.Helper()
	t.Setenv("RESTLESS_SETUP_MODE", "1") // BATCH-008 would drop every push under go test
	u := restless.NewUploader("k", baseURL, "", transport, nil)
	restless.SetUploadTiming(u, 200*time.Millisecond, time.Millisecond)
	return u
}

func TestUploadCapAndBacklog(t *testing.T) {
	t.Setenv("RESTLESS_ENV", "production")

	release := make(chan struct{})
	var mu sync.Mutex
	var sizes []int
	var active, peak atomic.Int32
	transport := func(url string, body []byte, headers map[string]string) ([]byte, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		mu.Lock()
		sizes = append(sizes, entriesIn(t, body))
		mu.Unlock()
		<-release
		return []byte(`{}`), nil
	}
	snapshot := func() []int {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(sizes)
	}

	u := newUploader(t, "https://remote.example", transport)
	for i := 0; i < 300; i++ {
		u.Push(captured("r"))
	}

	waitFor(t, "4 uploads", func() bool { return len(snapshot()) == 4 })
	time.Sleep(50 * time.Millisecond) // a fifth upload would have started by now
	if got := snapshot(); !slices.Equal(got, []int{10, 10, 10, 10}) {
		t.Fatalf("first uploads carried %v entries, want [10 10 10 10] (BATCH-009)", got)
	}

	// Each freed slot takes up to 100 of what queued behind the cap.
	for i := 0; i < 4; i++ {
		release <- struct{}{}
	}
	waitFor(t, "the backlog uploads", func() bool { return len(snapshot()) == 7 })
	backlog := snapshot()[4:]
	slices.Sort(backlog)
	if !slices.Equal(backlog, []int{60, 100, 100}) {
		t.Fatalf("backlog uploads carried %v entries, want 100, 100 and 60 (BATCH-010)", backlog)
	}

	close(release)
	u.Flush()
	total := 0
	for _, n := range snapshot() {
		total += n
	}
	if total != 300 {
		t.Errorf("uploaded %d entries, want 300", total)
	}
	if p := peak.Load(); p > 4 {
		t.Errorf("%d uploads ran at once, want at most 4 (BATCH-009)", p)
	}
}

func TestUploadPartialBatchWaitsForTimerInProduction(t *testing.T) {
	t.Setenv("RESTLESS_ENV", "production")
	var calls atomic.Int32
	u := newUploader(t, "https://remote.example", func(string, []byte, map[string]string) ([]byte, error) {
		calls.Add(1)
		return nil, nil
	})
	for i := 0; i < 9; i++ {
		u.Push(captured("r"))
	}
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("a partial batch was sent %d times before the timer or a flush (BATCH-010)", n)
	}
	u.Flush()
	if n := calls.Load(); n != 1 {
		t.Errorf("flush made %d uploads, want 1 (BATCH-005)", n)
	}
}

func TestUploadRetries503And429WithTheSameBody(t *testing.T) {
	stub, srv := newIngest(t, func(n int, w http.ResponseWriter, r *http.Request) {
		switch n {
		case 1:
			refuse(503)(n, w, r)
		case 2:
			refuse(429)(n, w, r)
		default:
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{}`))
		}
	})
	u := newUploader(t, srv.URL, nil)
	u.Push(captured("a"))
	u.Flush() // BATCH-005: returns only after the retries settle

	if n := stub.calls(); n != 3 {
		t.Fatalf("got %d attempts, want 3", n)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	for _, b := range stub.bodies[1:] {
		if string(b) != string(stub.bodies[0]) {
			t.Error("a retry sent a different body (WIRE-026)")
		}
	}
}

func TestUploadGivesUpAfterTwoRetries(t *testing.T) {
	stub, srv := newIngest(t, refuse(503))
	u := newUploader(t, srv.URL, nil)
	u.Push(captured("a"))
	u.Flush()
	if n := stub.calls(); n != 3 {
		t.Errorf("got %d attempts, want 3 (WIRE-026: at most 2 retries)", n)
	}
}

func TestUploadDoesNotRetry(t *testing.T) {
	cases := []struct {
		name   string
		handle func(int, http.ResponseWriter, *http.Request)
	}{
		{"a 502 (the ingest may have stored it)", refuse(502)},
		{"a 504", refuse(504)},
		{"a 500", refuse(500)},
		{"a timeout", func(_ int, w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}},
		{"a reset after the request was sent", func(_ int, w http.ResponseWriter, _ *http.Request) {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				if tcp, ok := conn.(*net.TCPConn); ok {
					_ = tcp.SetLinger(0) // RST rather than FIN
				}
				conn.Close()
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub, srv := newIngest(t, c.handle)
			u := newUploader(t, srv.URL, nil)
			u.Push(captured("a"))
			start := time.Now()
			u.Flush()
			if n := stub.calls(); n != 1 {
				t.Errorf("got %d attempts, want 1 (WIRE-027)", n)
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("flush took %s; the upload timeout did not apply (WIRE-028)", d)
			}
		})
	}
}

func TestUploadRetriesAConnectionThatNeverReachedTheIngest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	var calls atomic.Int32
	transport := func(url string, body []byte, headers map[string]string) ([]byte, error) {
		if calls.Add(1) == 1 {
			_, err := http.Post("http://"+closedAddr+"/v1/request", "application/json", nil)
			if err == nil {
				return nil, errors.New("expected the closed port to refuse")
			}
			return nil, err
		}
		return []byte(`{}`), nil
	}
	u := newUploader(t, "http://localhost:3003", transport)
	u.Push(captured("a"))
	u.Flush()
	if n := calls.Load(); n != 2 {
		t.Errorf("got %d attempts, want 2 (WIRE-026: refused connections may retry)", n)
	}
}

func TestUploadRetriesAStatusErrorFromACustomTransport(t *testing.T) {
	var calls atomic.Int32
	transport := func(string, []byte, map[string]string) ([]byte, error) {
		switch calls.Add(1) {
		case 1:
			return nil, &restless.StatusError{Status: 503, RetryAfter: "0"}
		case 2:
			return nil, &restless.StatusError{Status: 502}
		}
		return []byte(`{}`), nil
	}
	u := newUploader(t, "http://localhost:3003", transport)
	u.Push(captured("a"))
	u.Flush()
	if n := calls.Load(); n != 2 {
		t.Errorf("got %d attempts, want 2 (503 retried, then 502 dropped)", n)
	}
}

func TestUploadPanicNeverReachesTheHost(t *testing.T) {
	var calls atomic.Int32
	u := newUploader(t, "http://localhost:3003", func(string, []byte, map[string]string) ([]byte, error) {
		if calls.Add(1) == 1 {
			panic("transport exploded")
		}
		return nil, nil
	})
	u.Push(captured("a"))
	u.Flush()
	// The panicked upload must have given its slot back.
	u.Push(captured("b"))
	u.Flush()
	if n := calls.Load(); n != 2 {
		t.Errorf("got %d uploads, want 2 (SAFETY-001)", n)
	}
}

func TestUploadSendsTheSpecVersion(t *testing.T) {
	var got atomic.Value
	_, srv := newIngest(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("X-Restless-Spec-Version"))
		w.WriteHeader(202)
	})
	u := newUploader(t, srv.URL, nil)
	u.Push(captured("a"))
	u.Flush()
	if v, _ := got.Load().(string); v != "1.3.0" {
		t.Errorf("X-Restless-Spec-Version = %q, want 1.3.0 (META-002)", v)
	}
}
