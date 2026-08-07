package restless_test

// End-to-end middleware tests over real net/http. These cover the Level 2
// behaviour the shared vectors cannot reach: injection, blocking, the
// enrich cache, and the safety guarantees.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	restless "github.com/restlesshq/go"
)

// captureTransport records uploads and replies like the ingest does.
func captureTransport(reply string) (restless.Transport, func() []map[string]any) {
	var mu sync.Mutex
	var batches [][]map[string]any

	transport := func(url string, body []byte, headers map[string]string) ([]byte, error) {
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, err
		}
		mu.Lock()
		batches = append(batches, batch)
		mu.Unlock()
		return []byte(reply), nil
	}
	drain := func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		var all []map[string]any
		for _, b := range batches {
			all = append(all, b...)
		}
		return all
	}
	return transport, drain
}

func newTestClient(t *testing.T, reply string) (*restless.Client, func() []map[string]any) {
	t.Helper()
	transport, drain := captureTransport(reply)
	client, err := restless.New("proj_key",
		restless.WithBaseURL("https://ingress.example"),
		restless.WithTransport(transport))
	if err != nil {
		t.Fatal(err)
	}
	// BATCH-008 drops captures under `go test`; this is the documented
	// override the setup CLI also uses.
	t.Setenv("RESTLESS_SETUP_MODE", "1")
	return client, drain
}

func TestCapturesAndRedacts(t *testing.T) {
	client, drain := newTestClient(t, `{}`)
	client.Setup(func(r *restless.RequestInfo) restless.SetupResult {
		return restless.SetupResult{
			APIKey: restless.Mask(r.Header("Authorization")),
			Owner: &restless.Owner{ID: "ws_acme", Enrich: func(id string) restless.OwnerDetails {
				return restless.OwnerDetails{"label": "Acme", "email": "ops@acme.test"}
			}},
		}
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /pets", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(201)
		// A big integer, to prove no lossy JSON round trip.
		_, _ = w.Write([]byte(`{"id":9007199254740993}`))
	})
	srv := httptest.NewServer(client.Middleware()(mux))
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/pets?api_key=sk_secret123&page=2",
		strings.NewReader(`{"name":"Rex","password":"hunter2hunter2"}`))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer sk_live_abcdef123456")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.Header.Get("x-request-id") == "" {
		t.Error("no x-request-id header (REQID-010)")
	}

	client.Flush()
	entries := drain()
	if len(entries) != 1 {
		t.Fatalf("expected 1 upload, got %d", len(entries))
	}
	har := entries[0]["request"].(map[string]any)["log"].(map[string]any)["entries"].([]any)[0].(map[string]any)
	hreq := har["request"].(map[string]any)

	if url := hreq["url"].(string); !strings.Contains(url, "%3CREDACTED") {
		t.Errorf("api_key not redacted in url: %s", url)
	}
	body := hreq["postData"].(map[string]any)["text"].(string)
	if !strings.Contains(body, "<REDACTED:14:ter2>") {
		t.Errorf("password not redacted: %s", body)
	}
	if strings.Contains(body, "hunter2hunter2") {
		t.Errorf("plaintext password on the wire: %s", body)
	}
	for _, h := range hreq["headers"].([]any) {
		hm := h.(map[string]any)
		if hm["name"] == "authorization" && !strings.HasPrefix(hm["value"].(string), "Bearer <REDACTED") {
			t.Errorf("authorization not redacted with scheme preserved: %v", hm["value"])
		}
	}

	// REDACT-020: nothing to redact in the response, so it is byte-identical
	// and the int64 survives.
	resBody := har["response"].(map[string]any)["content"].(map[string]any)["text"].(string)
	if resBody != `{"id":9007199254740993}` {
		t.Errorf("response body was re-serialized: %s", resBody)
	}

	group := entries[0]["group"].(map[string]any)
	if group["id"] != "ws_acme" || group["label"] != "Acme" {
		t.Errorf("group = %v", group)
	}
	// WIRE-013: always an array, even from a single string.
	if emails, ok := group["emails"].([]any); !ok || len(emails) != 1 {
		t.Errorf("emails not normalized to an array: %v", group["emails"])
	}
}

func TestEnrichRunsOncePerOwner(t *testing.T) {
	client, _ := newTestClient(t, `{}`)
	var mu sync.Mutex
	calls := 0
	client.Setup(func(r *restless.RequestInfo) restless.SetupResult {
		return restless.SetupResult{Owner: &restless.Owner{
			ID: "ws_acme",
			Enrich: func(id string) restless.OwnerDetails {
				mu.Lock()
				calls++
				mu.Unlock()
				return restless.OwnerDetails{"label": "Acme"}
			},
		}}
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) })
	srv := httptest.NewServer(client.Middleware()(mux))
	defer srv.Close()

	for i := 0; i < 5; i++ {
		resp, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	// CACHE-001: at most once per cache key per TTL window.
	if calls != 1 {
		t.Errorf("enrich ran %d times, want 1", calls)
	}
}

func TestInjectionAndRecoveryRoundTrip(t *testing.T) {
	reply := `{"docsUrl":"https://docs.acme.test","recoveryMessages":{"404:resource":"Check the id."}}`
	client, _ := newTestClient(t, reply)
	client.Setup(func(r *restless.RequestInfo) restless.SetupResult { return restless.SetupResult{} })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /pets/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"code":"pet_not_found"}`))
	})
	srv := httptest.NewServer(client.Middleware()(mux))
	defer srv.Close()

	get := func() map[string]any {
		resp, err := http.Get(srv.URL + "/pets/99")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("response was not valid JSON (content-length bug?): %v", err)
		}
		if resp.Header.Get("x-log-url") == "" {
			t.Error("no x-log-url on a 4xx (INJECT-002)")
		}
		return out
	}

	first := get()
	debug := first["debug"].(map[string]any)
	if strings.Contains(debug["recovery"].(string), "Check the id.") {
		t.Error("first occurrence should not have a cached message yet")
	}
	if !strings.Contains(debug["recovery"].(string), "get-pets-id.md") {
		t.Errorf("dig-in slug wrong: %v", debug["recovery"])
	}

	client.Flush() // round-trips the reply, seeding the recovery cache

	second := get()
	debug2 := second["debug"].(map[string]any)
	if !strings.Contains(debug2["recovery"].(string), "Check the id.") {
		t.Errorf("second occurrence missing the cached message: %v", debug2["recovery"])
	}
	// INJECT-006: the server-supplied docs origin is now in use.
	if !strings.HasPrefix(debug2["log"].(string), "https://docs.acme.test/") {
		t.Errorf("docsUrl not applied: %v", debug2["log"])
	}
}

func TestBlockRejectsBeforeHandler(t *testing.T) {
	client, _ := newTestClient(t, `{}`)
	client.Setup(func(r *restless.RequestInfo) restless.SetupResult {
		return restless.SetupResult{Block: &restless.Block{Status: 402, Message: "Payment required"}}
	})
	reached := false
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { reached = true })
	srv := httptest.NewServer(client.Middleware()(mux))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 402 {
		t.Errorf("status = %d, want 402", resp.StatusCode)
	}
	if reached {
		t.Error("handler ran despite Block (SETUP-004)")
	}
}

func TestPanicIsLoggedAndRepanicked(t *testing.T) {
	client, drain := newTestClient(t, `{}`)
	client.Setup(func(r *restless.RequestInfo) restless.SetupResult { return restless.SetupResult{} })

	mux := http.NewServeMux()
	mux.HandleFunc("GET /crash", func(w http.ResponseWriter, r *http.Request) {
		frobnicate()
	})
	srv := httptest.NewServer(client.Middleware()(mux))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/crash")
	if err == nil {
		resp.Body.Close()
	}

	client.Flush()
	entries := drain()
	if len(entries) != 1 {
		t.Fatalf("a panic produced %d logs, want 1 - an unhandled crash is the "+
			"single most valuable thing to capture", len(entries))
	}
	fp, ok := entries[0]["errorFingerprint"].(map[string]any)
	if !ok {
		t.Fatal("no fingerprint on the panic log")
	}
	// FP-040: panics group by the panicking function, not per route.
	if fp["strategy"] != "stack" {
		t.Errorf("strategy = %v, want stack", fp["strategy"])
	}
	// Asserting the STRATEGY alone is not enough, and this is the assertion
	// that matters. An earlier version fingerprinted every panic to the
	// SDK's own middleware.go with a function name of "1" - still strategy
	// "stack", still green, and completely useless: every panic in the
	// process would have shared one group.
	key, _ := fp["key"].(string)
	if !strings.Contains(key, "frobnicate") {
		t.Errorf("key = %q, want the panicking function (frobnicate)", key)
	}
	if strings.Contains(key, "middleware.go") {
		t.Errorf("key = %q points at the SDK's own frame, not the customer's", key)
	}
	if !strings.Contains(entries[0]["routePattern"].(string), "/crash") {
		t.Errorf("routePattern = %v, want /crash", entries[0]["routePattern"])
	}
}

// frobnicate is a named function so the panic fingerprint has something
// recognisable to key on.
func frobnicate() {
	panic("the widget frobnicator is on fire")
}

func TestSetupPanicDoesNotBreakTheRequest(t *testing.T) {
	// SAFETY-002: a broken callback must not reach handler code.
	client, _ := newTestClient(t, `{}`)
	client.Setup(func(r *restless.RequestInfo) restless.SetupResult {
		panic("customer callback is buggy")
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(client.Middleware()(mux))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("request failed because of a callback panic: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestRouteResolverNormalizesServeMuxPattern(t *testing.T) {
	client, drain := newTestClient(t, `{}`)
	client.Setup(func(r *restless.RequestInfo) restless.SetupResult { return restless.SetupResult{} })
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pets/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	srv := httptest.NewServer(client.Middleware()(mux))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pets/7")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	client.Flush()

	entries := drain()
	if len(entries) != 1 {
		t.Fatalf("got %d entries", len(entries))
	}
	// The method prefix must be stripped: routePattern is a PATH template.
	if got := entries[0]["routePattern"]; got != "/pets/{id}" {
		t.Errorf("routePattern = %v, want /pets/{id}", got)
	}
}
