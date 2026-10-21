package restless_test

// Sampling (CONTRACT.md section 12.1). The pure functions are pinned by the
// shared vectors in spec/vectors/sampling.json; these cover what vectors
// cannot: the typed option, the one-draw rule, header suppression in the
// middleware, stubs on the wire, and the config report.

import (
	"encoding/json"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	restless "github.com/restlesshq/go"
)

// ingest records every call by path and replies to uploads with reply.
type ingest struct {
	mu      sync.Mutex
	reply   string
	fail    bool
	calls   []ingestCall
	uploads []map[string]any
}

type ingestCall struct {
	path    string
	headers map[string]string
	body    []byte
}

func (in *ingest) transport(url string, body []byte, headers map[string]string) ([]byte, error) {
	path := url[strings.Index(url, "/v1/"):]
	in.mu.Lock()
	defer in.mu.Unlock()
	in.calls = append(in.calls, ingestCall{path: path, headers: headers, body: body})
	if in.fail && path == "/v1/sampling" {
		panic("ingest unreachable")
	}
	if path == "/v1/request" {
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, err
		}
		in.uploads = append(in.uploads, batch...)
		return []byte(in.reply), nil
	}
	return []byte(`{}`), nil
}

func (in *ingest) byPath(path string) []ingestCall {
	in.mu.Lock()
	defer in.mu.Unlock()
	var out []ingestCall
	for _, c := range in.calls {
		if c.path == path {
			out = append(out, c)
		}
	}
	return out
}

func (in *ingest) entries() []map[string]any {
	in.mu.Lock()
	defer in.mu.Unlock()
	return append([]map[string]any(nil), in.uploads...)
}

func newSamplingClient(t *testing.T, in *ingest, s restless.Sampling, u float64) (*restless.Client, *atomic.Int32) {
	t.Helper()
	t.Setenv("RESTLESS_SETUP_MODE", "1")
	client, err := restless.New("proj_key",
		restless.WithBaseURL("https://ingress.example"),
		restless.WithTransport(in.transport),
		restless.WithSampling(s))
	if err != nil {
		t.Fatal(err)
	}
	draws := &atomic.Int32{}
	restless.SetSamplingRand(client, func() float64 {
		draws.Add(1)
		return u
	})
	return client, draws
}

func petsServer(client *restless.Client) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /pets", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"pets":[{"name":"Rex"}]}`))
	})
	mux.HandleFunc("POST /pets", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	mux.HandleFunc("GET /pets/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.PathValue("id") == "missing" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"code":"pet_not_found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"Rex"}`))
	})
	mux.HandleFunc("GET /stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("data: 1\n\n"))
		w.(http.Flusher).Flush()
	})
	mux.HandleFunc("GET /silent", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) { panic("boom") })
	return httptest.NewServer(client.Middleware()(mux))
}

type response struct {
	status  int
	headers http.Header
	body    string
}

func do(t *testing.T, srv *httptest.Server, method, path, body string) response {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("content-type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, headers: resp.Header, body: string(buf)}
}

func harOf(entry map[string]any) map[string]any {
	return entry["request"].(map[string]any)["log"].(map[string]any)["entries"].([]any)[0].(map[string]any)
}

func TestSamplingOffDropsEverything(t *testing.T) {
	in := &ingest{reply: `{"docsUrl":"https://docs.acme.test"}`}
	client, _ := newSamplingClient(t, in, restless.Sampling{Routes: map[string]restless.SamplingMode{
		"GET /health":    restless.SampleOff,
		"* /pets/{id}":   restless.SampleOff,
		"get /stream/":   restless.SampleOff,
		"GET /silent":    restless.SampleOff,
		"GET /pets/:id/": restless.SampleOff, // same key as "* /pets/{id}" for GET
	}}, 0)
	srv := petsServer(client)
	defer srv.Close()

	for _, path := range []string{"/health", "/pets/1", "/pets/missing", "/stream", "/silent"} {
		res := do(t, srv, "GET", path, "")
		for _, h := range []string{"x-request-id", "x-restless-id", "x-debug", "x-api-feedback", "x-log-url"} {
			if v := res.headers.Get(h); v != "" {
				t.Errorf("GET %s: %s = %q on a dropped request (SAMPLE-033)", path, h, v)
			}
		}
		if path == "/pets/missing" {
			// The customer's error goes out exactly as written: no debug object.
			if res.status != 404 || res.body != `{"code":"pet_not_found"}` {
				t.Errorf("dropped 404 was altered: %d %s", res.status, res.body)
			}
		}
		if path == "/stream" && res.body != "data: 1\n\n" {
			t.Errorf("stream body = %q", res.body)
		}
	}
	client.Flush()
	if n := len(in.entries()); n != 0 {
		t.Errorf("uploaded %d entries under \"off\"", n)
	}
}

func TestSamplingErrorsMode(t *testing.T) {
	in := &ingest{reply: `{"docsUrl":"https://docs.acme.test"}`}
	client, _ := newSamplingClient(t, in, restless.Sampling{Default: restless.SampleErrors}, 0)
	srv := petsServer(client)
	defer srv.Close()

	ok := do(t, srv, "GET", "/pets/1", "")
	if ok.headers.Get("x-request-id") != "" || ok.headers.Get("x-debug") != "" ||
		ok.headers.Get("x-api-feedback") != "" {
		t.Errorf("a success under \"errors\" kept its headers: %v", ok.headers)
	}
	miss := do(t, srv, "GET", "/pets/missing", "")
	if miss.headers.Get("x-request-id") == "" || miss.headers.Get("x-debug") == "" ||
		miss.headers.Get("x-api-feedback") == "" {
		t.Errorf("an error under \"errors\" lost its headers: %v", miss.headers)
	}

	client.Flush()
	entries := in.entries()
	if len(entries) != 1 {
		t.Fatalf("uploaded %d entries, want just the 404", len(entries))
	}
	har := harOf(entries[0])
	if status := har["response"].(map[string]any)["status"].(float64); status != 404 {
		t.Errorf("uploaded status %v", status)
	}
	if _, ok := entries[0]["sampled"]; ok {
		t.Error("a full entry carries `sampled` (WIRE-030)")
	}
	if entries[0]["errorFingerprint"] == nil {
		t.Error("the error lost its fingerprint")
	}
}

func TestSamplingPanicCountsAsError(t *testing.T) {
	for _, tc := range []struct {
		mode restless.SamplingMode
		want int
	}{{restless.SampleErrors, 1}, {restless.SampleRate(0), 1}, {restless.SampleOff, 0}} {
		in := &ingest{reply: `{}`}
		client, _ := newSamplingClient(t, in, restless.Sampling{Default: tc.mode}, 0.99)
		srv := petsServer(client)
		// net/http logs the re-panicked handler panic; keep test output clean.
		srv.Config.ErrorLog = log.New(io.Discard, "", 0)
		_, _ = http.Get(srv.URL + "/boom")
		srv.Close()
		client.Flush()
		entries := in.entries()
		if len(entries) != tc.want {
			t.Errorf("%v: %d entries for a panic, want %d", tc.mode, len(entries), tc.want)
			continue
		}
		if tc.want == 1 {
			if _, ok := entries[0]["sampled"]; ok {
				t.Errorf("%v: a panic was sent as a stub", tc.mode)
			}
		}
	}
}

func TestSamplingRateStub(t *testing.T) {
	in := &ingest{reply: `{}`}
	client, _ := newSamplingClient(t, in, restless.Sampling{Routes: map[string]restless.SamplingMode{
		"POST /pets": restless.SampleRate(0.5),
	}}, 0.5) // u == rate is a stub (SAMPLE-031)
	srv := petsServer(client)
	defer srv.Close()

	res := do(t, srv, "POST", "/pets", `{"name":"Rex","password":"hunter2hunter2"}`)
	if res.headers.Get("x-request-id") == "" || res.headers.Get("x-debug") == "" {
		t.Errorf("a stub is a real log and keeps its headers: %v", res.headers)
	}
	if res.body != `{"id":1}` {
		t.Errorf("response body = %q", res.body)
	}

	client.Flush()
	entries := in.entries()
	if len(entries) != 1 {
		t.Fatalf("uploaded %d entries, want 1 stub", len(entries))
	}
	if entries[0]["sampled"] != true {
		t.Errorf("sampled = %v, want true", entries[0]["sampled"])
	}
	har := harOf(entries[0])
	req := har["request"].(map[string]any)
	if _, ok := req["postData"]; ok {
		t.Error("a stub carries postData (SAMPLE-034)")
	}
	if req["bodySize"].(float64) != -1 {
		t.Errorf("request bodySize = %v, want -1", req["bodySize"])
	}
	resp := har["response"].(map[string]any)
	if resp["bodySize"].(float64) != -1 || resp["content"].(map[string]any)["text"] != "" {
		t.Errorf("a stub carries a response body: %v", resp)
	}
	// Headers are still captured and redacted.
	found := false
	for _, h := range resp["headers"].([]any) {
		if h.(map[string]any)["name"] == "content-type" {
			found = true
		}
	}
	if !found {
		t.Error("a stub lost its response headers")
	}
}

func TestSamplingRateHitIsFull(t *testing.T) {
	in := &ingest{reply: `{}`}
	client, _ := newSamplingClient(t, in, restless.Sampling{Routes: map[string]restless.SamplingMode{
		"GET /pets": restless.SampleRate(0.5),
	}}, 0.49)
	srv := petsServer(client)
	defer srv.Close()

	do(t, srv, "GET", "/pets", "")
	client.Flush()
	entries := in.entries()
	if len(entries) != 1 {
		t.Fatalf("uploaded %d entries", len(entries))
	}
	if _, ok := entries[0]["sampled"]; ok {
		t.Error("a full entry carries `sampled`")
	}
	text := harOf(entries[0])["response"].(map[string]any)["content"].(map[string]any)["text"]
	if text != `{"pets":[{"name":"Rex"}]}` {
		t.Errorf("response body = %v", text)
	}
}

func TestSamplingUnmatchedRouteUsesDefault(t *testing.T) {
	in := &ingest{reply: `{}`}
	client, _ := newSamplingClient(t, in, restless.Sampling{
		Default: restless.SampleOff,
		Routes:  map[string]restless.SamplingMode{"GET /pets": restless.SampleOn},
	}, 0)
	srv := petsServer(client)
	defer srv.Close()

	do(t, srv, "GET", "/pets", "")
	if res := do(t, srv, "GET", "/nowhere", ""); res.headers.Get("x-request-id") != "" {
		t.Error("an unmatched request did not use the \"off\" default")
	}
	client.Flush()
	if n := len(in.entries()); n != 1 {
		t.Errorf("uploaded %d entries, want 1", n)
	}
}

func TestSamplingDrawsOncePerRequest(t *testing.T) {
	in := &ingest{reply: `{}`}
	client, draws := newSamplingClient(t, in, restless.Sampling{Default: restless.SampleRate(0.5)}, 0.9)
	srv := petsServer(client)
	defer srv.Close()

	// Flush, Write, Flush again, and a handler that writes nothing: each
	// would be a decision point if the recorder re-asked.
	for _, path := range []string{"/stream", "/pets", "/silent", "/pets/1"} {
		do(t, srv, "GET", path, "")
	}
	client.Flush()
	if n := draws.Load(); n != 4 {
		t.Errorf("drew u %d times for 4 requests (SAMPLE-032)", n)
	}
}

func TestSamplingWithoutConfigChangesNothing(t *testing.T) {
	in := &ingest{reply: `{}`}
	t.Setenv("RESTLESS_SETUP_MODE", "1")
	client, err := restless.New("proj_key",
		restless.WithBaseURL("https://ingress.example"),
		restless.WithTransport(in.transport),
		// Explicitly all "on" is the default configuration (SAMPLE-041).
		restless.WithSampling(restless.Sampling{Default: restless.SampleOn}))
	if err != nil {
		t.Fatal(err)
	}
	restless.SetSamplingRand(client, func() float64 {
		t.Error("u drawn without sampling configured")
		return 0
	})
	srv := petsServer(client)
	defer srv.Close()

	do(t, srv, "GET", "/pets", "")
	client.Flush()
	if n := len(in.byPath("/v1/sampling")); n != 0 {
		t.Errorf("sent %d sampling reports without a config", n)
	}
	for _, c := range in.byPath("/v1/request") {
		if _, ok := c.headers["x-restless-sampling"]; ok {
			t.Error("x-restless-sampling sent without a config")
		}
	}
	if n := len(in.entries()); n != 1 {
		t.Errorf("uploaded %d entries", n)
	}
}

func TestSamplingReportOncePerProcess(t *testing.T) {
	in := &ingest{reply: `{}`}
	client, _ := newSamplingClient(t, in, restless.Sampling{
		Default: restless.SampleRate(0.25),
		Routes: map[string]restless.SamplingMode{
			"get /pets/:id/": restless.SampleRate(0.1),
			"GET /health":    restless.SampleOff,
			"bad key":        restless.SampleOff,
		},
	}, 0)

	// Not at construction (SAMPLE-051).
	client.Flush()
	if n := len(in.byPath("/v1/sampling")); n != 0 {
		t.Fatalf("reported at construction")
	}

	srv := petsServer(client)
	defer srv.Close()
	for i := 0; i < 5; i++ {
		do(t, srv, "GET", "/pets/1", "")
	}
	client.Flush()

	reports := in.byPath("/v1/sampling")
	if len(reports) != 1 {
		t.Fatalf("sent %d reports, want 1", len(reports))
	}
	report := reports[0]
	if report.headers["Authorization"] != "Bearer proj_key" {
		t.Errorf("report auth = %q", report.headers["Authorization"])
	}
	wantBody := `{"hash":"%s","default":0.25,"routes":{"GET /health":"off","GET /pets/{id}":0.1},` +
		`"creator":{"name":"restless-sdk-go","version":"` + restless.SDKVersion + `"}}`
	var parsed struct{ Hash string }
	_ = json.Unmarshal(report.body, &parsed)
	if got := string(report.body); got != strings.Replace(wantBody, "%s", parsed.Hash, 1) {
		t.Errorf("report body:\n  got  %s\n  want %s", got, wantBody)
	}
	cfg, _ := restless.NormalizeSamplingJSON(nil,
		[]byte(`{"default":0.25,"routes":{"GET /pets/{id}":0.1,"GET /health":"off"}}`))
	if parsed.Hash != cfg.Hash() || len(parsed.Hash) != 64 {
		t.Errorf("report hash %q, want %q", parsed.Hash, cfg.Hash())
	}

	uploads := in.byPath("/v1/request")
	if len(uploads) == 0 {
		t.Fatal("no uploads")
	}
	for _, u := range uploads {
		if u.headers["x-restless-sampling"] != parsed.Hash {
			t.Errorf("upload x-restless-sampling = %q (SAMPLE-052)", u.headers["x-restless-sampling"])
		}
	}
}

func TestSamplingReportResentOnRequest(t *testing.T) {
	in := &ingest{reply: `{"needsSamplingConfig":true}`}
	client, _ := newSamplingClient(t, in, restless.Sampling{Default: restless.SampleRate(0.5)}, 0)
	srv := petsServer(client)
	defer srv.Close()

	do(t, srv, "GET", "/pets", "")
	client.Flush()
	client.Flush() // the resend is started from the upload's goroutine
	if n := len(in.byPath("/v1/sampling")); n != 2 {
		t.Errorf("sent %d reports, want the first and one resend (SAMPLE-053)", n)
	}

	// Anything but a literal true is ignored, and does not break the other
	// response channels.
	in2 := &ingest{reply: `{"needsSamplingConfig":"true","docsUrl":"https://docs.acme.test"}`}
	client2, _ := newSamplingClient(t, in2, restless.Sampling{Default: restless.SampleRate(0.5)}, 0)
	srv2 := petsServer(client2)
	defer srv2.Close()
	do(t, srv2, "GET", "/pets", "")
	client2.Flush()
	client2.Flush()
	if n := len(in2.byPath("/v1/sampling")); n != 1 {
		t.Errorf("sent %d reports for a non-boolean flag, want 1", n)
	}
	if res := do(t, srv2, "GET", "/pets", ""); res.headers.Get("x-log-url") == "" {
		t.Error("a mistyped needsSamplingConfig took docsUrl down with it")
	}
}

func TestSamplingReportFailureNeverSurfaces(t *testing.T) {
	in := &ingest{reply: `{}`, fail: true}
	client, _ := newSamplingClient(t, in, restless.Sampling{Default: restless.SampleRate(0.5)}, 0)
	srv := petsServer(client)
	defer srv.Close()

	if res := do(t, srv, "GET", "/pets", ""); res.status != 200 {
		t.Errorf("status %d with a failing report", res.status)
	}
	client.Flush()
	if n := len(in.entries()); n != 1 {
		t.Errorf("uploaded %d entries, want 1", n)
	}
}

func TestSamplingSettingsMergeCodeWins(t *testing.T) {
	var settings restless.Settings
	if err := json.Unmarshal([]byte(`{"apis":[{"name":"Pets","sampling":{
		"default":"errors",
		"routes":{"GET /health":"off","GET /pets":"off"}}}]}`), &settings); err != nil {
		t.Fatal(err)
	}
	entry, err := restless.ResolveAPI(&settings, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.Sampling) == 0 {
		t.Fatal("the settings entry dropped its sampling block")
	}

	in := &ingest{reply: `{}`}
	t.Setenv("RESTLESS_SETUP_MODE", "1")
	client := restless.NewWithEntry("proj_key", entry,
		restless.WithBaseURL("https://ingress.example"),
		restless.WithTransport(in.transport),
		restless.WithSampling(restless.Sampling{
			Routes: map[string]restless.SamplingMode{"GET /pets": restless.SampleOn},
		}))
	srv := petsServer(client)
	defer srv.Close()

	if res := do(t, srv, "GET", "/health", ""); res.headers.Get("x-request-id") != "" {
		t.Error("the settings file's \"off\" route was not applied")
	}
	if res := do(t, srv, "GET", "/pets", ""); res.headers.Get("x-request-id") == "" {
		t.Error("code did not win over the settings file for GET /pets")
	}
	if res := do(t, srv, "GET", "/pets/1", ""); res.headers.Get("x-request-id") != "" {
		t.Error("the settings file's default did not apply")
	}
}

func TestSamplingInvalidValuesNeverPanic(t *testing.T) {
	for _, tc := range []struct {
		s restless.Sampling
		// A config whose only content is invalid is the default config
		// (SAMPLE-041) and never draws. An invalid MODE on a valid key still
		// leaves a route, set to "on".
		draws bool
	}{
		{restless.Sampling{Default: restless.SampleRate(math.NaN())}, false},
		{restless.Sampling{Default: restless.SampleRate(math.Inf(1))}, false},
		{restless.Sampling{Default: restless.SampleRate(-0.1)}, false},
		{restless.Sampling{Default: restless.SampleRate(1.5)}, false},
		{restless.Sampling{Routes: map[string]restless.SamplingMode{
			"": restless.SampleOff, "GET": restless.SampleOff, "GET pets": restless.SampleOff}}, false},
		{restless.Sampling{Routes: nil}, false},
		{restless.Sampling{Routes: map[string]restless.SamplingMode{"GET /pets": {}}}, true},
	} {
		in := &ingest{reply: `{}`}
		client, draws := newSamplingClient(t, in, tc.s, 0)
		srv := petsServer(client)
		do(t, srv, "GET", "/pets", "")
		srv.Close()
		client.Flush()
		if n := len(in.entries()); n != 1 {
			t.Errorf("%+v: uploaded %d entries, want 1 (falls back to \"on\")", tc.s, n)
		}
		if got := draws.Load() != 0; got != tc.draws {
			t.Errorf("%+v: drew u = %v, want %v", tc.s, got, tc.draws)
		}
	}

	cfg, warnings := restless.NormalizeSamplingJSON([]byte(`[1]`),
		[]byte(`{"default":"OFF","routes":{"G3T /x":"off","GET /y":"0.5","GET /z":true}}`))
	if cfg.Default().String() != "on" || len(cfg.RouteKeys()) != 2 {
		t.Errorf("invalid input normalized to %v %v", cfg.Default(), cfg.RouteKeys())
	}
	if len(warnings) != 5 {
		t.Errorf("got %d warnings, want 5: %q", len(warnings), warnings)
	}
}

func TestSamplingTypedDuplicatesAreDeterministic(t *testing.T) {
	// "GET /a" and "get /a" normalize to the same key. A map has no order,
	// so the later in byte order wins: "get /a" sorts after "GET /a".
	for i := 0; i < 20; i++ {
		in := &ingest{reply: `{}`}
		client, _ := newSamplingClient(t, in, restless.Sampling{Routes: map[string]restless.SamplingMode{
			"GET /health": restless.SampleOn,
			"get /health": restless.SampleOff,
		}}, 0)
		srv := petsServer(client)
		res := do(t, srv, "GET", "/health", "")
		srv.Close()
		if res.headers.Get("x-request-id") != "" {
			t.Fatal("duplicate normalized keys did not resolve to the later one in byte order")
		}
	}
}

func TestSamplingModeJSON(t *testing.T) {
	for mode, want := range map[restless.SamplingMode]string{
		restless.SampleOn:          `"on"`,
		restless.SampleOff:         `"off"`,
		restless.SampleErrors:      `"errors"`,
		restless.SampleRate(0.1):   `0.1`,
		restless.SampleRate(0.001): `0.001`,
	} {
		got, err := json.Marshal(mode)
		if err != nil || string(got) != want {
			t.Errorf("%v marshals to %s (%v), want %s", mode, got, err, want)
		}
	}
}
