package restless

import (
	"bytes"
	"io"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// net/http middleware. One wrapper covers the standard library, chi,
// gorilla/mux, and anything else that speaks http.Handler.

// SAFETY-007. Never buffer an unbounded response.
const maxCaptureBytes = 1024 * 1024

var streamingTypes = []string{"text/event-stream"}

// RouteResolver returns the templated route pattern for a request, e.g.
// "/pets/{id}". Frameworks expose this differently, so it is pluggable:
//
//	chi:   func(r *http.Request) string { return chi.RouteContext(r.Context()).RoutePattern() }
//	echo:  c.Path()
//	gin:   c.FullPath()
//
// Returning "" is fine and expected when nothing matched. ServeMux patterns
// are picked up automatically by DefaultRouteResolver.
type RouteResolver func(r *http.Request) string

// DefaultRouteResolver reads the ServeMux pattern (Go 1.23+).
//
// http.Request.Pattern includes the method and any host, e.g.
// "GET /pets/{id}", so the method is trimmed off to leave just the path
// template - which is what the contract's routePattern means and what every
// other SDK reports. Shipping "GET /pets/{id}" verbatim would split the
// dashboard's grouping and produce a junk recovery slug.
func DefaultRouteResolver(r *http.Request) string {
	pattern := r.Pattern
	if pattern == "" {
		return ""
	}
	if idx := strings.LastIndex(pattern, " "); idx != -1 {
		pattern = pattern[idx+1:]
	}
	if idx := strings.Index(pattern, "/"); idx > 0 {
		pattern = pattern[idx:] // strip a host prefix
	}
	return pattern
}

// Middleware returns the http.Handler wrapper.
func (c *Client) Middleware(resolvers ...RouteResolver) func(http.Handler) http.Handler {
	resolve := DefaultRouteResolver
	if len(resolvers) > 0 && resolvers[0] != nil {
		resolve = resolvers[0]
	}
	engine := c.engine

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := &RequestInfo{Request: r, Route: resolve(r)}
			setup := engine.Resolve(info)

			// SETUP-004. Reject before the handler runs.
			if setup.Block != nil {
				status := setup.Block.Status
				if status == 0 {
					status = 403
				}
				message := setup.Block.Message
				if message == "" {
					message = "Forbidden"
				}
				body := `{"error":"` + message + `"}`
				w.Header().Set("content-type", "application/json")
				w.Header().Set("content-length", strconv.Itoa(len(body)))
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
				return
			}

			reqHeaders, reqOrder := headerMap(r.Header)

			// Buffer the request body so the handler still sees it.
			var reqBody *string
			if r.Body != nil {
				limited := io.LimitReader(r.Body, maxCaptureBytes+1)
				buf, err := io.ReadAll(limited)
				if err == nil {
					if len(buf) <= maxCaptureBytes {
						s := string(buf)
						reqBody = &s
					}
					r.Body = io.NopCloser(bytes.NewReader(buf))
				}
			}

			rawID := NewRequestID()
			startedAt := NowISO()
			start := time.Now()

			for name, value := range RequestIDResponseHeaders(
				rawID, reqHeaders, engine.RequestIDPrefix(), engine.HasAPIKey()) {
				w.Header().Set(name, value)
			}

			rec := &responseRecorder{
				ResponseWriter: w,
				engine:         engine,
				rawID:          rawID,
				method:         r.Method,
				route:          info.Route,
				status:         200,
			}

			// SAFETY-001. A panic in the handler is the single most valuable
			// thing to log, and without this it is the one case that produces
			// no log at all: net/http recovers at the connection level and
			// writes its own 500, and this middleware never reaches Record.
			//
			// The stack goes through as StackTrace, which is what makes the
			// `stack` fingerprint strategy reachable (FP-040): panics group by
			// the panicking function rather than collapsing per route.
			//
			// Re-panicked unchanged, so net/http's own handling and any outer
			// middleware behave exactly as before.
			defer func() {
				if rec.finished {
					return
				}
				if p := recover(); p != nil {
					stack := string(debug.Stack())
					// The router matched before the handler ran and panicked,
					// so the pattern is available now even though it was not
					// before dispatch.
					route := info.Route
					if after := resolve(r); after != "" {
						route = after
					}
					engine.Record(CapturedRequest{
						RequestID:          rawID,
						StartedAt:          startedAt,
						Duration:           int(time.Since(start).Milliseconds()),
						RoutePattern:       route,
						Method:             r.Method,
						URL:                fullURL(r),
						RequestHeaders:     reqHeaders,
						requestHeaderOrder: reqOrder,
						RequestBody:        reqBody,
						Status:             500,
						ResponseHeaders:    map[string]string{"content-type": "text/plain"},
						StackTrace:         stack,
						User:               &UserContext{APIKey: setup.APIKey, Owner: setup.Owner},
					})
					panic(p)
				}
			}()

			next.ServeHTTP(rec, r)

			// Re-resolve. A router only knows which route matched once it HAS
			// matched, which happens inside next.ServeHTTP - so the value read
			// before dispatch is empty for a middleware wrapping a mux.
			// net/http's ServeMux fills r.Pattern on the request in place, and
			// chi's RouteContext works the same way, so reading again here is
			// what actually produces a route pattern.
			//
			// The pre-dispatch value is still passed to the setup callback,
			// which necessarily runs first; it is populated only when the
			// middleware is registered per-route rather than around the mux.
			if after := resolve(r); after != "" {
				rec.route = after
			}

			rec.finish(r, setup, reqHeaders, reqOrder, reqBody, startedAt, start)
		})
	}
}

// responseRecorder buffers the response so a 4xx/5xx body can be rewritten
// before it goes out (INJECT-003).
type responseRecorder struct {
	http.ResponseWriter
	engine *Engine
	rawID  string
	method string
	route  string

	status      int
	wroteHeader bool
	streaming   bool
	buf         bytes.Buffer
	overflow    bool
	finished    bool
}

func (rec *responseRecorder) WriteHeader(status int) {
	if rec.wroteHeader {
		return
	}
	rec.status = status
	rec.wroteHeader = true
	contentType := rec.Header().Get("content-type")
	for _, t := range streamingTypes {
		if strings.Contains(contentType, t) {
			rec.streaming = true
		}
	}
	// A success or a stream is passed straight through: there is no BODY to
	// inject, so there is no reason to hold the response.
	if rec.status < 400 || rec.streaming {
		// INJECT-002. The headers ship on every status, and this is the last
		// moment before the header block is committed to the client.
		for name, value := range DebugHeaders(
			rec.rawID, rec.engine.RequestIDPrefix(), rec.engine.PortalURL()) {
			rec.ResponseWriter.Header().Set(name, value)
		}
		rec.ResponseWriter.WriteHeader(status)
	}
}

func (rec *responseRecorder) Write(p []byte) (int, error) {
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	if rec.status < 400 || rec.streaming {
		if !rec.overflow && rec.buf.Len()+len(p) <= maxCaptureBytes {
			rec.buf.Write(p)
		} else {
			rec.overflow = true
		}
		return rec.ResponseWriter.Write(p)
	}
	// Held back for possible rewriting.
	if !rec.overflow && rec.buf.Len()+len(p) <= maxCaptureBytes {
		rec.buf.Write(p)
	} else {
		rec.overflow = true
	}
	return len(p), nil
}

// Flush implements http.Flusher so streaming handlers keep working.
func (rec *responseRecorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rec *responseRecorder) finish(
	r *http.Request, setup resolvedSetup,
	reqHeaders map[string]string, reqOrder []string, reqBody *string,
	startedAt string, start time.Time,
) {
	rec.finished = true
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}

	resHeaders, resOrder := headerMap(rec.Header())
	duration := int(time.Since(start).Milliseconds())

	var rawBody *string
	if !rec.overflow && !rec.streaming {
		s := rec.buf.String()
		rawBody = &s
	}

	var fingerprint *Fingerprint
	outBody := rawBody

	if rec.status >= 400 {
		// INJECT-009. Fingerprint the customer's RAW response, before any
		// injected header or body field is layered on.
		fingerprint = rec.engine.ComputeFingerprint(CapturedRequest{
			Method:          rec.method,
			RoutePattern:    rec.route,
			Status:          rec.status,
			ResponseHeaders: resHeaders,
			ResponseBody:    rawBody,
		})
		recovery := ""
		if fingerprint != nil {
			recovery = rec.engine.LookupRecovery(fingerprint.Key)
		}
		injection := BuildDebugInjection(
			rec.status, rec.rawID, rec.engine.RequestIDPrefix(),
			recovery, rec.method, rec.route, rec.engine.PortalURL())

		for name, value := range injection.Headers {
			rec.ResponseWriter.Header().Set(name, value)
		}
		if rawBody != nil {
			modified := ApplyInternalBodyMods(
				*rawBody, resHeaders["content-type"], injection.Mutate)
			if modified != *rawBody {
				// INJECT-008. Otherwise the client truncates mid-JSON.
				rec.ResponseWriter.Header().Set("content-length", strconv.Itoa(len(modified)))
				outBody = &modified
			}
		}
		rec.ResponseWriter.WriteHeader(rec.status)
		if outBody != nil {
			_, _ = io.WriteString(rec.ResponseWriter, *outBody)
		} else {
			_, _ = rec.ResponseWriter.Write(rec.buf.Bytes())
		}
		// Re-read: the injection added headers after the first snapshot.
		resHeaders, resOrder = headerMap(rec.Header())
	}

	rec.engine.Record(CapturedRequest{
		RequestID:           rec.rawID,
		StartedAt:           startedAt,
		Duration:            duration,
		RoutePattern:        rec.route,
		Method:              r.Method,
		URL:                 fullURL(r),
		RequestHeaders:      reqHeaders,
		requestHeaderOrder:  reqOrder,
		RequestBody:         reqBody,
		Status:              rec.status,
		ResponseHeaders:     resHeaders,
		responseHeaderOrder: resOrder,
		ResponseBody:        outBody,
		User:                &UserContext{APIKey: setup.APIKey, Owner: setup.Owner},
		ErrorFingerprint:    fingerprint,
	})
}

// headerMap flattens http.Header, preserving a deterministic order.
//
// HAR-004 wants capture order, and Go's map iteration is deliberately
// randomized, so the order is recorded separately rather than inferred.
// Duplicate values are joined with ", " as the reference does.
func headerMap(h http.Header) (map[string]string, []string) {
	out := make(map[string]string, len(h))
	order := make([]string, 0, len(h))
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		lower := strings.ToLower(name)
		out[lower] = strings.Join(h[name], ", ")
		order = append(order, lower)
	}
	return out, order
}

func fullURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("x-forwarded-proto"); forwarded != "" {
		scheme = forwarded
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host + r.URL.RequestURI()
}
