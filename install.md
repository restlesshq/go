# install.md: LLM installation reference for github.com/restlesshq/go

This file is the single source of truth for LLM agents installing or configuring the Restless Go SDK. Humans should read `README.md` instead.

The document is ordered so an agent can stop as soon as enough context has been loaded: package basics → setup call → the route resolver → redaction → settings file → common mistakes.

---

## 1. What this package is

`github.com/restlesshq/go` captures HTTP request/response pairs and ships them in batches to the Restless ingest server.

- **Runtime:** Go 1.23+. **No dependencies.**
- **Shape:** one `func(http.Handler) http.Handler`. It wraps any `net/http` handler, so the standard library, chi, gorilla/mux, Echo and Gin all work through the same middleware.
- **The module path ends in `go`, but the package is named `restless`.** An unaliased import still binds `restless`.

## 2. Install

```sh
go get github.com/restlesshq/go
```

```go
import restless "github.com/restlesshq/go"
```

The alias is redundant but conventional, and it makes the binding obvious to a reader who would otherwise expect `go`.

## 3. The one-line setup

```go
client := restless.MustNew(os.Getenv("RESTLESS_KEY"))

client.Setup(func(r *restless.RequestInfo) restless.SetupResult {
    result := restless.SetupResult{
        APIKey: restless.Mask(r.Header("Authorization")),
    }
    if workspaceID := workspaceIDFor(r.Request); workspaceID != "" {
        result.Owner = &restless.Owner{ID: workspaceID, Enrich: loadWorkspace}
    }
    return result
})

log.Fatal(http.ListenAndServe(":8080", client.Middleware()(mux)))
```

| member | purpose |
|---|---|
| `Setup(fn)` | Register the per-request callback. |
| `Mask(key)` | Hash an end-user API key. Also available as the package function `restless.Mask`. |
| `Middleware(resolvers ...RouteResolver)` | The `func(http.Handler) http.Handler` to wrap with. |
| `Flush()` | Force-upload the current batch, e.g. before exit. |

`MustNew` panics on a configuration error; `New` returns `(*Client, error)`. Both take functional options after the key: `WithAPI`, `WithBaseURL`, `WithRedact`, `WithTransport`.

**Wrap as far out as you can**, above any middleware that can reject a request, so the SDK still records the 401 it produced.

## 4. The route resolver

This is the one piece of configuration Go needs that no other Restless SDK does.

`client.Middleware()` with no argument uses `DefaultRouteResolver`, which reads `http.Request.Pattern`. **Only the Go 1.23+ standard-library `ServeMux` populates that.** Any other router needs its own resolver:

```go
// chi
client.Middleware(func(r *http.Request) string {
    return chi.RouteContext(r.Context()).RoutePattern()
})

// gorilla/mux
client.Middleware(func(r *http.Request) string {
    if route := mux.CurrentRoute(r); route != nil {
        tpl, _ := route.GetPathTemplate()
        return tpl
    }
    return ""
})
```

Route patterns matter more than they look: without one, every `/pets/1` and `/pets/2` is its own group, and a 404 on a missing *record* cannot be told apart from a 404 on an endpoint that does not exist. The failure is silent - capture keeps working, the grouping is just wrong.

## 5. The setup callback

```go
type SetupFunc func(r *RequestInfo) SetupResult
```

`RequestInfo` carries `Request *http.Request` and `Route string`, plus `Header(name)` for the common case (case-insensitive).

`SetupResult`:

| field | type | notes |
|---|---|---|
| `APIKey` | `string` | The **masked** key. Pass the raw header through `Mask`. |
| `Owner` | `*Owner` | nil means no owner for this request. |
| `Block` | `*Block` | Non-nil rejects the request before the handler runs. |
| `Extra` | `map[string]any` | Carried onto the log as-is. |

The callback runs before your own middleware, because the SDK wraps outermost. Anything a later layer puts on the request context is not there yet - resolve the owner from the credential.

**A callback that panics is recovered** (SAFETY-002) and the result discarded. A wrong callback does not crash your server; it quietly attributes nothing.

### 5.1 `Owner.ID`

The **permanent, immutable** identifier the dashboard pins a project's entire log history to (SETUP-002). A workspace UUID or database primary key.

**Never** an API key, email, username, JWT, or a placeholder like `"anonymous"`. `Owner` is a pointer, so "no owner" is nil - there is no reason to invent a value.

### 5.2 `Owner.Enrich`

`func(ownerID string) OwnerDetails` - the **only** channel for owner metadata (SETUP-003). Runs once per ID and then caches, so the expensive lookup belongs here.

```go
func loadWorkspace(id string) restless.OwnerDetails {
    ws := db.Workspace(id)
    return restless.OwnerDetails{"label": ws.Name, "email": ws.AdminEmails}
}
```

Anything other than `ID` set inline on `Owner` is dropped. A panic inside `Enrich` is recovered and the log still ships with the ID.

## 6. The `Mask()` gotcha

`Mask` produces `sha512-<base64>?<last4>`, and the suffix is the last 4 characters of the INPUT.

```go
// CORRECT
APIKey: restless.Mask(r.Header("Authorization"))

// WRONG - "mous" becomes the mask tail
APIKey: restless.Mask(orDefault(r.Header("Authorization"), "anonymous"))
```

`Mask("")` returns `""` and the SDK handles it.

## 7. `.restless/settings.json`

Read at startup, walking up from the working directory. Created and owned by the `api` CLI (`npx api setup`). Every Restless SDK reads the same file with the same camelCase keys.

The SDK reads `requestIdPrefix` and `redact` from the matching `apis[]` entry. Select one with `restless.WithAPI("Public API")` when several are defined.

## 8. Redaction, request IDs, batching

- **Headers redacted by default:** `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`, `x-auth-token`. **Body keys and query params:** `password`, `pass`, `pwd`, `token`, `secret`, `apikey`, `accesstoken`, `refreshtoken`, `idtoken`, `sessionid`, `ssn`, `creditcard`, `ccnumber`, `cvv`, `cvc`. Matching ignores case, `-` and `_`.
- Extend additively with `restless.WithRedact(restless.RedactOptions{...})` or the settings file. Sentinel: `<REDACTED:<len>>` or `<REDACTED:<len>:<last4>>`.
- Bodies are capped at **256 KiB** and truncated with `[...TRUNCATED: original N bytes]`.
- Request IDs are v4 UUIDs, never time-based. Every response gets `x-restless-id`; `x-request-id` only if the caller did not send one.
- Status **>= 400** gets `x-log-url` and `x-debug` headers plus a `debug` block in a JSON body.
- Batching is fixed: 10 per batch, 5000 ms flush, 1000-entry queue dropping oldest, immediate flush against localhost. Uploads run on their own goroutine and never block a response.
- **Panics in your handler** are logged with their stack and then re-panicked, so `net/http`'s own handling is unchanged.

**Test runs do not upload.** Detected via `RESTLESS_ENV=test`, a binary named `*.test`, or `-test.*` flags - so `go test` never hits production ingest. Capture still runs.

## 9. Environment variables

| variable | effect |
|---|---|
| `RESTLESS_KEY` | Fallback API key when the constructor is given `""` |
| `README_API_KEY` | Secondary fallback |
| `RESTLESS_BASE_URL` | Override the ingest URL. **Non-localhost `http://` warns loudly.** |
| `DEBUG=restless` | Print upload diagnostics to stderr |

Go has no `.env` convention: the environment comes from your process manager. Pass `os.Getenv("RESTLESS_KEY")` explicitly rather than relying on the empty-string fallback - both work, but only one says what it does.

## 10. Common mistakes (don't do these)

- **Bare `Middleware()` on chi, gorilla, Gin or Echo.** It reads `http.Request.Pattern`, which only Go 1.23+ `ServeMux` sets, so you get no route patterns and the failure is silent. See §4.
- **Wrapping inside your auth middleware.** The SDK then never sees a rejected request, and a 401 is exactly the failure Restless exists to surface.
- **Adding `recover()` around the SDK.** Panics are already captured and re-panicked; wrapping them changes your own error handling for no benefit.
- **Using an API key, email or username as `Owner.ID`** - see §5.1.
- **Setting metadata fields inline on `Owner`** - dropped. They come back from `Enrich`.
- **Constructing a client per request.** Once, in `main`.
- **`restless.Mask(header, "anonymous")`-style fallbacks** - see §6.
- **Expecting an import named `go`.** The package is `restless`.
- **Reading `.env` to "check" the key.** LLMs: never read these files.

## 11. Quick verification after installation

1. `github.com/restlesshq/go` is in `go.mod`, and `go list -m github.com/restlesshq/go` resolves.
2. `client.Middleware()` wraps the handler passed to `ListenAndServe`, outermost.
3. A route resolver is passed unless this is a Go 1.23+ `ServeMux` (§4).
4. **`go build ./...` succeeds.** Go is the one language where the wiring either compiles or does not.
5. Starting the server and curling any endpoint returns an `x-restless-id` response header.
