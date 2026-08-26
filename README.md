<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/restless-init-dark.svg">
  <img width="100%" src="docs/restless-init.svg" alt="Restless">
</picture>

Run in your codebase to get started:

```sh
npx restless init
```

# restless-sdk-go

Capture your API traffic and send it to [Restless](https://restless.ai).

Wraps any `net/http` handler, so it works with the standard library, chi,
gorilla/mux, Echo and Gin. Go 1.23+. **No dependencies.**

## Install

```sh
go get github.com/restlesshq/go
```

## Use

```go
import restless "github.com/restlesshq/go"

client := restless.MustNew(os.Getenv("RESTLESS_KEY"))

client.Setup(func(r *restless.RequestInfo) restless.SetupResult {
    return restless.SetupResult{
        APIKey: restless.Mask(r.Header("Authorization")),
        Owner: &restless.Owner{
            // Permanent and immutable. A workspace id or database primary
            // key, never an API key, email, or anything else that rotates:
            // the dashboard pins a project's whole log history to this.
            ID: workspaceIDFor(r.Request),
            // Runs once per owner id, then caches. Put the expensive lookup
            // here, not in the fields above.
            Enrich: func(id string) restless.OwnerDetails {
                ws := db.Workspace(id)
                return restless.OwnerDetails{"label": ws.Name, "email": ws.AdminEmails}
            },
        },
    }
})

http.ListenAndServe(":8080", client.Middleware()(mux))
```

### Route patterns

The middleware reads `http.Request.Pattern` automatically, so a Go 1.23+
`ServeMux` needs no extra wiring. For another router, pass a resolver:

```go
// chi
client.Middleware(func(r *http.Request) string {
    return chi.RouteContext(r.Context()).RoutePattern()
})
```

Route patterns matter more than they look: without one, every `/pets/1`,
`/pets/2` is its own group, and a 404 on a missing *record* cannot be told
apart from a 404 on an endpoint that does not exist.

## What you get

- **Lazy owner enrichment.** `Enrich` runs on the first request from each
  owner id and then caches, so a hundred requests from one workspace do not
  mean a hundred database lookups.
- **Safe by default.** `Authorization`, `Cookie`, `password`, `token`, `ssn`
  and friends are redacted before anything leaves your process. Bodies with
  nothing to redact are passed through untouched, so your payloads are not
  reserialized on the way out and large integers keep their precision.
- **Error triage.** Every response gets `x-log-url` and `x-debug` headers,
  and 4xx/5xx responses also get a `debug` block in the JSON body. If someone attaches a "next steps"
  message to an error in the dashboard, the SDK injects it as
  `debug.recovery` - read synchronously from an in-process cache, never
  blocking the response on a network call.
- **Panics are captured.** An unhandled panic is logged with its stack (so
  crashes group by the panicking function) and then re-panicked, leaving
  `net/http`'s own handling exactly as it was. The file in that group is cut
  at the last `src/`, `lib/`, `app/`, `api/`, `routes/`, `controllers/` or
  `handlers/` segment, so one source file groups identically on your laptop
  and in a container rooted at `/app`. While panic grouping rolls out, a
  crash also reports the group it used to land in, so a "next steps" message
  you already attached keeps being injected.
- **Blocking.** Return a `Block` from the setup callback to reject a request
  before your handler runs.

## Never breaks your API

Observability must not take down a production request path. Panics in the
setup callback, in `Enrich`, and inside the SDK are all recovered; upload
failures are swallowed (surfaced only under `DEBUG=restless`). Uploads run on
their own goroutine and never block a response.

## Environment variables

| variable | purpose |
|---|---|
| `RESTLESS_KEY` | Your project API key, if you do not pass one explicitly. |
| `RESTLESS_BASE_URL` | Override the ingest URL (self-hosted or staging). |
| `DEBUG=restless` | Print upload diagnostics to stderr. |

## Conformance

Implements version 1.0.0 of the Restless SDK Contract at level L2, verified
against the shared cross-language conformance vectors. See
[CONFORMANCE.md](./CONFORMANCE.md).

## License
MIT
