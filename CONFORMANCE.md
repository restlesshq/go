# Conformance

| | |
|---|---|
| **Spec version** | 1.3.0 |
| **Level** | L2 (core + batching, caches, injection, safety) |
| **Reference** | `restlesshq/node` (`@restlessai/sdk`) |
| **Driver** | `go run ./cmd/conformance` |

Declared in `version.go` (META-001).

## Verifying

The harness and vectors live in the reference SDK, so the commands below
assume it is checked out as a sibling (`../node`), which is how
`setup.sh` in the install repo arranges things. The vectors in `spec/` here
are a pinned copy, so `go test ./...` alone works without it.


```sh
# in-process, no Node needed
go test ./...

# the shared cross-language harness
go build -o /tmp/conformance ./cmd/conformance
node ../node/spec/harness/run-vectors.mjs -- /tmp/conformance

# differential fuzz against the reference implementation
node ../node/spec/harness/fuzz.mjs \
  --ref  "node ../node/spec/driver/.build/node.js" \
  --test "/tmp/conformance" \
  --iterations 20000
```

Current status: **252 vectors, 244 passed, 0 failed, 8 skipped.** Zero
divergence across ~90,000 fuzz comparisons on five seeds (24301, 90210, 7,
1337, 5), about a quarter of them on the sampling ops.

The 8 skips are cases outside this implementation's dialect, not gaps:

- 7 `fp/stack-*` cases feed a v8-shaped stack into `fingerprint`. FP-044
  makes frame parsing per-language and FP-046 requires the driver to say so
  rather than guess. Covered natively in `stack_test.go`.
- 1 `redactBody/lone-surrogate` case. See the exemption below.

FP-042 is explicitly NOT dialect-exempt and is verified here through the
`projectRelative` op, which takes an already-extracted path.

## Go-specific decisions

Each of these is a place where the obvious Go code silently disagrees with
the reference. They are the reason this SDK is byte-compatible.

| Contract | What Go needs |
|---|---|
| PRIM-010 | `len()` is BYTES. Code-point counts go through `utf8.RuneCountInString`, and tails through `[]rune` slicing (`text.go`). |
| PRIM-002 | The whitespace set is enumerated as escapes. Go refuses to compile a source file containing a literal U+FEFF anywhere but the first byte. |
| PRIM-004 | RE2 has no lookahead, which is exactly why `NormalizeRoute` is specified as a whole-segment test. It ports as a direct transliteration. |
| PRIM-020 | `strings.ToLower` is SIMPLE case mapping; the contract wants FULL. They differ on U+0130, which moves a fingerprint. `fullLower` handles it, and it is the only unconditional case. Final_Sigma is deliberately not implemented: PRIM-021 is non-normative and documents that no algorithm in the contract can observe it. |
| REDACT-010 | Denylist name normalization uses full Unicode lowercase, not an ASCII fold, and this is a **security** requirement. A key spelled `toKen` with U+212A KELVIN SIGN lowercases to `token` and must be redacted; an ASCII-only fold leaves it unmatched and ships the secret. An ASCII-only fold is the easy mistake here and leaks the value; `normalizeName` now shares `fullLower` with FP-020, and `redact_test.go` pins the KELVIN case in a header, a body key and a query parameter. |
| PRIM-030..032 | `encoding/json` sorts map keys, loses int64 precision, and HTML-escapes `<`/`>`/`&` - which would mangle the `<REDACTED:...>` sentinel the dashboard pattern-matches on. `orderedjson.go` exists entirely for this. |
| PRIM-040 | Hand-built timestamp. `time.RFC3339Nano` emits nanoseconds and strips trailing zeros, so the digit count would vary per request. |
| REDACT-028 | `net/url.QueryEscape` uses a different safe set and turns a space into `+`. The unreserved set is spelled out. |
| BATCH-008 | Test detection keys on the `.test` binary suffix and `-test.*` flags. |
| FP-042 | "The LAST project dir" is a segment scan, not a regex. RE2 has no lookahead to express a rightmost match in one pass, and the loop is clearer than a reversed pattern would be anyway. |
| FP-043 | Go's `debug.Stack()` is innermost-FIRST, like v8 and unlike a Python traceback, so the walk goes forwards. |
| FP-044 | Frames are `func\n\tfile.go:line`. Stdlib frames are skipped via `runtime.GOROOT()` rather than a hardcoded path, and the SDK's own frames by package prefix *with* the trailing separator (without it, `github.com/restlesshq/go` also matches `..._test`). |
| SAMPLE-002 | The rate is quantized as `math.Floor(float64(r*10000) + 0.5)`. The Go spec lets the compiler fuse `x*y+z` into one FMA instruction (arm64 does), which skips rounding the product; the explicit conversion forces the two roundings JavaScript performs. A search around every half step found no rate in [0, 1] where fusion moves the result, so this is insurance, not a known divergence. |
| SAMPLE-013 | Route key ORDER decides which of two keys normalizing to the same one wins. `encoding/json` into a map has already lost it, so the settings file's `sampling` is kept as `json.RawMessage` and decoded with the order-preserving parser in `orderedjson.go`, and the driver hands the sampling ops their raw input for the same reason. `WithSampling` takes a Go map, which has no order at all: its keys are taken in sorted byte order, so the later key in byte order wins. That is deterministic, which map iteration is not. |
| SAMPLE-032 | `net/http` commits the status at `WriteHeader`, a first `Write`, or a `Flush`, so the recorder decides at the first of those (or at the end of a handler that wrote nothing, or at a panic) and takes the id header back there on a drop. `Flush` before any write goes through `WriteHeader`, and a held 4xx/5xx is not flushed early. |
| BATCH-009 | The in-flight count lives under the uploader's mutex, so taking a slot and splitting a batch off the queue are one step; a freed slot wakes `Flush` through a `sync.Cond`. A goroutine sleeping before a WIRE-026 retry keeps its slot. |
| WIRE-026 | Only the default transport reports a status the uploader can retry on; a custom `WithTransport` func returning an error gets no retry unless the error is a dial failure. "Never reached the ingest" is any `net.OpError` with `Op == "dial"` or a `net.DNSError`, minus timeouts. That is slightly wider than Node's three error codes (it includes host and network unreachable), and still nothing was sent. |
| WIRE-028 | A `context.WithTimeout` per attempt, so each retry gets its own 10 s and the deadline also covers reading the response body. The deadline error is a timeout, so it is never retried. |
| CACHE-* | Every cache is mutex-guarded. Go serves requests on many goroutines, so an unsynchronized map is not a theoretical race - the runtime aborts the process. |

## Exemption: PRIM-034 (unpaired surrogates)

This SDK claims the **PRIM-035 exemption**. A Go `string` is UTF-8 by
definition and cannot hold an unpaired surrogate; `encoding/json` replaces
one with U+FFFD while decoding, before any SDK code runs. Rust has the same
constraint for the same reason.

Per PRIM-035 the SDK never raises on such input and substitutes U+FFFD. The
conformance driver reports `unsupported` for any input LINE containing a
lone surrogate escape, because the limitation is at the transport layer
rather than in redaction.

The sampling ops are the one exception, and are run anyway. Every string
they read is a route key, a path or a mode, each valid only as printable
ASCII (SAMPLE-001, SAMPLE-010), so an unpaired surrogate and the U+FFFD it
decodes to are both rejected and the output cannot differ. The fuzz key
generator oversamples surrogates, so refusing them would only cost coverage.
