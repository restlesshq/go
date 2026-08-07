# Conformance

| | |
|---|---|
| **Spec version** | 1.0.0 |
| **Level** | L2 (core + batching, caches, injection, safety) |
| **Reference** | `restlesshq/node` (`@restlessai/sdk`) |
| **Driver** | `go run ./cmd/conformance` |

Declared in `version.go` (META-001).

## Verifying

The harness and vectors live in the reference SDK, so the commands below
assume it is checked out as a sibling (`../node-sdk`), which is how
`setup.sh` in the install repo arranges things. The vectors in `spec/` here
are a pinned copy, so `go test ./...` alone works without it.


```sh
# in-process, no Node needed
go test ./...

# the shared cross-language harness
go build -o /tmp/conformance ./cmd/conformance
node ../node-sdk/spec/harness/run-vectors.mjs -- /tmp/conformance

# differential fuzz against the reference implementation
node ../node-sdk/spec/harness/fuzz.mjs \
  --ref  "node ../node-sdk/spec/driver/.build/node.js" \
  --test "/tmp/conformance" \
  --iterations 20000
```

Current status: **208 vectors, 199 passed, 0 failed, 9 skipped.** Zero
divergence across ~28,000 fuzz comparisons on four seeds (24301, 90210, 7,
1337).

The 9 skips are cases outside this implementation's dialect, not gaps:

- 8 `fp/stack-*` cases feed a v8-shaped stack into `fingerprint`. FP-044
  makes frame parsing per-language and FP-046 requires the driver to say so
  rather than guess. Covered natively in `stack_test.go`.
- 1 `redactBody/lone-surrogate` case. See the exemption below.

`fp/stack-carries-previous-key` is the eighth of those; it is a v8 stack like
the rest, so FP-047's output is pinned in `middleware_test.go` instead.
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

## Optional requirements

| Contract | Status |
|---|---|
| FP-047 (SHOULD, transitional) | **Implemented.** A `stack` fingerprint carries `PreviousKey`, the key the ladder would have produced without it. Both keys go up in the batch's fingerprint list, so the ingest can answer for either, and `Engine.LookupRecoveryFor` prefers the current key and falls back to the previous one. Without it, making the stack strategy reachable would move the key for every uncaught 5xx and silently orphan the Agent Recovery message attached to the old one. Remove once no project has a recovery message on a 5xx `message`-strategy group. |
