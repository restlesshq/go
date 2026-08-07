// Command conformance is the Go conformance driver.
// See node-sdk/spec/driver/PROTOCOL.md.
//
// Dev-only: it lives under cmd/ so it is not part of the importable API and
// no customer ever runs it.
//
//	go run ./cmd/conformance
//
// Reads JSON Lines on stdin, writes JSON Lines on stdout. The body is a thin
// shell over internal/conformance, which vectors_test.go also uses.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/restlesshq/go/internal/conformance"
)

type request struct {
	ID    json.RawMessage `json:"id"`
	Op    string          `json:"op"`
	Input map[string]any  `json:"input"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	// Vectors and fuzz inputs can exceed the default 64KiB line limit.
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)

	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var out map[string]any
		if conformance.HasLoneSurrogateEscape(line) {
			// Checked on the RAW LINE, because this is a TRANSPORT limit
			// rather than an SDK one: encoding/json replaces an unpaired
			// surrogate with U+FFFD while decoding, so by the time any op
			// runs the input is already gone. A Go string is UTF-8 and has
			// no encoding for one; Rust has the same constraint (PRIM-035).
			out = map[string]any{
				"id": idOf(line),
				"error": "unsupported: input line contains an unpaired surrogate " +
					"escape, which a UTF-8-native string cannot represent (PRIM-035)",
			}
		} else {
			var req request
			if err := json.Unmarshal([]byte(line), &req); err != nil {
				out = map[string]any{"id": nil, "error": err.Error()}
			} else if result, err := conformance.Dispatch(req.Op, req.Input); err != nil {
				out = map[string]any{"id": req.ID, "error": err.Error()}
			} else {
				out = map[string]any{"id": req.ID, "result": result}
			}
		}

		emit(writer, out)
		writer.Flush()
	}
}

// idOf best-effort extracts the id so the harness can still correlate a
// response for a line we refuse to fully decode.
func idOf(line string) any {
	var only struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal([]byte(line), &only) == nil {
		return only.ID
	}
	return nil
}

func emit(w *bufio.Writer, out map[string]any) {
	enc := json.NewEncoder(w)
	// SetEscapeHTML(false) so the driver's own transport does not mangle a
	// `<REDACTED:...>` sentinel into `\u003cREDACTED...` and report a false
	// failure against a value the SDK produced correctly.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode failed: %v\n", err)
	}
}
