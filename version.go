package restless

// Identity of this SDK, and the contract version it implements.
//
// META-001: the spec version an SDK implements must be recorded in a
// machine-readable form alongside its conformance level.
const (
	// SDKName is distinct per implementation (WIRE-016), so the ingest can
	// attribute a payload to a language.
	SDKName    = "restless-sdk-go"
	SDKVersion = "0.1.1"

	// SpecVersion is the spec/CONTRACT.md version this SDK is verified
	// against.
	SpecVersion = "1.0.1"

	// ConformanceLevel per CONTRACT.md 1.1: L1 is the pure functions, L2
	// adds batching, caches, injection and the safety guarantees.
	ConformanceLevel = "L2"
)
