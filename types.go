package restless

// OwnerDetails is fully-resolved owner data, ready for the wire: whatever
// the user's enrich callback returned.
type OwnerDetails map[string]any

// Owner is what the user puts under Owner in their setup result.
//
// ID is the PERMANENT, IMMUTABLE identifier for the workspace, tenant or
// end-user this request belongs to (SETUP-002). The dashboard pins a
// project's entire log history to it, so it must be something that will
// never change: a database primary key or a workspace UUID. Never an API
// key, an email, a username, or any other rotatable value.
//
// Enrich is the ONLY channel for owner metadata (SETUP-003). It runs once
// per ID and then caches, so the lookup cost is amortized; inline metadata
// fields are not supported and anything other than ID is dropped.
type Owner struct {
	ID     string
	Enrich func(ownerID string) OwnerDetails
}

// Block rejects a request before the handler runs (SETUP-004).
type Block struct {
	Status  int
	Message string
}

// SetupResult is what the per-request callback returns.
//
// Keep the top-level fields CHEAP - read straight off the request. Anything
// expensive belongs in Owner.Enrich, which the SDK calls lazily and dedups
// by owner ID.
type SetupResult struct {
	// APIKey is the MASKED end-user key. Pass the raw header through Mask;
	// never substitute a placeholder like "anonymous", whose last 4
	// characters would become the mask tail (SETUP-001).
	APIKey string
	Owner  *Owner
	Block  *Block
	// Extra fields are stored on the log as-is (SETUP-005).
	Extra map[string]any
}

// UserContext is the resolved per-request user data stored on a log.
type UserContext struct {
	APIKey string
	// Owner carries the resolved owner: its ID plus whatever Enrich
	// returned. The wire field is named projectId (WIRE-019); the
	// user-facing concept is the owner.
	Owner OwnerDetails
}

// SetupFunc is the per-request callback registered with Client.Setup.
type SetupFunc func(r *RequestInfo) SetupResult
