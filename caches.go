package restless

import (
	"sync"
	"time"
)

// In-process caches. Implements CONTRACT.md section 11.
//
// All three are mutex-guarded: unlike the Node and Python SDKs, a Go server
// handles requests on many goroutines concurrently, so an unsynchronized map
// here is not a race in theory but a crash in practice (Go's runtime aborts
// the process on concurrent map access).

const (
	enrichTTL           = time.Hour       // CACHE-004
	recoveryTTL         = time.Hour       // CACHE-014
	recoveryNegativeTTL = 5 * time.Minute // CACHE-014
)

type enrichEntry struct {
	value OwnerDetails
	at    time.Time
}

// EnrichCache stores the enriched VALUE, not merely a freshness flag
// (CACHE-003). Every upload has to carry owner metadata, including uploads
// that skipped the callback, because the ingest cannot backfill it.
type EnrichCache struct {
	mu      sync.RWMutex
	entries map[string]enrichEntry
	ttl     time.Duration
}

func NewEnrichCache() *EnrichCache {
	return &EnrichCache{entries: map[string]enrichEntry{}, ttl: enrichTTL}
}

func (c *EnrichCache) Get(key string) (OwnerDetails, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Since(entry.at) > c.ttl {
		c.Invalidate(key)
		return nil, false
	}
	return entry.value, true
}

func (c *EnrichCache) Set(key string, value OwnerDetails) {
	c.mu.Lock()
	c.entries[key] = enrichEntry{value: value, at: time.Now()}
	c.mu.Unlock()
}

// Invalidate drops a key so the next request re-runs enrich (CACHE-006).
func (c *EnrichCache) Invalidate(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

func (c *EnrichCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

type recoveryEntry struct {
	message string
	present bool // false means "server confirmed there is no message"
	at      time.Time
}

// RecoveryCache maps a fingerprint key to a recovery message.
//
// Every read is synchronous and in-process (CACHE-010). The lookup sits on
// the hot path of every 4xx/5xx, so it never performs I/O and never blocks
// the response; a cold miss simply injects nothing.
//
// "No message for this fingerprint" is itself cached, with a shorter TTL, so
// a cold miss does not stay a cold miss on every subsequent request and a
// freshly-attached dashboard message still starts working within minutes.
type RecoveryCache struct {
	mu          sync.RWMutex
	entries     map[string]recoveryEntry
	ttl         time.Duration
	negativeTTL time.Duration
}

func NewRecoveryCache() *RecoveryCache {
	return &RecoveryCache{
		entries:     map[string]recoveryEntry{},
		ttl:         recoveryTTL,
		negativeTTL: recoveryNegativeTTL,
	}
}

// Lookup is the hot-path read: a message to inject, or "" (CACHE-010).
func (c *RecoveryCache) Lookup(key string) string {
	entry, known := c.entry(key)
	if !known || !entry.present {
		return ""
	}
	return entry.message
}

// Known reports whether we have any answer for this key, positive or
// negative. Used to honour CACHE-013: a negative entry must never clobber a
// positive one.
func (c *RecoveryCache) Known(key string) bool {
	_, known := c.entry(key)
	return known
}

func (c *RecoveryCache) entry(key string) (recoveryEntry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return recoveryEntry{}, false
	}
	ttl := c.ttl
	if !entry.present {
		ttl = c.negativeTTL
	}
	if time.Since(entry.at) > ttl {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return recoveryEntry{}, false
	}
	return entry, true
}

func (c *RecoveryCache) Set(key, message string) {
	c.mu.Lock()
	c.entries[key] = recoveryEntry{message: message, present: true, at: time.Now()}
	c.mu.Unlock()
}

// SetAbsent negative-caches a key (CACHE-012).
func (c *RecoveryCache) SetAbsent(key string) {
	c.mu.Lock()
	c.entries[key] = recoveryEntry{present: false, at: time.Now()}
	c.mu.Unlock()
}

func (c *RecoveryCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Blocklist is a set of masked keys to reject. O(1) lookup, per-process.
type Blocklist struct {
	mu      sync.RWMutex
	blocked map[string]bool
}

func NewBlocklist() *Blocklist {
	return &Blocklist{blocked: map[string]bool{}}
}

func (b *Blocklist) Replace(maskedKeys []string) {
	next := make(map[string]bool, len(maskedKeys))
	for _, key := range maskedKeys {
		next[key] = true
	}
	b.mu.Lock()
	b.blocked = next
	b.mu.Unlock()
}

func (b *Blocklist) Has(maskedKey string) bool {
	if maskedKey == "" {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.blocked[maskedKey]
}

func (b *Blocklist) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.blocked)
}
