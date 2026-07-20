// Package privacy enforces the server-side offload privacy guardrails.
//
// - strict_zk content is rejected (403)
// - No logging of input or output content
// - Memory is zeroed after inference
// - Rate-limited per tenant
package privacy

import (
	"sync"
	"time"
)

// Guard enforces privacy constraints for server-side AI inference.
type Guard struct {
	mu     sync.Mutex
	limits map[string]*rateLimiter
}

type rateLimiter struct {
	count    int
	window   time.Time
	maxReqs  int
	interval time.Duration
}

// maxRateLimitEntries caps the rate limiter map to prevent unbounded growth.
const maxRateLimitEntries = 10000

// NewGuard creates a new privacy guard with default rate limits.
func NewGuard() *Guard {
	return &Guard{
		limits: make(map[string]*rateLimiter),
	}
}

// Check verifies that the request is allowed under privacy constraints.
// folderMode must be "managed_encrypted" — "strict_zk" is rejected.
func (g *Guard) Check(tenantID, folderMode string) error {
	if folderMode == "strict_zk" {
		return ErrStrictZkForbidden
	}
	if folderMode != "managed_encrypted" {
		return ErrInvalidFolderMode
	}

	// Rate limit: 100 requests per minute per tenant
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()

	// Evict expired entries periodically to prevent unbounded map growth
	if len(g.limits) > maxRateLimitEntries {
		for id, rl := range g.limits {
			if now.Sub(rl.window) >= rl.interval {
				delete(g.limits, id)
			}
		}
	}

	rl, ok := g.limits[tenantID]
	if !ok {
		rl = &rateLimiter{
			maxReqs:  100,
			interval: time.Minute,
		}
		g.limits[tenantID] = rl
	}

	if now.Sub(rl.window) >= rl.interval {
		rl.count = 0
		rl.window = now
	}

	if rl.count >= rl.maxReqs {
		return ErrRateLimited
	}

	rl.count++
	return nil
}

// Wipe zeroes a byte slice in-place. Called after inference to
// ensure no plaintext remains in memory.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Errors
type PrivacyError string

func (e PrivacyError) Error() string { return string(e) }

const (
	ErrStrictZkForbidden PrivacyError = "ai offload not available for strict_zk folders"
	ErrInvalidFolderMode PrivacyError = "invalid folder encryption mode"
	ErrRateLimited       PrivacyError = "rate limit exceeded for tenant"
)
