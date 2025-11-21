package network

import (
	"sync"
	"time"
)

// RateLimiter implements token bucket algorithm for rate limiting
type RateLimiter struct {
	rate       float64    // requests per second
	tokens     float64    // current tokens
	maxTokens  float64    // max tokens (burst size)
	lastUpdate time.Time  // last token update time
	mu         sync.Mutex // mutex for thread safety
}

// NewRateLimiter creates a new rate limiter
// rate: requests per second (0 = unlimited)
func NewRateLimiter(rate float64) *RateLimiter {
	if rate <= 0 {
		return nil // No rate limiting
	}

	return &RateLimiter{
		rate:       rate,
		tokens:     rate,
		maxTokens:  rate * 2, // Allow burst of 2x rate
		lastUpdate: time.Now(),
	}
}

// Wait blocks until a token is available
func (rl *RateLimiter) Wait() {
	if rl == nil {
		return // No rate limiting
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.tokens += elapsed * rl.rate

	// Cap at max tokens
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}

	rl.lastUpdate = now

	// If no tokens available, wait
	if rl.tokens < 1 {
		waitTime := time.Duration((1-rl.tokens)/rl.rate*1000) * time.Millisecond
		rl.mu.Unlock()
		time.Sleep(waitTime)
		rl.mu.Lock()
		rl.tokens = 0
	} else {
		rl.tokens -= 1
	}
}
