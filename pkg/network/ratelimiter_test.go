package network

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter_Wait_Context(t *testing.T) {
	// 1 request per second
	rl := NewRateLimiter(1)

	// Consume the initial token
	rl.Wait(context.Background())

	// Next wait should block for ~1s
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := rl.Wait(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected context deadline exceeded error, got nil")
	}

	if elapsed > 200*time.Millisecond {
		t.Errorf("Wait took too long: %v", elapsed)
	}
}

func TestRateLimiter_Wait_Normal(t *testing.T) {
	// 10 requests per second = 100ms per token. Initial tokens = 10.
	rl := NewRateLimiter(10)

	// Consume initial burst (10 tokens)
	for i := 0; i < 10; i++ {
		rl.Wait(context.Background())
	}

	start := time.Now()
	// Now bucket is empty. Next wait should take ~100ms.
	err := rl.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < 90*time.Millisecond {
		t.Errorf("Rate limiting too fast: %v", elapsed)
	}
}
