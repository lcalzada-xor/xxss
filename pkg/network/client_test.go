package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Do_Retry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(1*time.Second, "", 1, 0)
	req, _ := http.NewRequest("GET", server.URL, nil)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestClient_Do_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Simulate slow response
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(1*time.Second, "", 1, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)

	_, err := client.Do(req)
	if err == nil {
		t.Fatal("Expected error due to context cancellation, got nil")
	}
}

func TestClient_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 1 request per second. Initial burst = 1.
	client := NewClient(1*time.Second, "", 1, 1)

	start := time.Now()
	// 1st request: consumes initial token (immediate)
	// 2nd request: waits for 1s
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)

	// Should take at least 1s (minus some buffer)
	if elapsed < 900*time.Millisecond {
		t.Errorf("Rate limiting too fast: %v", elapsed)
	}
}
