package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/v3/pkg/network"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner"
)

// BenchmarkScanWithPooling benchmarks scanning with optimized connection pooling
func BenchmarkScanWithPooling(b *testing.B) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + param + "</body></html>"))
	}))
	defer server.Close()

	// Create client with pooling (concurrency=40, default)
	client := network.NewClient(2*time.Second, "", 40, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.Scan(context.Background(), server.URL + "/?p=test")
	}
}

// BenchmarkScanLowConcurrency benchmarks with low concurrency (10)
func BenchmarkScanLowConcurrency(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + param + "</body></html>"))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.Scan(context.Background(), server.URL + "/?p=test")
	}
}

// BenchmarkScanHighConcurrency benchmarks with high concurrency (100)
func BenchmarkScanHighConcurrency(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + param + "</body></html>"))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "", 100, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.Scan(context.Background(), server.URL + "/?p=test")
	}
}

// BenchmarkParallelScans benchmarks parallel scanning
func BenchmarkParallelScans(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + param + "</body></html>"))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "", 40, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sc.Scan(context.Background(), server.URL + "/?p=test")
		}
	})
}
