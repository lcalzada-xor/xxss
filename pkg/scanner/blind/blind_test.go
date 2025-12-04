package blind_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
	"github.com/lcalzada-xor/xxss/v3/pkg/models"
	"github.com/lcalzada-xor/xxss/v3/pkg/network"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/blind"
)

func TestBlindScanner_Injection(t *testing.T) {
	// We need to verify that the scanner sends requests with the correct payloads.
	// Since the scanner uses fire-and-forget goroutines, we need a way to wait or check results.
	// We can use a WaitGroup in the test server to wait for expected requests,
	// or just sleep a bit (less robust but easier for fire-and-forget).
	// Better: use a channel to collect received requests.

	receivedRequests := make(chan *http.Request, 100)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clone request to avoid race conditions if we read it later
		// But we can just read body here
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body)) // Restore for channel if needed, or just store body string

		receivedRequests <- r
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Setup scanner
	client := network.NewClient(10*time.Second, "", 5, 0)
	logger := logger.NewLogger(0) // Silent
	blindURL := "http://callback.com"
	scanner := blind.NewScanner(client, nil, logger, blindURL)

	t.Run("InjectContextualBlind", func(t *testing.T) {
		targetURL := server.URL + "/test?q=1"
		// Inject into 'q'
		scanner.InjectContextualBlind(targetURL, "q", models.ContextHTML)

		// Wait for requests
		// We expect multiple payloads for ContextHTML
		// Let's wait a short duration to collect them
		time.Sleep(500 * time.Millisecond)

		found := false
		count := 0

		// Drain channel
	Loop:
		for {
			select {
			case req := <-receivedRequests:
				count++
				q := req.URL.Query().Get("q")
				if strings.Contains(q, blindURL) || strings.Contains(q, "callback.com") {
					found = true
				}
			default:
				break Loop
			}
		}

		if count == 0 {
			t.Errorf("Expected requests, got 0")
		}
		if !found {
			t.Errorf("Expected payload containing blind URL, but none found")
		}
	})

	t.Run("InjectBlindHeader", func(t *testing.T) {
		targetURL := server.URL + "/header"
		scanner.InjectBlindHeader(targetURL, "X-Custom-Header")

		time.Sleep(500 * time.Millisecond)

		found := false

	LoopHeader:
		for {
			select {
			case req := <-receivedRequests:
				val := req.Header.Get("X-Custom-Header")
				if strings.Contains(val, blindURL) || strings.Contains(val, "callback.com") {
					found = true
				}
			default:
				break LoopHeader
			}
		}

		if !found {
			t.Errorf("Expected header payload, but none found")
		}
	})
}
