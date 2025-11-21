package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/pkg/models"
	"github.com/lcalzada-xor/xxss/pkg/network"
	"github.com/lcalzada-xor/xxss/pkg/scanner"
)

// TestBlindXSS verifies that blind XSS payloads are injected and trigger callbacks
func TestBlindXSS(t *testing.T) {
	// 1. Create a mock callback server
	callbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer callbackServer.Close()

	// 2. Create a target server (doesn't need to reflect, just needs to be scanned)
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// We just need to accept the request so the scanner proceeds
		w.WriteHeader(200)
	}))
	defer targetServer.Close()

	// 3. Initialize scanner with blind URL
	client, _ := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})
	sc.SetBlindURL(callbackServer.URL)

	// 4. Inject Blind XSS (manually calling InjectBlind for unit testing)
	// Note: In a real scan, this happens inside Scan(), but Scan() also does other things.
	// We can call Scan() and check if callback is hit.
	// Scan() calls InjectBlind if blindURL is set.
	// However, InjectBlind is fire-and-forget (goroutine). We need to wait a bit.

	// Let's use Scan() to test integration
	// We need a parameter to scan.
	_, err := sc.Scan(targetServer.URL + "/?p=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Wait for goroutine to fire
	time.Sleep(100 * time.Millisecond)

	// Since InjectBlind sends a request to the target URL with the payload,
	// and the payload contains the callback URL.
	// Wait, InjectBlind sends a request TO THE TARGET.
	// The TARGET is supposed to execute the XSS and hit the CALLBACK.
	// But our mock target server does NOT execute JS.
	// So the callback server will NEVER be hit by the target.
	//
	// Correction: InjectBlind sends a request to the target.
	// The payload is something like "><script src=CALLBACK></script>".
	// Unless the target server actually parses this and makes a request to CALLBACK (which it won't, it's a Go mock),
	// the callback server won't be hit.
	//
	// So we can't test "callback hit" unless we mock the target to behave like a vulnerable browser (impossible here)
	// OR we check if the scanner SENT the blind payload to the target.

	// Let's change the test to verify the scanner SENDS the payload to the target.

	targetReceivedPayload := atomic.Bool{}
	targetServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if query param contains the callback URL
		// We check the decoded value
		paramVal := r.URL.Query().Get("p")
		if strings.Contains(paramVal, callbackServer.URL) {
			targetReceivedPayload.Store(true)
		}
		w.WriteHeader(200)
		// Reflect the parameter so scanner detects it
		w.Write([]byte("<html><body>" + paramVal + "</body></html>"))
	}))
	defer targetServer2.Close()

	_, err = sc.Scan(targetServer2.URL + "/?p=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if !targetReceivedPayload.Load() {
		t.Error("Target did not receive blind XSS payload")
	}
}

// TestBlindXSSHeader verifies blind XSS injection in headers
func TestBlindXSSHeader(t *testing.T) {
	callbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer callbackServer.Close()

	targetReceivedPayload := atomic.Bool{}
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if User-Agent header contains callback URL
		if strings.Contains(r.Header.Get("User-Agent"), callbackServer.URL) {
			targetReceivedPayload.Store(true)
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + r.Header.Get("User-Agent") + "</body></html>"))
	}))
	defer targetServer.Close()

	client, _ := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})
	sc.SetBlindURL(callbackServer.URL)

	// Scan headers
	_, err := sc.ScanHeader(targetServer.URL, "User-Agent")
	if err != nil {
		t.Fatalf("ScanHeader failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if !targetReceivedPayload.Load() {
		t.Error("Target did not receive blind XSS payload in header")
	}
}

// TestPolyglotSuggestion verifies that polyglots are suggested when standard payloads fail
func TestPolyglotSuggestion(t *testing.T) {
	// Server that reflects input but filters '>' so standard HTML payload fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		// Filter '>'
		if strings.Contains(param, ">") {
			param = strings.ReplaceAll(param, ">", "")
		}

		w.Header().Set("Content-Type", "text/html")
		// Reflect
		w.Write([]byte("<html><body>" + param + "</body></html>"))
	}))
	defer server.Close()

	client, _ := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.Scan(server.URL + "/?p=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	// Context should be HTML
	if results[0].Context != models.ContextHTML {
		t.Errorf("Expected HTML context, got %s", results[0].Context)
	}

	// Suggested payload should be a polyglot because standard payload requires '>'
	// Our GetSuggestedPayload for HTML requires both '<' and '>' for most standard payloads.
	// If '>' is missing, it returns "".
	// Then GetPolyglot is called.

	if results[0].SuggestedPayload == "" {
		t.Error("Expected suggested payload (polyglot)")
	}

	// Check if it matches one of our polyglots or just isn't empty
	// For now, just checking it's not empty is good, but let's be sure it's the polyglot
	// The polyglot string in polyglots.go starts with "jaVasCript:"
	if !strings.Contains(results[0].SuggestedPayload, "jaVasCript:") {
		t.Errorf("Expected polyglot payload, got: %s", results[0].SuggestedPayload)
	}
}

// TestPolyglotContexts verifies that context-specific polyglots are suggested
func TestPolyglotContexts(t *testing.T) {
	testCases := []struct {
		name            string
		response        string
		expectedContext models.ReflectionContext
		expectedPayload string
	}{
		{
			name:            "Attribute Context",
			response:        `<html><body><div title="%s"></div></body></html>`,
			expectedContext: models.ContextAttribute,
			expectedPayload: "\" onmouseover=\"alert(1)",
		},
		{
			name:            "JavaScript Context",
			response:        `<html><body><script>var x = '%s';</script></body></html>`,
			expectedContext: models.ContextJSSingleQuote,
			expectedPayload: "';alert(1);//",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				param := r.URL.Query().Get("p")
				// Filter '>' to force polyglot suggestion (avoids <script>)
				if strings.Contains(param, ">") {
					param = strings.ReplaceAll(param, ">", "")
				}
				// For Attribute context, also filter space to avoid standard attribute payload
				if tc.expectedContext == models.ContextAttribute && strings.Contains(param, " ") {
					param = strings.ReplaceAll(param, " ", "")
				}
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(strings.Replace(tc.response, "%s", param, 1)))
			}))
			defer server.Close()

			client, _ := network.NewClient(2*time.Second, "", 10, 0)
			sc := scanner.NewScanner(client, map[string]string{})

			results, err := sc.Scan(server.URL + "/?p=test")
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if len(results) == 0 {
				t.Fatal("Expected at least one result")
			}

			if results[0].Context != tc.expectedContext {
				t.Errorf("Expected context %s, got %s", tc.expectedContext, results[0].Context)
			}

			// Check if the suggested payload matches the expected polyglot for this context
			// Note: GetPolyglot returns the first one in the list.
			if results[0].SuggestedPayload != tc.expectedPayload {
				t.Errorf("Expected payload %s, got %s", tc.expectedPayload, results[0].SuggestedPayload)
			}
		})
	}
}

// TestBlindXSSPOSTBody verifies blind XSS injection in POST body parameters
func TestBlindXSSPOSTBody(t *testing.T) {
	callbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer callbackServer.Close()

	targetReceivedPayload := atomic.Bool{}
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse POST body
		if err := r.ParseForm(); err == nil {
			if strings.Contains(r.FormValue("username"), callbackServer.URL) {
				targetReceivedPayload.Store(true)
			}
		}
		// Reflect the parameter so scanner detects it
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + r.FormValue("username") + "</body></html>"))
	}))
	defer targetServer.Close()

	client, _ := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})
	sc.SetBlindURL(callbackServer.URL)

	// Create POST request config
	config := &models.RequestConfig{
		Method:      "POST",
		URL:         targetServer.URL,
		Body:        "username=test&password=test",
		ContentType: "application/x-www-form-urlencoded",
	}

	// Scan POST request
	_, err := sc.ScanRequest(config)
	if err != nil {
		t.Fatalf("ScanRequest failed: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if !targetReceivedPayload.Load() {
		t.Error("Target did not receive blind XSS payload in POST body")
	}
}
