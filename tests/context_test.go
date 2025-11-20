package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/models"
	"github.com/lcalzada-xor/xxss/network"
	"github.com/lcalzada-xor/xxss/scanner"
)

// Test HTML context detection
func TestContextDetection_HTML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		response := `<html><body><div>` + param + `</div></body></html>`
		w.Write([]byte(response))
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

	if results[0].Context != models.ContextHTML {
		t.Errorf("Expected HTML context, got %s", results[0].Context)
	}

	t.Logf("Context: %s, Exploitable: %v, Payload: %s", results[0].Context, results[0].Exploitable, results[0].SuggestedPayload)
}

// Test JavaScript context detection
func TestContextDetection_JavaScript(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		response := `<html><body><script>var x = "` + param + `";</script></body></html>`
		w.Write([]byte(response))
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

	if results[0].Context != models.ContextJavaScript {
		t.Errorf("Expected JavaScript context, got %s", results[0].Context)
	}

	// Should suggest JavaScript-specific payload
	if results[0].SuggestedPayload == "" {
		t.Error("Expected suggested payload for JavaScript context")
	}

	t.Logf("Context: %s, Payload: %s", results[0].Context, results[0].SuggestedPayload)
}

// Test Attribute context detection
func TestContextDetection_Attribute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		response := `<html><body><input value="` + param + `"></body></html>`
		w.Write([]byte(response))
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

	if results[0].Context != models.ContextAttribute {
		t.Errorf("Expected Attribute context, got %s", results[0].Context)
	}

	t.Logf("Context: %s, Payload: %s", results[0].Context, results[0].SuggestedPayload)
}

// Test Comment context detection
func TestContextDetection_Comment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		response := `<html><body><!-- ` + param + ` --></body></html>`
		w.Write([]byte(response))
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

	if results[0].Context != models.ContextComment {
		t.Errorf("Expected Comment context, got %s", results[0].Context)
	}

	// Comment context should not be exploitable
	if results[0].Exploitable {
		t.Error("Comment context should not be exploitable")
	}

	t.Logf("Context: %s, Exploitable: %v", results[0].Context, results[0].Exploitable)
}

// Test CSP blocking detection
func TestSecurityHeaders_CSP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		response := `<html><body><div>` + param + `</div></body></html>`
		w.Write([]byte(response))
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

	// Should detect CSP
	if results[0].SecurityHeaders.CSP == "" {
		t.Error("Expected CSP to be detected")
	}

	if !results[0].SecurityHeaders.HasAntiXSS {
		t.Error("Expected HasAntiXSS to be true with CSP")
	}

	// Should not be exploitable with strict CSP
	if results[0].Exploitable {
		t.Error("Should not be exploitable with strict CSP")
	}

	t.Logf("CSP: %s, Exploitable: %v", results[0].SecurityHeaders.CSP, results[0].Exploitable)
}

// Test exploitability scoring
func TestExploitability_WithRequiredChars(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		response := `<html><body><div>` + param + `</div></body></html>`
		w.Write([]byte(response))
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

	// HTML context with < and > should be exploitable
	hasLt := false
	hasGt := false
	for _, char := range results[0].Unfiltered {
		if char == "<" {
			hasLt = true
		}
		if char == ">" {
			hasGt = true
		}
	}

	if hasLt && hasGt && !results[0].Exploitable {
		t.Error("Should be exploitable with < and > in HTML context")
	}

	t.Logf("Unfiltered chars: %v, Exploitable: %v", results[0].Unfiltered, results[0].Exploitable)
}

// Test payload suggestions
func TestPayloadSuggestions(t *testing.T) {
	testCases := []struct {
		name              string
		responseTemplate  string
		expectedContext   models.ReflectionContext
		shouldHavePayload bool
	}{
		{
			name:              "HTML with angle brackets",
			responseTemplate:  `<html><body><div>%s</div></body></html>`,
			expectedContext:   models.ContextHTML,
			shouldHavePayload: true,
		},
		{
			name:              "JavaScript with quotes",
			responseTemplate:  `<html><body><script>var x = "%s";</script></body></html>`,
			expectedContext:   models.ContextJavaScript,
			shouldHavePayload: true,
		},
		{
			name:              "Attribute with quotes",
			responseTemplate:  `<html><body><input value="%s"></body></html>`,
			expectedContext:   models.ContextAttribute,
			shouldHavePayload: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				param := r.URL.Query().Get("p")
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(fmt.Sprintf(tc.responseTemplate, param)))
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

			if tc.shouldHavePayload && results[0].SuggestedPayload == "" {
				t.Error("Expected suggested payload")
			}

			t.Logf("Context: %s, Payload: %s", results[0].Context, results[0].SuggestedPayload)
		})
	}
}
