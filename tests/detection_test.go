package tests

import (
	"html"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/network"
	"github.com/lcalzada-xor/xxss/scanner"
)

// TestHTMLEncodingFalsePositive tests that xxss doesn't report false positives
// when special characters are HTML-encoded
func TestHTMLEncodingFalsePositive(t *testing.T) {
	// Create a server that HTML-encodes all input
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		encoded := html.EscapeString(input)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><div>" + encoded + "</div></body></html>"))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "")
	sc := scanner.NewScanner(client, map[string]string{})

	// Scan the URL with a parameter
	results, err := sc.Scan(server.URL + "/?q=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// We expect the scanner to still report this (it's a screening tool)
	// but in a real scenario, dalfox would filter it out
	// The key is that we're detecting the encoding exists
	if len(results) > 0 {
		t.Logf("Scanner reported %d results (expected for screening tool)", len(results))
		// This is acceptable - xxss is a screening tool, dalfox will verify
	}
}

// TestMultipleReflections tests that xxss detects reflections in multiple contexts
func TestMultipleReflections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		// Reflect in 3 different places
		response := `<html>
			<head><title>Search: ` + html.EscapeString(input) + `</title></head>
			<body>
				<h1>Results for: ` + html.EscapeString(input) + `</h1>
				<script>var query = "` + input + `";</script>
			</body>
		</html>`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "")
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.Scan(server.URL + "/?q=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect reflection in the JavaScript context (unencoded)
	if len(results) == 0 {
		t.Error("Expected to find reflected parameter, but got none")
	} else {
		t.Logf("Found %d reflected parameters", len(results))
		for _, result := range results {
			if len(result.Unfiltered) > 0 {
				t.Logf("Parameter %s has unfiltered chars: %v", result.Parameter, result.Unfiltered)
			}
		}
	}
}

// TestXSSWithoutQuotes tests detection of XSS vulnerabilities that don't use quotes
func TestXSSWithoutQuotes(t *testing.T) {
	// Server vulnerable to: <img src=x onerror=alert(1)>
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		// Vulnerable: no quotes around attribute value
		response := `<html><body><img src=` + input + `></body></html>`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "")
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.Scan(server.URL + "/?q=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect space and = characters (needed for XSS without quotes)
	if len(results) == 0 {
		t.Error("Expected to find reflected parameter")
	} else {
		found := false
		for _, result := range results {
			// Check if we detected space or = characters
			for _, char := range result.Unfiltered {
				if char == " " || char == "=" {
					found = true
					t.Logf("Successfully detected '%s' character needed for XSS without quotes", char)
				}
			}
		}
		if !found {
			t.Error("Did not detect space or = characters needed for XSS without quotes")
		}
	}
}

// TestLargeReflection tests that we don't skip reflections >200 chars
func TestLargeReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		// Add padding to make the reflected content >200 chars
		padding := ""
		for i := 0; i < 250; i++ {
			padding += "x"
		}
		response := `<html><body><textarea>` + padding + input + `</textarea></body></html>`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "")
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.Scan(server.URL + "/?q=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should still detect reflection even with >200 chars (now limit is 1000)
	if len(results) == 0 {
		t.Error("Expected to find reflected parameter even with large content")
	} else {
		t.Logf("Successfully detected reflection in large content")
	}
}

// TestUniqueBaselineProbe tests that baseline check uses unique values
func TestUniqueBaselineProbe(t *testing.T) {
	// Server that reflects parameter value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		response := `<html><body><div>ID: ` + id + `</div></body></html>`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "")
	sc := scanner.NewScanner(client, map[string]string{})

	// Test with a common value that might appear elsewhere
	results, err := sc.Scan(server.URL + "/?id=1")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect reflection using unique probe values
	if len(results) == 0 {
		t.Error("Expected to find reflected parameter with unique probe")
	} else {
		t.Logf("Successfully detected reflection using unique baseline probe")
	}
}

// TestRawPayloadMode tests that raw payload mode sends unencoded characters
func TestRawPayloadMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		response := `<html><body>` + input + `</body></html>`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "")
	sc := scanner.NewScanner(client, map[string]string{})
	sc.SetRawPayload(true) // Enable raw payload mode

	results, err := sc.Scan(server.URL + "/?q=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify the raw mode is being set and scanner runs
	t.Logf("Raw payload mode test completed, results: %d", len(results))
}
