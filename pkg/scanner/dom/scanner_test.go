package dom

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lcalzada-xor/xxss/pkg/logger"
)

func TestDOMScanner_ScanDOM(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{
			name:     "No Vulnerability",
			body:     "<html><body><h1>Hello</h1></body></html>",
			expected: 0,
		},
		{
			name:     "Basic DOM XSS",
			body:     "<script>document.write(location.search)</script>",
			expected: 1,
		},
		{
			name:     "Multiple DOM XSS",
			body:     "<script>\ndocument.write(location.search);\nelement.innerHTML = location.hash;\n</script>",
			expected: 2,
		},
		{
			name:     "Taint Analysis: Variable Assignment",
			body:     "<script>\nvar x = location.search;\ndocument.write(x);\n</script>",
			expected: 1, // Should be detected now
		},
		{
			name:     "Taint Analysis: Transitive",
			body:     "<script>\nvar x = location.search;\nvar y = x;\ndocument.write(y);\n</script>",
			expected: 1, // Should be detected now
		},
		{
			name:     "New Source: localStorage",
			body:     "<script>\ndocument.write(localStorage.getItem('foo'));\n</script>",
			expected: 1,
		},
		{
			name:     "Sanitization (Should be Safe)",
			body:     "<script>\nvar x = DOMPurify.sanitize(location.search);\ndocument.write(x);\n</script>",
			expected: 0,
		},
		{
			name:     "Scope Isolation (Should be Safe)",
			body:     "<script>\nfunction safe() { var x = 'safe'; document.write(x); }\nfunction unsafe() { var y = location.search; }\n</script>",
			expected: 0,
		},
		{
			name:     "Scope Isolation (Should be Unsafe)",
			body:     "<script>\nfunction unsafe() { var x = location.search; document.write(x); }\n</script>",
			expected: 1,
		},
		{
			name:     "Complex Expression (Concatenation)",
			body:     "<script>\nvar x = location.search;\nvar y = 'safe' + x;\ndocument.write(y);\n</script>",
			expected: 1,
		},
		{
			name:     "Modern Source: navigation.currentEntry",
			body:     "<script>\ndocument.write(navigation.currentEntry.url);\n</script>",
			expected: 1,
		},
		{
			name:     "Modern Sink: navigation.navigate",
			body:     "<script>\nnavigation.navigate(location.search);\n</script>",
			expected: 1,
		},
		{
			name:     "jQuery Sink: .html()",
			body:     "<script>\n$('#div').html(location.hash);\n</script>",
			expected: 1,
		},
		{
			name:     "Prototype Pollution: __proto__ assignment",
			body:     "<script>\nvar obj = {};\nobj.__proto__.polluted = true;\n</script>",
			expected: 1,
		},
		{
			name:     "Prototype Pollution: Bracket notation",
			body:     "<script>\nvar obj = {};\nobj['prototype'].polluted = true;\n</script>",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := NewDOMScanner(logger.NewLogger(0))
			findings := ds.ScanDOM(tt.body)
			if len(findings) != tt.expected {
				t.Errorf("ScanDOM() = %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}

func TestDOMScanner_ScanDeepDOM_Caching(t *testing.T) {
	// Mock server that returns different content for the same URL (should be cached)
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		fmt.Fprintf(w, "var x = location.hash; document.write(x); // Call %d", callCount)
	}))
	defer server.Close()

	ds := NewDOMScanner(logger.NewLogger(0))
	client := server.Client()

	// First scan
	findings1 := ds.ScanDeepDOM(server.URL, "<script src='"+server.URL+"'></script>", client)
	if len(findings1) != 1 {
		t.Errorf("First scan failed to detect XSS")
	}

	// Second scan (should use cache)
	findings2 := ds.ScanDeepDOM(server.URL, "<script src='"+server.URL+"'></script>", client)
	if len(findings2) != 1 {
		t.Errorf("Second scan failed to detect XSS")
	}

	if callCount != 1 {
		t.Errorf("Expected 1 HTTP request (cached), got %d", callCount)
	}
}

func TestDOMScanner_ScanDeepDOM(t *testing.T) {
	// Setup mock servers for external JS
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "var x = location.hash; document.write(x);")
	}))
	defer vulnServer.Close()

	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "console.log('Hello');")
	}))
	defer safeServer.Close()

	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{
			name:     "External Vulnerable JS",
			body:     fmt.Sprintf("<script src='%s'></script>", vulnServer.URL),
			expected: 1,
		},
		{
			name:     "External Safe JS",
			body:     fmt.Sprintf("<script src='%s'></script>", safeServer.URL),
			expected: 0,
		},
		{
			name:     "Mixed Inline and External",
			body:     fmt.Sprintf("<script>var y = location.search; eval(y);</script><script src='%s'></script>", vulnServer.URL),
			expected: 2,
		},
	}

	// The original code had `ds := NewDOMScanner(NewLogger(0))` here,
	// but the instruction moves it inside the loop.
	// client := ts.Client() // ts is not defined here, using vulnServer.Client() or safeServer.Client() is not appropriate for a general client.
	// A single client should be created for the test function.

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := NewDOMScanner(logger.NewLogger(0))
			// The original code had `client := ts.Client()` inside the loop,
			// but `ts` is not defined in this scope.
			// Using a client from one of the mock servers or a new one.
			// For this test, we need a client that can access both servers.
			// Let's use a client from one of the servers, as it's configured for mock requests.
			// Or, better, create a new client for the test.
			// The original code used `ts.Client()` which was a single mock server.
			// Here we have two. Let's use vulnServer's client as a general client for the test.
			// Or, more robustly, create a new http.Client.
			// The instruction provided a snippet that had `client := ts.Client()` inside the loop,
			// but `ts` is not defined in this scope.
			// Let's assume the client should be created once for the test function.
			// The original code had `client := ts.Client()` outside the loop.
			// The instruction snippet seems to have a copy-paste error for the client.
			// I will keep the client declaration outside the loop and use `vulnServer.Client()`
			// as a representative client for the test.

			findings := ds.ScanDeepDOM(vulnServer.URL, tt.body, vulnServer.Client())
			if len(findings) != tt.expected {
				t.Errorf("ScanDeepDOM() = %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}
