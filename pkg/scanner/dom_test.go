package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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

	ds := NewDOMScanner()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ds.ScanDOM(tt.body)
			if len(findings) != tt.expected {
				t.Errorf("ScanDOM() = %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}

func TestDOMScanner_ScanDeepDOM_Caching(t *testing.T) {
	var requestCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/common.js" {
			requestCount++
			fmt.Fprint(w, "document.write(location.search);")
		} else {
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	ds := NewDOMScanner()
	client := ts.Client()

	// First scan
	body1 := fmt.Sprintf("<html><script src=\"%s/common.js\"></script></html>", ts.URL)
	ds.ScanDeepDOM(ts.URL, body1, client)

	// Second scan (should use cache)
	body2 := fmt.Sprintf("<html><script src=\"%s/common.js\"></script></html>", ts.URL)
	ds.ScanDeepDOM(ts.URL, body2, client)

	if requestCount != 1 {
		t.Errorf("Expected 1 request to /common.js, got %d", requestCount)
	}
}

func TestDOMScanner_ScanDeepDOM(t *testing.T) {
	// Setup mock server for external JS
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vulnerable.js" {
			fmt.Fprint(w, "document.write(location.search);")
		} else if r.URL.Path == "/safe.js" {
			fmt.Fprint(w, "console.log('Hello');")
		} else {
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{
			name:     "External Vulnerable JS",
			body:     fmt.Sprintf("<html><script src=\"%s/vulnerable.js\"></script></html>", ts.URL),
			expected: 1,
		},
		{
			name:     "External Safe JS",
			body:     fmt.Sprintf("<html><script src=\"%s/safe.js\"></script></html>", ts.URL),
			expected: 0,
		},
		{
			name:     "Mixed Inline and External",
			body:     fmt.Sprintf("<html><script>document.write(location.href)</script><script src=\"%s/vulnerable.js\"></script></html>", ts.URL),
			expected: 2,
		},
	}

	ds := NewDOMScanner()
	client := ts.Client()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ds.ScanDeepDOM(ts.URL, tt.body, client)
			if len(findings) != tt.expected {
				t.Errorf("ScanDeepDOM() = %d findings, want %d", len(findings), tt.expected)
			}
		})
	}
}
