package reflected_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/network"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/reflected"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/technologies"
)

func TestReflectedScanner_Integration(t *testing.T) {
	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		path := r.URL.Path

		w.Header().Set("Content-Type", "text/html")

		switch path {
		case "/html":
			fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", param)
		case "/attribute":
			fmt.Fprintf(w, "<html><body><input value=\"%s\"></body></html>", param)
		case "/js_single":
			fmt.Fprintf(w, "<script>var x = '%s';</script>", param)
		case "/js_double":
			fmt.Fprintf(w, "<script>var x = \"%s\";</script>", param)
		case "/template":
			fmt.Fprintf(w, "<script>var x = `%s`;</script>", param)
		case "/nested_template":
			// Vulnerable inside a nested template string
			fmt.Fprintf(w, "<script>var x = `outer ${ `inner %s` }`;</script>", param)
		case "/event":
			fmt.Fprintf(w, "<img src=x onerror=\"%s\">", param) // Already in JS context inside attribute
		case "/filtered":
			// Filter < and >
			safe := strings.ReplaceAll(param, "<", "&lt;")
			safe = strings.ReplaceAll(safe, ">", "&gt;")
			fmt.Fprintf(w, "<html><body>%s</body></html>", safe)
		default:
			fmt.Fprintf(w, "<html><body>Welcome</body></html>")
		}
	}))
	defer server.Close()

	// Setup scanner
	client := network.NewClient(10*time.Second, "", 5, 0)
	logger := logger.NewLogger(0) // Silent
	techManager := technologies.NewManager()
	scanner := reflected.NewScanner(client, nil, logger, techManager)

	tests := []struct {
		name         string
		path         string
		shouldFind   bool
		expectedCtx  models.ReflectionContext
		checkPayload bool
	}{
		{
			name:         "HTML Context",
			path:         "/html",
			shouldFind:   true,
			expectedCtx:  models.ContextHTML,
			checkPayload: true,
		},
		{
			name:         "Attribute Context",
			path:         "/attribute",
			shouldFind:   true,
			expectedCtx:  models.ContextAttribute,
			checkPayload: true,
		},
		{
			name:         "JS Single Quote",
			path:         "/js_single",
			shouldFind:   true,
			expectedCtx:  models.ContextJSSingleQuote,
			checkPayload: true,
		},
		{
			name:         "JS Double Quote",
			path:         "/js_double",
			shouldFind:   true,
			expectedCtx:  models.ContextJSDoubleQuote,
			checkPayload: true,
		},
		{
			name:         "Template Literal",
			path:         "/template",
			shouldFind:   true,
			expectedCtx:  models.ContextTemplateLiteral,
			checkPayload: true,
		},
		{
			name:         "Nested Template Literal",
			path:         "/nested_template",
			shouldFind:   true,
			expectedCtx:  models.ContextTemplateLiteral,
			checkPayload: true,
		},
		{
			name:         "Event Handler (JS Raw)",
			path:         "/event",
			shouldFind:   true,
			expectedCtx:  models.ContextJSRaw, // Or similar
			checkPayload: true,
		},
		{
			name:         "Filtered (Not Exploitable)",
			path:         "/filtered",
			shouldFind:   true, // It finds reflection
			expectedCtx:  models.ContextHTML,
			checkPayload: false, // Might not be exploitable if filtered
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targetURL := server.URL + tc.path + "?q=test"

			// 1. Check Reflection
			reflectedParams, err := scanner.CheckReflection(context.Background(), targetURL)
			if err != nil {
				t.Fatalf("CheckReflection failed: %v", err)
			}

			if len(reflectedParams) == 0 {
				if tc.shouldFind {
					t.Errorf("Expected to find reflection for %s, but found none", tc.name)
				}
				return
			}

			if !tc.shouldFind {
				t.Errorf("Expected NOT to find reflection for %s, but found: %v", tc.name, reflectedParams)
				return
			}

			// 2. Probe Parameter
			results, err := scanner.ProbeParameter(context.Background(), targetURL, "q")
			if err != nil {
				t.Fatalf("ProbeParameter failed: %v", err)
			}

			if len(results) == 0 {
				t.Fatalf("Expected results, got none")
			}
			result := results[0]

			if result.Context != tc.expectedCtx {
				t.Errorf("Context mismatch. Got %s, want %s", result.Context, tc.expectedCtx)
			}

			if tc.checkPayload {
				if result.SuggestedPayload == "" {
					t.Errorf("Expected suggested payload, got empty")
				}
				// Verify payload contains alert(1) or similar
				if !strings.Contains(result.SuggestedPayload, "alert(1)") && !strings.Contains(result.SuggestedPayload, "confirm(1)") {
					t.Errorf("Payload does not look valid: %s", result.SuggestedPayload)
				}
			}
		})
	}
}

func TestMultiReflection_Prioritization(t *testing.T) {
	// Setup mock server with a page containing multiple reflections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")

		w.Header().Set("Content-Type", "text/html")

		// Reflection 1: Safe (HTML Context, encoded)
		safeParam := strings.ReplaceAll(param, "<", "&lt;")
		safeParam = strings.ReplaceAll(safeParam, ">", "&gt;")

		// Reflection 2: Vulnerable (JS Context, no encoding)
		// This simulates a common scenario where one reflection is safe but another is not.

		html := fmt.Sprintf(`
			<html>
			<body>
				<!-- Safe Reflection -->
				<div>Search results for: %s</div>

				<script>
					// Vulnerable Reflection
					var search = '%s';
				</script>
			</body>
			</html>
		`, safeParam, param)

		fmt.Fprint(w, html)
	}))
	defer server.Close()

	// Setup scanner
	client := network.NewClient(10*time.Second, "", 5, 0)
	logger := logger.NewLogger(0) // Silent
	techManager := technologies.NewManager()
	scanner := reflected.NewScanner(client, nil, logger, techManager)

	targetURL := server.URL + "?q=test"

	// 1. Check Reflection
	reflectedParams, err := scanner.CheckReflection(context.Background(), targetURL)
	if err != nil {
		t.Fatalf("CheckReflection failed: %v", err)
	}

	if len(reflectedParams) == 0 {
		t.Fatalf("Expected to find reflection, but found none")
	}

	// 2. Probe Parameter
	results, err := scanner.ProbeParameter(context.Background(), targetURL, "q")
	if err != nil {
		t.Fatalf("ProbeParameter failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("Expected results, got none")
	}

	// We expect the scanner to prioritize the JS context reflection because it's exploitable
	// The HTML reflection is safe (encoded), so it shouldn't be the primary result if a better one exists.
	// Since we now return ALL exploitable results, we should find at least one exploitable one.

	foundExploitable := false
	for _, result := range results {
		if result.Exploitable {
			foundExploitable = true
			if result.Context != models.ContextJSSingleQuote {
				t.Errorf("Expected ContextJSSingleQuote for exploitable result, got %s", result.Context)
			}
			// Verify payload targets JS context
			if !strings.Contains(result.SuggestedPayload, "alert(1)") && !strings.Contains(result.SuggestedPayload, "-alert(1)-") && !strings.Contains(result.SuggestedPayload, "';") {
				t.Errorf("Payload does not look like a JS payload: %s", result.SuggestedPayload)
			}
		}
	}

	if !foundExploitable {
		t.Errorf("Expected at least one exploitable result, but found none.")
	}
}
