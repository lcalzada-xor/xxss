package dom

import (
	"strings"
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
)

func TestDOMScanner_PayloadGeneration(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedPayload string
	}{
		{
			name:            "innerHTML Sink",
			body:            "<script>document.body.innerHTML = location.search;</script>",
			expectedPayload: "<svg onload=alert(1)>", // ContextHTML -> <svg onload=alert(1)>
		},
		{
			name:            "eval Sink",
			body:            "<script>eval(location.search);</script>",
			expectedPayload: "alert(1)", // ContextJSRaw -> alert(1)
		},
		{
			name:            "location Sink",
			body:            "<script>location.href = location.search;</script>",
			expectedPayload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e", // ContextURL -> Polyglot
		},
		{
			name:            "javascript: Protocol",
			body:            "<a href='javascript:location.search'>Click me</a>",
			expectedPayload: "javascript:alert(1)", // ContextAttribute (inferred) -> javascript:alert(1) (hardcoded in scanner.go for this specific case)
		},
		{
			name:            "jQuery Sink",
			body:            "<script>$('#test').html(location.hash);</script>",
			expectedPayload: "<svg onload=alert(1)>", // ContextHTML -> <svg onload=alert(1)>
		},
	}

	ds := NewDOMScanner(logger.NewLogger(0))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ds.ScanDOM(tt.body)
			if len(findings) == 0 {
				t.Fatalf("Expected at least 1 finding, got 0")
			}

			found := false
			for _, f := range findings {
				// We check if the payload contains the expected string because GeneratePayload might return polyglots
				// or variations. But for specific contexts it should be precise.
				// However, GeneratePayload returns specific strings for specific contexts.
				// Let's check exact match or containment.
				if strings.Contains(f.SuggestedPayload, tt.expectedPayload) {
					found = true
					break
				}
				// Also check if it matches one of the other valid payloads for that context
				if tt.name == "innerHTML Sink" || tt.name == "jQuery Sink" {
					if strings.Contains(f.SuggestedPayload, "<img src=x onerror=alert(1)>") {
						found = true
						break
					}
				}
			}

			if !found {
				t.Errorf("Expected payload containing '%s', got: %v", tt.expectedPayload, findings[0].SuggestedPayload)
			}
		})
	}
}
