package security

import (
	"net/http"
	"testing"
)

func TestDetect(t *testing.T) {
	manager, err := NewWAFManager()
	if err != nil {
		t.Fatalf("Failed to create WAFManager: %v", err)
	}

	tests := []struct {
		name           string
		headers        map[string]string
		body           string
		expectedWAF    string
		expectDetected bool
	}{
		{
			name: "Cloudflare Header",
			headers: map[string]string{
				"Server": "cloudflare",
			},
			body:           "<html>...</html>",
			expectedWAF:    "Cloudflare WAF",
			expectDetected: true,
		},
		{
			name: "Incapsula Body",
			headers: map[string]string{
				"Content-Type": "text/html",
			},
			body:           "<html>...Incapsula incident ID...</html>",
			expectedWAF:    "Incapsula WAF",
			expectDetected: true,
		},
		{
			name: "AWS WAF Header",
			headers: map[string]string{
				"X-Amzn-RequestId": "12345",
			},
			body:           "<html>...</html>",
			expectedWAF:    "AWS WAF",
			expectDetected: true,
		},
		{
			name: "No WAF",
			headers: map[string]string{
				"Server": "Apache",
			},
			body:           "<html>Hello World</html>",
			expectedWAF:    "",
			expectDetected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			for k, v := range tc.headers {
				header.Set(k, v)
			}

			waf := manager.Detect(header, tc.body)

			if waf.Detected != tc.expectDetected {
				t.Errorf("Expected Detected=%v, got %v", tc.expectDetected, waf.Detected)
			}
			if waf.Name != tc.expectedWAF {
				t.Errorf("Expected Name='%s', got '%s'", tc.expectedWAF, waf.Name)
			}
		})
	}
}
