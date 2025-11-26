package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeWAF(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseBody   string
		expectedWAF    string
		expectDetected bool
	}{
		{
			name:           "Cloudflare Block",
			responseStatus: 403,
			responseBody:   "<html>...cloudflare...</html>",
			expectedWAF:    "Cloudflare (Active)",
			expectDetected: true,
		},
		{
			name:           "ModSecurity Block",
			responseStatus: 406,
			responseBody:   "Not Acceptable... mod_security ...",
			expectedWAF:    "ModSecurity (Active)",
			expectDetected: true,
		},
		{
			name:           "Generic Block",
			responseStatus: 403,
			responseBody:   "Access Denied",
			expectedWAF:    "Generic WAF (Blocked Request)",
			expectDetected: true,
		},
		{
			name:           "No Block",
			responseStatus: 200,
			responseBody:   "OK",
			expectedWAF:    "",
			expectDetected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify probe parameter is sent
				if r.URL.Query().Get("waf_probe") != "<script>alert(1)</script>" {
					t.Errorf("Expected waf_probe parameter")
				}
				w.WriteHeader(tc.responseStatus)
				w.Write([]byte(tc.responseBody))
			}))
			defer server.Close()

			client := server.Client()
			waf := ProbeWAF(client, server.URL)

			if waf.Detected != tc.expectDetected {
				t.Errorf("Expected Detected=%v, got %v", tc.expectDetected, waf.Detected)
			}
			if waf.Name != tc.expectedWAF {
				t.Errorf("Expected Name='%s', got '%s'", tc.expectedWAF, waf.Name)
			}
		})
	}
}
