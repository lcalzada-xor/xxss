package tests

import (
	"net/http"
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/security"
)

func TestWAFDetection(t *testing.T) {
	manager, err := security.NewWAFManager()
	if err != nil {
		t.Fatalf("Failed to create WAFManager: %v", err)
	}

	tests := []struct {
		name     string
		headers  http.Header
		expected string
	}{
		{
			name: "Cloudflare via Server header",
			headers: http.Header{
				"Server": []string{"cloudflare"},
			},
			expected: "Cloudflare WAF",
		},
		{
			name: "Cloudflare via CF-Ray",
			headers: http.Header{
				"Cf-Ray": []string{"123456789-SJC"},
			},
			expected: "Cloudflare WAF",
		},
		{
			name: "AWS WAF",
			headers: http.Header{
				"X-Amzn-Requestid": []string{"abc123"},
			},
			expected: "AWS WAF",
		},
		{
			name: "Akamai",
			headers: http.Header{
				"X-Akamai-Transformed": []string{"9 12345"},
			},
			expected: "Akamai WAF",
		},
		{
			name: "Imperva",
			headers: http.Header{
				"X-Iinfo": []string{"1-123456"},
			},
			expected: "Incapsula WAF",
		},
		{
			name: "ModSecurity",
			headers: http.Header{
				"Server": []string{"Apache/2.4.41 (Ubuntu) mod_security/2.9.3"},
			},
			expected: "ModSecurity",
		},
		{
			name: "F5 BIG-IP",
			headers: http.Header{
				"X-Cnection": []string{"close"},
			},
			expected: "F5 BIG-IP",
		},
		{
			name: "Sucuri",
			headers: http.Header{
				"X-Sucuri-Id": []string{"12345"},
			},
			expected: "Sucuri WAF",
		},
		{
			name: "Barracuda",
			headers: http.Header{
				"Server": []string{"Barracuda WAF"},
			},
			expected: "Barracuda WAF",
		},
		{
			name: "No WAF detected",
			headers: http.Header{
				"Server": []string{"nginx/1.18.0"},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := manager.Detect(tt.headers, "")
			if waf.Name != tt.expected {
				t.Errorf("Detect() = %v, want %v", waf.Name, tt.expected)
			}
			if tt.expected != "" && !waf.Detected {
				t.Errorf("WAF should be detected but Detected = false")
			}
		})
	}
}
