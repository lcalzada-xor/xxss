package tests

import (
	"net/http"
	"testing"

	"github.com/lcalzada-xor/xxss/pkg/scanner/security"
)

func TestWAFDetection(t *testing.T) {
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
			expected: "Cloudflare",
		},
		{
			name: "Cloudflare via CF-Ray",
			headers: http.Header{
				"Cf-Ray": []string{"123456789-SJC"},
			},
			expected: "Cloudflare",
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
			expected: "Akamai",
		},
		{
			name: "Imperva",
			headers: http.Header{
				"X-Iinfo": []string{"1-123456"},
			},
			expected: "Imperva",
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
			expected: "Sucuri",
		},
		{
			name: "Barracuda",
			headers: http.Header{
				"Server": []string{"Barracuda WAF"},
			},
			expected: "Barracuda",
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
			waf := security.DetectWAF(tt.headers)
			if waf.Name != tt.expected {
				t.Errorf("DetectWAF() = %v, want %v", waf.Name, tt.expected)
			}
			if tt.expected != "" && !waf.Detected {
				t.Errorf("WAF should be detected but Detected = false")
			}
		})
	}
}
