package security

import (
	"net/http"
	"strings"
)

// WAF represents a detected Web Application Firewall
type WAF struct {
	Name     string
	Detected bool
}

// DetectWAF analyzes HTTP response headers to identify the presence of a WAF
func DetectWAF(headers http.Header) *WAF {
	for key, values := range headers {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(strings.Join(values, " "))

		// Cloudflare
		if keyLower == "server" && strings.Contains(valueLower, "cloudflare") {
			return &WAF{Name: "Cloudflare", Detected: true}
		}
		if keyLower == "cf-ray" || keyLower == "cf-cache-status" {
			return &WAF{Name: "Cloudflare", Detected: true}
		}

		// AWS WAF
		if keyLower == "x-amzn-requestid" || keyLower == "x-amz-cf-id" {
			return &WAF{Name: "AWS WAF", Detected: true}
		}
		if strings.Contains(valueLower, "awselb") || strings.Contains(valueLower, "awsalb") {
			return &WAF{Name: "AWS WAF", Detected: true}
		}

		// Akamai
		if keyLower == "x-akamai-transformed" || keyLower == "akamai-origin-hop" {
			return &WAF{Name: "Akamai", Detected: true}
		}
		if strings.Contains(valueLower, "akamai") {
			return &WAF{Name: "Akamai", Detected: true}
		}

		// Imperva/Incapsula
		if keyLower == "x-iinfo" || keyLower == "x-cdn" && strings.Contains(valueLower, "incapsula") {
			return &WAF{Name: "Imperva", Detected: true}
		}
		if strings.Contains(valueLower, "incapsula") || strings.Contains(valueLower, "imperva") {
			return &WAF{Name: "Imperva", Detected: true}
		}

		// ModSecurity
		if strings.Contains(valueLower, "mod_security") || strings.Contains(valueLower, "modsecurity") {
			return &WAF{Name: "ModSecurity", Detected: true}
		}

		// F5 BIG-IP
		if keyLower == "x-cnection" || keyLower == "x-wa-info" {
			return &WAF{Name: "F5 BIG-IP", Detected: true}
		}
		if strings.Contains(valueLower, "bigip") || strings.Contains(valueLower, "f5") {
			return &WAF{Name: "F5 BIG-IP", Detected: true}
		}

		// Sucuri
		if keyLower == "x-sucuri-id" || keyLower == "x-sucuri-cache" {
			return &WAF{Name: "Sucuri", Detected: true}
		}
		if strings.Contains(valueLower, "sucuri") {
			return &WAF{Name: "Sucuri", Detected: true}
		}

		// Barracuda
		if strings.Contains(valueLower, "barracuda") || keyLower == "barra-counter" {
			return &WAF{Name: "Barracuda", Detected: true}
		}
	}

	return &WAF{Name: "", Detected: false}
}
