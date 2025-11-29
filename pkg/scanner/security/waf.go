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

// Detect passively analyzes HTTP response headers and body to identify the presence of a WAF
func Detect(headers http.Header, body string) *WAF {
	// 1. Check Headers
	for key, values := range headers {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(strings.Join(values, " "))

		// Cloudflare
		if keyLower == "server" && strings.Contains(valueLower, "cloudflare") {
			return &WAF{Name: "Cloudflare WAF", Detected: true}
		}
		if keyLower == "cf-ray" || keyLower == "cf-cache-status" || keyLower == "__cf_bm" {
			return &WAF{Name: "Cloudflare WAF", Detected: true}
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
			return &WAF{Name: "Akamai WAF", Detected: true}
		}
		if strings.Contains(valueLower, "akamai") {
			return &WAF{Name: "Akamai WAF", Detected: true}
		}

		// Imperva/Incapsula
		if keyLower == "x-iinfo" || keyLower == "x-cdn" && strings.Contains(valueLower, "incapsula") {
			return &WAF{Name: "Incapsula WAF", Detected: true}
		}
		if strings.Contains(valueLower, "incapsula") || strings.Contains(valueLower, "imperva") {
			return &WAF{Name: "Incapsula WAF", Detected: true}
		}
		if keyLower == "visid_incap" {
			return &WAF{Name: "Incapsula WAF", Detected: true}
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
			return &WAF{Name: "Sucuri WAF", Detected: true}
		}
		if strings.Contains(valueLower, "sucuri") {
			return &WAF{Name: "Sucuri WAF", Detected: true}
		}

		// Barracuda
		if strings.Contains(valueLower, "barracuda") || keyLower == "barra-counter" {
			return &WAF{Name: "Barracuda WAF", Detected: true}
		}
	}

	// 2. Check Body Content
	// Incapsula
	if strings.Contains(body, "Incapsula incident ID") ||
		strings.Contains(body, "_Incapsula_Resource") ||
		strings.Contains(body, "visid_incap") {
		return &WAF{Name: "Incapsula WAF", Detected: true}
	}

	// Cloudflare
	if strings.Contains(body, "Attention Required! | Cloudflare") ||
		strings.Contains(body, "Ray ID:") {
		return &WAF{Name: "Cloudflare WAF", Detected: true}
	}

	// Akamai
	if strings.Contains(body, "AkamaiGHost") ||
		strings.Contains(body, "Access Denied") {
		// "Access Denied" is too generic, check for Akamai specific context if possible,
		// but for now we'll trust the signature if it was working.
		// Actually "Access Denied" is very generic. Let's be careful.
		// The previous signature had "Reference #" which is also generic.
		// Let's stick to "AkamaiGHost" for body.
		if strings.Contains(body, "AkamaiGHost") {
			return &WAF{Name: "Akamai WAF", Detected: true}
		}
	}

	// AWS WAF
	if strings.Contains(body, "AWS WAF") {
		return &WAF{Name: "AWS WAF", Detected: true}
	}

	return &WAF{Name: "", Detected: false}
}
