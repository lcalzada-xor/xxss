package security

import (
	"net/http"
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// AnalyzeSecurityHeaders extracts and analyzes security headers from response
func AnalyzeSecurityHeaders(resp *http.Response) models.SecurityHeaders {
	headers := models.SecurityHeaders{}

	headers.ContentType = resp.Header.Get("Content-Type")
	headers.CSP = resp.Header.Get("Content-Security-Policy")
	headers.XContentTypeOptions = resp.Header.Get("X-Content-Type-Options")
	headers.XXSSProtection = resp.Header.Get("X-XSS-Protection")

	// Determine if anti-XSS headers are present
	headers.HasAntiXSS = headers.CSP != "" ||
		headers.XContentTypeOptions == "nosniff" ||
		strings.Contains(headers.XXSSProtection, "1")

	// Analyze if CSP is bypassable
	if headers.CSP != "" {
		headers.CSPBypassable = AnalyzeCSPBypass(headers.CSP)
	}

	return headers
}

// AnalyzeCSPBypass checks if CSP can be bypassed
func AnalyzeCSPBypass(csp string) bool {
	cspLower := strings.ToLower(csp)

	// Check for unsafe-inline (allows inline scripts)
	if strings.Contains(cspLower, "unsafe-inline") {
		return true
	}

	// Check for unsafe-eval (allows eval())
	if strings.Contains(cspLower, "unsafe-eval") {
		return true
	}

	// Check for wildcard sources (allows any domain)
	if strings.Contains(cspLower, "script-src *") ||
		strings.Contains(cspLower, "default-src *") {
		return true
	}

	// Check for common bypassable CDNs/domains
	bypassableDomains := []string{
		"googleapis.com",   // JSONP endpoints
		"gstatic.com",      // Google static
		"cloudflare.com",   // CDN
		"jsdelivr.net",     // CDN
		"unpkg.com",        // CDN
		"cdnjs.cloudflare", // CDN
		"ajax.googleapis",  // JSONP
		"*.google.com",     // Wildcard Google
		"data:",            // Data URIs
		"blob:",            // Blob URIs
	}

	for _, domain := range bypassableDomains {
		if strings.Contains(cspLower, domain) {
			return true
		}
	}

	// Check for base-uri missing (allows base tag injection)
	if !strings.Contains(cspLower, "base-uri") {
		// If script-src is restrictive but base-uri is not set, it's bypassable
		if strings.Contains(cspLower, "script-src") {
			return true
		}
	}

	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// IsExploitable determines if XSS is likely exploitable based on context and headers
func IsExploitable(context models.ReflectionContext, headers models.SecurityHeaders, unfiltered []string) bool {
	// If in comment, not exploitable
	if context == models.ContextComment {
		return false
	}

	// If Content-Type is not HTML, likely not exploitable
	if headers.ContentType != "" && !strings.Contains(headers.ContentType, "text/html") {
		// Exception: some browsers will render as HTML anyway
		if !strings.Contains(headers.ContentType, "application/xhtml") {
			return false
		}
	}

	// If CSP is strict and NOT bypassable, likely not exploitable
	if headers.CSP != "" && !headers.CSPBypassable {
		cspLower := strings.ToLower(headers.CSP)

		// Check if default-src or script-src is restrictive
		if strings.Contains(cspLower, "default-src 'self'") ||
			strings.Contains(cspLower, "script-src 'self'") ||
			strings.Contains(cspLower, "script-src 'none'") {

			// Check if unsafe-inline is NOT present (which would allow inline scripts)
			if !strings.Contains(cspLower, "unsafe-inline") {
				// CSP blocks inline scripts
				if context == models.ContextHTML || context == models.ContextJavaScript {
					return false
				}
			}
		}
	}

	// Check if we have necessary characters for the context
	switch context {
	case models.ContextHTML:
		// Primary: need < and > for tag injection
		if contains(unfiltered, "<") && contains(unfiltered, ">") {
			return true
		}

		return false

	case models.ContextJavaScript:
		// Need quotes or semicolon to break out
		return contains(unfiltered, "\"") || contains(unfiltered, "'") || contains(unfiltered, ";")

	case models.ContextAttribute:
		// Need quotes to break out, or > and < to close tag
		return contains(unfiltered, "\"") || contains(unfiltered, "'") ||
			(contains(unfiltered, ">") && contains(unfiltered, "<"))

	case models.ContextCSS:
		// CSS injection is complex, assume exploitable if reflected
		return true

	case models.ContextURL:
		// URL injection is possible with javascript: protocol
		return true

	case models.ContextAngular:
		// AngularJS template injection
		// Need parentheses and dot for constructor escape
		if contains(unfiltered, "(") && contains(unfiltered, ")") && contains(unfiltered, ".") {
			return true
		}
		// Or brackets for array-based escape
		if contains(unfiltered, "[") && contains(unfiltered, "]") {
			return true
		}
		// Even simple expressions can be dangerous in Angular
		return true
	}

	return true
}
