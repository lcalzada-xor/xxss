package scanner

import (
	"net/http"
	"strings"

	"github.com/lcalzada-xor/xxss/models"
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

	return headers
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

	// If CSP is strict, likely not exploitable
	if headers.CSP != "" {
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
		return contains(unfiltered, "<") && contains(unfiltered, ">")

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
	}

	return true
}
