package tests

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/security"
)

// TestCSPBypass_UnsafeInline tests detection of unsafe-inline
func TestCSPBypass_UnsafeInline(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' 'unsafe-inline'"
	if !security.AnalyzeCSPBypass(csp) {
		t.Error("Expected CSP with unsafe-inline to be bypassable")
	}
}

// TestCSPBypass_UnsafeEval tests detection of unsafe-eval
func TestCSPBypass_UnsafeEval(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' 'unsafe-eval'"
	if !security.AnalyzeCSPBypass(csp) {
		t.Error("Expected CSP with unsafe-eval to be bypassable")
	}
}

// TestCSPBypass_Wildcard tests detection of wildcard sources
func TestCSPBypass_Wildcard(t *testing.T) {
	csp := "default-src 'self'; script-src *"
	if !security.AnalyzeCSPBypass(csp) {
		t.Error("Expected CSP with wildcard to be bypassable")
	}
}

// TestCSPBypass_JSONP tests detection of JSONP endpoints
func TestCSPBypass_JSONP(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' https://ajax.googleapis.com"
	if !security.AnalyzeCSPBypass(csp) {
		t.Error("Expected CSP with googleapis.com to be bypassable (JSONP)")
	}
}

// TestCSPBypass_CDN tests detection of bypassable CDNs
func TestCSPBypass_CDN(t *testing.T) {
	cdns := []string{
		"default-src 'self'; script-src 'self' https://cdn.jsdelivr.net",
		"default-src 'self'; script-src 'self' https://unpkg.com",
		"default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com",
	}

	for _, csp := range cdns {
		if !security.AnalyzeCSPBypass(csp) {
			t.Errorf("Expected CSP with CDN to be bypassable: %s", csp)
		}
	}
}

// TestCSPBypass_DataURI tests detection of data: URIs
func TestCSPBypass_DataURI(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' data:"
	if !security.AnalyzeCSPBypass(csp) {
		t.Error("Expected CSP with data: to be bypassable")
	}
}

// TestCSPBypass_MissingBaseURI tests detection of missing base-uri
func TestCSPBypass_MissingBaseURI(t *testing.T) {
	csp := "default-src 'self'; script-src 'self'"
	if !security.AnalyzeCSPBypass(csp) {
		t.Error("Expected CSP without base-uri to be bypassable")
	}
}

// TestCSPBypass_Strict tests that strict CSP is not bypassable
func TestCSPBypass_Strict(t *testing.T) {
	csp := "default-src 'self'; script-src 'self'; base-uri 'self'; object-src 'none'"
	if security.AnalyzeCSPBypass(csp) {
		t.Error("Expected strict CSP to NOT be bypassable")
	}
}
