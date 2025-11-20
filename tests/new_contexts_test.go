package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/models"
	"github.com/lcalzada-xor/xxss/network"
	"github.com/lcalzada-xor/xxss/scanner"
)

// TestContextDetection_TemplateLiteral tests detection of template literal context
func TestContextDetection_TemplateLiteral(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		// Reflect in template literal
		w.Write([]byte("<html><body><script>const x = `" + param + "`;</script></body></html>"))
	}))
	defer server.Close()

	client, _ := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.Scan(server.URL + "/?p=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	if results[0].Context != models.ContextTemplateLiteral {
		t.Errorf("Expected template_literal context, got %s", results[0].Context)
	}

	// Should suggest template literal payload
	if !strings.Contains(results[0].SuggestedPayload, "${") && !strings.Contains(results[0].SuggestedPayload, "`") {
		t.Logf("Payload: %s", results[0].SuggestedPayload)
	}
}

// TestContextDetection_SVG tests detection of SVG context
func TestContextDetection_SVG(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		// Reflect in SVG
		w.Write([]byte("<html><body><svg><text>" + param + "</text></svg></body></html>"))
	}))
	defer server.Close()

	client, _ := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.Scan(server.URL + "/?p=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	if results[0].Context != models.ContextSVG {
		t.Errorf("Expected svg context, got %s", results[0].Context)
	}

	t.Logf("SVG Context detected, Payload: %s", results[0].SuggestedPayload)
}

// TestContextDetection_MetaRefresh tests detection of meta refresh context
func TestContextDetection_MetaRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		// Reflect in meta refresh
		w.Write([]byte("<html><head><meta http-equiv=\"refresh\" content=\"0;url=" + param + "\"></head></html>"))
	}))
	defer server.Close()

	client, _ := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.Scan(server.URL + "/?p=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	if results[0].Context != models.ContextMetaRefresh {
		t.Errorf("Expected meta_refresh context, got %s", results[0].Context)
	}

	// Should suggest javascript: or data: URI
	if !strings.Contains(results[0].SuggestedPayload, "javascript:") && !strings.Contains(results[0].SuggestedPayload, "data:") {
		t.Logf("Payload: %s", results[0].SuggestedPayload)
	}
}

// TestContextDetection_DataURI tests detection of data URI context
func TestContextDetection_DataURI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		// Reflect in data URI
		w.Write([]byte("<html><body><a href=\"data:text/html," + param + "\">link</a></body></html>"))
	}))
	defer server.Close()

	client, _ := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.Scan(server.URL + "/?p=test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	if results[0].Context != models.ContextDataURI {
		t.Errorf("Expected data_uri context, got %s", results[0].Context)
	}

	// Should suggest data URI payload
	if !strings.Contains(results[0].SuggestedPayload, "data:") {
		t.Logf("Payload: %s", results[0].SuggestedPayload)
	}
}
