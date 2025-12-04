package dom

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
)

func TestEvidencePopulation(t *testing.T) {
	// 1. Regex-based Finding (javascript: protocol)
	html := `<a href="javascript:alert(1)">Click me</a>`
	findings := NewDOMScanner(logger.NewLogger(0)).ScanDOM(html)
	if len(findings) == 0 {
		t.Fatal("Expected findings, got 0")
	}
	if findings[0].Evidence != ` href="javascript:alert(1)"` {
		t.Errorf("Expected evidence ' href=\"javascript:alert(1)\"', got '%s'", findings[0].Evidence)
	}

	// 2. AST-based Finding (dangerouslySetInnerHTML)
	js := `
	function render() {
		const taint = location.hash;
		const element = {
			dangerouslySetInnerHTML: { __html: taint }
		};
	}
	`
	findings = NewDOMScanner(logger.NewLogger(0)).ScanDOM(js)
	if len(findings) == 0 {
		t.Fatal("Expected AST findings, got 0")
	}

	// The evidence should be the object literal or property
	// Based on walker.go, it's the node passed to GetSnippet
	// For dangerouslySetInnerHTML, it's the PropertyKeyed node for __html
	// Let's check if it contains "taint" or "__html"
	if findings[0].Evidence == "" {
		t.Error("Expected evidence to be populated, got empty string")
	}
	t.Logf("AST Evidence: %s", findings[0].Evidence)
}
