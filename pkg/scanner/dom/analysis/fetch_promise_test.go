package analysis

import (
	"regexp"
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
)

func TestFetchPromiseDetection(t *testing.T) {
	code := `
		function loadData() {
			// Source flows into fetch URL (sink 1 - optional, but good to detect)
			// Response flows into eval (sink 2 - critical)
			fetch('/api?q=' + window.location.search)
				.then(response => response.text())
				.then(data => {
					eval(data); // Sink
				});
		}
	`
	sources := []*regexp.Regexp{
		regexp.MustCompile(`location\..*`),
	}
	sinks := []*regexp.Regexp{
		regexp.MustCompile(`eval`),
	}

	// Verbose logger
	findings, _ := AnalyzeJS(code, sources, sinks, logger.NewLogger(2))

	found := false
	for _, f := range findings {
		if f.Sink == "eval" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected finding for Fetch Promise chain, but got none")
	}
}
