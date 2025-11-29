package analysis

import (
	"regexp"
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
)

func TestReproBinaryExpressionSink(t *testing.T) {
	code := `
		var storeId = location.search;
		document.write('<option>' + storeId + '</option>');
	`
	sources := []*regexp.Regexp{
		regexp.MustCompile(`location\..*`),
	}
	sinks := []*regexp.Regexp{
		regexp.MustCompile(`document\.write`),
	}

	findings, _ := AnalyzeJS(code, sources, sinks, logger.NewLogger(0))

	if len(findings) == 0 {
		t.Errorf("Expected finding for binary expression sink, but got none")
	} else {
		t.Logf("Found %d findings", len(findings))
		for _, f := range findings {
			t.Logf("Finding: %s -> %s", f.Source, f.Sink)
		}
	}
}
