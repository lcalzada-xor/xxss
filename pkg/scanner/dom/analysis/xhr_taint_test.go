package analysis

import (
	"regexp"
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
)

func TestLab2Detection(t *testing.T) {
	code := `
		function search(path) {
			var xhr = new XMLHttpRequest();
			xhr.onreadystatechange = function() {
				if (this.readyState == 4 && this.status == 200) {
					eval('var searchResultsObj = ' + this.responseText);
					displaySearchResults(searchResultsObj);
				}
			};
			xhr.open("GET", path + window.location.search);
			xhr.send();
		}
	`
	sources := []*regexp.Regexp{
		regexp.MustCompile(`location\..*`),
	}
	sinks := []*regexp.Regexp{
		regexp.MustCompile(`eval`),
	}

	// Use a verbose logger
	findings, _ := AnalyzeJS(code, sources, sinks, logger.NewLogger(2))

	if len(findings) == 0 {
		t.Errorf("Expected finding for Lab 2 (eval sink), but got none")
	} else {
		t.Logf("Found %d findings", len(findings))
		for _, f := range findings {
			t.Logf("Finding: %s -> %s", f.Source, f.Sink)
		}
	}
}
