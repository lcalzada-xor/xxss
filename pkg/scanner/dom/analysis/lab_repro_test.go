package analysis

import (
	"regexp"
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
)

func TestRealLabDetection(t *testing.T) {
	code := `
		var stores = ["London","Paris","Milan"];
		var store = (new URLSearchParams(window.location.search)).get('storeId');
		document.write('<select name="storeId">');
		if(store) {
			document.write('<option selected>'+store+'</option>');
		}
		for(var i=0;i<stores.length;i++) {
			if(stores[i] === store) {
				continue;
			}
			document.write('<option>'+stores[i]+'</option>');
		}
		document.write('</select>');
	`
	sources := []*regexp.Regexp{
		regexp.MustCompile(`location\..*`),
	}
	sinks := []*regexp.Regexp{
		regexp.MustCompile(`document\.write`),
	}

	findings, _ := AnalyzeJS(code, sources, sinks, logger.NewLogger(0))

	if len(findings) == 0 {
		t.Errorf("Expected finding for real lab code, but got none")
	} else {
		t.Logf("Found %d findings", len(findings))
		for _, f := range findings {
			t.Logf("Finding: %s -> %s", f.Source, f.Sink)
		}
	}
}
