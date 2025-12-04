package analysis

import (
	"regexp"
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
)

func TestGTMFalsePositives(t *testing.T) {
	tests := []struct {
		name         string
		code         string
		shouldFind   bool
		expectedSink string
	}{
		{
			name:       "GTM location.href as key",
			code:       `var w = window; var obj = {}; obj[w.location.href] = "something";`,
			shouldFind: false, // Should be false because full URL cannot be __proto__
		},
		{
			name:       "GTM location.href directly",
			code:       `var obj = {}; obj[location.href] = "something";`,
			shouldFind: false,
		},
		{
			name:       "Generic tainted key (window.name)",
			code:       `var obj = {}; obj[window.name] = "something";`,
			shouldFind: true, // window.name is user controlled and could be "__proto__"
		},
	}

	sources := []*regexp.Regexp{
		regexp.MustCompile(`location\..*`),
		regexp.MustCompile(`w\.location\..*`),
		regexp.MustCompile(`window\.name`),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, _ := AnalyzeJS(tt.code, sources, nil, logger.NewLogger(0))

			found := false
			for _, f := range findings {
				if f.Sink == "Dynamic Property Assignment" {
					found = true
				}
			}

			if tt.shouldFind && !found {
				t.Errorf("Expected finding for %s, but got none", tt.name)
			}
			if !tt.shouldFind && found {
				t.Errorf("Unexpected finding for %s", tt.name)
			}
		})
	}
}
