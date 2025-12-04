package analysis

import (
	"regexp"
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
)

func TestPrototypePollutionClassification(t *testing.T) {
	tests := []struct {
		name               string
		code               string
		expectedConfidence string
		expectedSink       string
	}{
		{
			name:               "Static Assignment (Low Risk)",
			code:               `var obj = {}; obj.__proto__.polluted = "static";`,
			expectedConfidence: "LOW",
			expectedSink:       "Prototype Pollution",
		},
		{
			name:               "Dynamic Key Assignment (High Risk)",
			code:               `var obj = {}; obj[window.name] = "polluted";`,
			expectedConfidence: "HIGH",
			expectedSink:       "Dynamic Property Assignment",
		},
		{
			name:               "Tainted Value Assignment (High Risk)",
			code:               `var obj = {}; obj.__proto__.polluted = location.hash;`,
			expectedConfidence: "HIGH",
			expectedSink:       "Prototype Pollution",
		},
		{
			name:               "Safe Prototype Extension (Should be Ignored)",
			code:               `MyClass.prototype.method = function() {};`,
			expectedConfidence: "NONE", // Should not be found
			expectedSink:       "",
		},
	}

	sources := []*regexp.Regexp{
		regexp.MustCompile(`location\..*`),
		regexp.MustCompile(`window\.name`),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, _ := AnalyzeJS(tt.code, sources, nil, logger.NewLogger(0))

			found := false
			for _, f := range findings {
				if f.Sink == tt.expectedSink {
					found = true
					if f.Confidence != tt.expectedConfidence {
						t.Errorf("Expected confidence %s, got %s for %s", tt.expectedConfidence, f.Confidence, tt.name)
					}
				}
			}

			if !found && tt.expectedSink != "" {
				t.Errorf("Expected finding for %s, but got none", tt.name)
			}
			if found && tt.expectedSink == "" {
				t.Errorf("Unexpected finding for %s", tt.name)
			}
		})
	}
}
