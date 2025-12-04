package technologies

import (
	"testing"
)

func TestDependencyAnalyzer_Analyze(t *testing.T) {
	// Use default rules for testing, or we could mock them
	analyzer := NewDependencyAnalyzer(DefaultDependencies())

	tests := []struct {
		name         string
		input        []*Technology
		expectedName string
		shouldAdd    bool
	}{
		{
			name: "Bootstrap 4 implies jQuery",
			input: []*Technology{
				{Name: "Bootstrap", Version: "4.5.0", Confidence: "High"},
			},
			expectedName: "jQuery",
			shouldAdd:    true,
		},
		{
			name: "Bootstrap 5 does not imply jQuery",
			input: []*Technology{
				{Name: "Bootstrap", Version: "5.0.0", Confidence: "High"},
			},
			expectedName: "jQuery",
			shouldAdd:    false,
		},
		{
			name: "Backbone implies Underscore",
			input: []*Technology{
				{Name: "Backbone.js", Version: "1.4.0", Confidence: "High"},
			},
			expectedName: "Underscore.js",
			shouldAdd:    true,
		},
		{
			name: "Backbone with Lodash needs no Underscore",
			input: []*Technology{
				{Name: "Backbone.js", Version: "1.4.0", Confidence: "High"},
				{Name: "Lodash", Version: "4.17.20", Confidence: "High"},
			},
			expectedName: "Underscore.js",
			shouldAdd:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.Analyze(tt.input)

			found := false
			for _, tech := range result {
				if tech.Name == tt.expectedName {
					found = true
					break
				}
			}

			if found != tt.shouldAdd {
				t.Errorf("Analyze() found %s = %v, want %v", tt.expectedName, found, tt.shouldAdd)
			}
		})
	}
}
