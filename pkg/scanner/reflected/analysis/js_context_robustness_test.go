package analysis

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func TestAnalyzeJavaScriptContext_Complex(t *testing.T) {
	tests := []struct {
		name     string
		context  string
		probe    string
		expected models.ReflectionContext
	}{
		{
			name:     "Escaped Quote in String",
			context:  `var x = 'foo \' probe';`,
			probe:    "probe",
			expected: models.ContextJSSingleQuote,
		},
		{
			name:     "Quote in Comment",
			context:  `// This is a "comment" with probe`,
			probe:    "probe",
			expected: models.ContextComment,
		},
		{
			name: "Probe in Comment",
			context: `/* multi-line 
			comment with probe */`,
			probe:    "probe",
			expected: models.ContextComment,
		},
		{
			name:     "Regex Literal",
			context:  `var re = /probe/;`,
			probe:    "probe",
			expected: models.ContextJSRaw, // Regex is effectively raw for our purposes (or specialized)
		},
		{
			name:     "Template Literal Nested",
			context:  "`outer ${ `inner probe` }`",
			probe:    "probe",
			expected: models.ContextTemplateLiteral,
		},
		{
			name:     "Slash in String",
			context:  `var x = "http://example.com/probe";`,
			probe:    "probe",
			expected: models.ContextJSDoubleQuote,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isJS, ctx := analyzeJavaScriptContext(tt.context, tt.probe, -1)
			// For this test, we assume analyzeJavaScriptContext is called appropriately (e.g. inside script tag)
			// But since analyzeJavaScriptContext takes the whole context, we might need to wrap it in script tags for the regex to match
			// OR we can test the internal logic if we export it.
			// The current implementation checks for <script> tags first.

			// Let's wrap in script tags to trigger the logic
			fullContext := "<script>" + tt.context + "</script>"
			isJS, ctx = analyzeJavaScriptContext(fullContext, tt.probe, -1)

			if !isJS {
				t.Errorf("Expected JS context, got none")
			}
			if ctx != tt.expected {
				t.Errorf("Context: got %v, want %v", ctx, tt.expected)
			}
		})
	}
}
