package analysis

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/models"
)

func TestAnalyzeJavaScriptContext_EventHandlers(t *testing.T) {
	tests := []struct {
		name     string
		context  string
		probe    string
		expected models.ReflectionContext
	}{
		{
			name:     "Standard onclick",
			context:  `<img src=x onclick="alert('probe')">`,
			probe:    "probe",
			expected: models.ContextJSSingleQuote,
		},
		{
			name:     "Onclick with double quotes",
			context:  `<div onclick='alert("probe")'>`,
			probe:    "probe",
			expected: models.ContextJSDoubleQuote,
		},
		{
			name:     "Unquoted attribute (HTML5)",
			context:  `<div onclick=alert(probe)>`,
			probe:    "probe",
			expected: models.ContextJSRaw,
		},
		{
			name:     "Malformed HTML (missing closing quote)",
			context:  `<div onclick="alert('probe)`,
			probe:    "probe",
			expected: models.ContextJSSingleQuote, // Tokenizer handles this gracefully usually
		},
		{
			name:     "Complex nesting",
			context:  `<a href="#" onclick="if(confirm('test')){ window.location='probe'; }">Click me</a>`,
			probe:    "probe",
			expected: models.ContextJSSingleQuote,
		},
		{
			name:     "Not an event handler",
			context:  `<div class="probe">`,
			probe:    "probe",
			expected: models.ContextUnknown,
		},
		{
			name:     "Event handler but probe not in it",
			context:  `<div onclick="alert(1)" class="probe">`,
			probe:    "probe",
			expected: models.ContextUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isJS, ctx := analyzeJavaScriptContext(tt.context, tt.probe, -1)

			if tt.expected == models.ContextUnknown {
				if isJS {
					t.Errorf("Expected NOT JS context, got %s", ctx)
				}
			} else {
				if !isJS {
					t.Errorf("Expected JS context, got none")
				}
				if ctx != tt.expected {
					t.Errorf("Context: got %v, want %v", ctx, tt.expected)
				}
			}
		})
	}
}
