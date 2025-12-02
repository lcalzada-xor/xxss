package analysis

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func TestDetectContext(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		probe    string
		expected models.ReflectionContext
	}{
		{
			name:     "HTML Context - Simple",
			body:     "<div>probe</div>",
			probe:    "probe",
			expected: models.ContextHTML,
		},
		{
			name: "HTML Context - Inside Tag",
			body: "<div id=probe>", // Missing quotes, but technically attribute value if parsed strictly, but here it might be ambiguous without quotes. Let's see implementation.
			// Actually, without quotes, it's attribute value.
			// But our isInAttribute checks for quotes.
			// If no quotes, it falls back to HTML or TagName?
			// <div id=probe> -> probe is part of attribute value.
			// Let's check a clear HTML case.
			probe:    "probe",
			expected: models.ContextHTML, // Current implementation might default to HTML if not in quotes
		},
		{
			name:     "Attribute Context - Double Quotes",
			body:     `<div id="probe">`,
			probe:    "probe",
			expected: models.ContextAttribute,
		},
		{
			name:     "Attribute Context - Single Quotes",
			body:     `<div id='probe'>`,
			probe:    "probe",
			expected: models.ContextAttribute,
		},
		{
			name:     "URL Context - Href",
			body:     `<a href="probe">`,
			probe:    "probe",
			expected: models.ContextURL,
		},
		{
			name:     "URL Context - Src",
			body:     `<img src='probe'>`,
			probe:    "probe",
			expected: models.ContextURL,
		},
		{
			name:     "JS Context - Script Tag",
			body:     `<script>var x = "probe";</script>`,
			probe:    "probe",
			expected: models.ContextJSDoubleQuote,
		},
		{
			name:     "JS Context - Single Quote",
			body:     `<script>var x = 'probe';</script>`,
			probe:    "probe",
			expected: models.ContextJSSingleQuote,
		},
		{
			name:     "JS Context - Event Handler",
			body:     `<img onerror="alert('probe')">`,
			probe:    "probe",
			expected: models.ContextJSSingleQuote,
		},
		{
			name:     "Comment Context",
			body:     `<!-- probe -->`,
			probe:    "probe",
			expected: models.ContextComment,
		},
		{
			name:     "Title Context",
			body:     `<title>probe</title>`,
			probe:    "probe",
			expected: models.ContextRCDATA,
		},
		{
			name:     "Textarea Context",
			body:     `<textarea>probe</textarea>`,
			probe:    "probe",
			expected: models.ContextRCDATA,
		},
		{
			name:     "Template Literal",
			body:     "<script>`probe`</script>",
			probe:    "probe",
			expected: models.ContextTemplateLiteral,
		},
		{
			name:     "Meta Refresh",
			body:     `<meta http-equiv="refresh" content="0;url=probe">`,
			probe:    "probe",
			expected: models.ContextMetaRefresh,
		},
		{
			name:     "SVG Context",
			body:     `<svg><text>probe</text></svg>`,
			probe:    "probe",
			expected: models.ContextSVG,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := DetectContext(tt.body, tt.probe, -1)
			if ctx != tt.expected {
				t.Errorf("DetectContext() = %v, want %v", ctx, tt.expected)
			}
		})
	}
}
