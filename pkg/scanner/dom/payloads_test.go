package dom

import (
	"strings"
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/models"
)

func TestGenerateDOMPayload(t *testing.T) {
	tests := []struct {
		name     string
		sink     string
		context  models.ReflectionContext
		expected string // We check if it contains this or doesn't contain <script
	}{
		{
			name:     "innerHTML sink should not return script",
			sink:     "document.getElementById('x').innerHTML",
			context:  models.ContextUnknown,
			expected: "<img",
		},
		{
			name:     "outerHTML sink should not return script",
			sink:     "element.outerHTML",
			context:  models.ContextUnknown,
			expected: "<img",
		},
		{
			name:     "eval sink should return JS",
			sink:     "eval",
			context:  models.ContextUnknown,
			expected: "alert(1)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := GenerateDOMPayload(tc.sink, tc.context, nil)

			if strings.Contains(strings.ToLower(tc.sink), "html") {
				if strings.HasPrefix(payload, "<script") {
					t.Errorf("Expected non-script payload for %s, got %s", tc.sink, payload)
				}
			}

			if !strings.Contains(payload, tc.expected) && !strings.Contains(payload, "alert(1)") {
				// Loose check, mainly ensuring we get a valid payload
				t.Errorf("Expected payload containing '%s' or 'alert(1)', got '%s'", tc.expected, payload)
			}
		})
	}
}
