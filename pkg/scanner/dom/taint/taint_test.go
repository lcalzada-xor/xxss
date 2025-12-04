package taint

import (
	"testing"
)

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		sources  []string
		sinks    []string
		expected int // number of findings
	}{
		{
			name:     "Direct Assignment",
			code:     `var x = location.hash; eval(x);`,
			sources:  []string{"location.hash"},
			sinks:    []string{"eval"},
			expected: 1,
		},
		{
			name:     "Transitive Assignment",
			code:     `var a = location.hash; var b = a; document.write(b);`,
			sources:  []string{"location.hash"},
			sinks:    []string{"document.write"},
			expected: 1,
		},
		{
			name:     "Concatenation",
			code:     `var a = location.search + "foo"; element.innerHTML = a;`,
			sources:  []string{"location.search"},
			sinks:    []string{"element.innerHTML"},
			expected: 1,
		},
		{
			name:     "Safe Scope Shadowing",
			code:     `var x = location.hash; function safe() { var x = "safe"; eval(x); } safe();`,
			sources:  []string{"location.hash"},
			sinks:    []string{"eval"},
			expected: 0, // Should be 0 because inner x is safe
		},
		{
			name:     "Global Access",
			code:     `x = location.hash; eval(x);`,
			sources:  []string{"location.hash"},
			sinks:    []string{"eval"},
			expected: 1,
		},
		{
			name:     "Member Expression Source",
			code:     `var x = window.location.hash; eval(x);`,
			sources:  []string{"window.location.hash"},
			sinks:    []string{"eval"},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, _, err := Analyze(tt.code, tt.sources, tt.sinks)
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}
			if len(findings) < tt.expected {
				t.Errorf("Expected at least %d findings, got %d", tt.expected, len(findings))
			}
		})
	}
}
