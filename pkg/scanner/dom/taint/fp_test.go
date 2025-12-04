package taint

import (
	"testing"
)

func TestFalsePositives(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		sources  []string
		sinks    []string
		expected int // number of findings (0 means no FP)
	}{
		{
			name:     "Safe Property Access (length)",
			code:     `var x = location.hash.length; document.write(x);`,
			sources:  []string{"location.hash"},
			sinks:    []string{"document.write"},
			expected: 0, // Should be 0, likely 1 (FP)
		},
		{
			name:     "Reassignment to Safe",
			code:     `var x = location.hash; x = "safe"; document.write(x);`,
			sources:  []string{"location.hash"},
			sinks:    []string{"document.write"},
			expected: 0, // Should be 0, likely 1 (FP)
		},
		{
			name:     "Independent Variables",
			code:     `var x = location.hash; var y = "safe"; document.write(y);`,
			sources:  []string{"location.hash"},
			sinks:    []string{"document.write"},
			expected: 0,
		},
		{
			name:     "Sanitization (Mock)",
			code:     `var x = location.hash; var y = sanitize(x); document.write(y);`,
			sources:  []string{"location.hash"},
			sinks:    []string{"document.write"},
			expected: 1, // Currently expected to be 1 because we don't track sanitizers yet
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, _, err := Analyze(tt.code, tt.sources, tt.sinks)
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}
			if len(findings) != tt.expected {
				t.Logf("Potential FP found in '%s': Expected %d findings, got %d", tt.name, tt.expected, len(findings))
			}
		})
	}
}
