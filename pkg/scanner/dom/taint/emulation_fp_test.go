package taint

import (
	"testing"
)

func TestEmulationFalsePositives(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected int // Should be 0 for FPs
	}{
		{
			name:     "Safe Execution",
			code:     `var x = 1 + 1; var y = x * 2;`,
			expected: 0,
		},
		{
			name:     "Safe Sink Usage",
			code:     `document.write("Hello World");`,
			expected: 0,
		},
		{
			name:     "Unreachable Sink",
			code:     `if (false) { eval(location.hash); }`,
			expected: 0,
		},
		{
			name:     "Safe String Operation",
			code:     `var x = "safe"; eval(x);`,
			expected: 0,
		},
		{
			name:     "Dead Code (Function not called)",
			code:     `function dangerous() { eval(location.hash); }`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We pass empty patterns because we rely on emulator's internal traps
			findings, _, err := Analyze(tt.code, []string{}, []string{})
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}

			found := 0
			for _, f := range findings {
				if f.Source == "Emulator" {
					found++
				}
			}

			if found != tt.expected {
				t.Errorf("Expected %d emulator findings, got %d", tt.expected, found)
			}
		})
	}
}
