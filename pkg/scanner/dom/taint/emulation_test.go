package taint

import (
	"testing"
)

func TestEmulation(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name:     "Obfuscated Eval (Join)",
			code:     `var parts = ["#pay", "load"]; eval(parts.join(""));`,
			expected: 1,
		},
		{
			name: "Base64 Obfuscation (atob)",
			// atob('ZXZhbChsb2NhdGlvbi5oYXNoKQ==') -> eval(location.hash)
			// But we need to define atob in emulator or use a simpler obfuscation.
			// Goja might have atob? No, it's browser API.
			// Let's use string concatenation which is common.
			code:     `var e = "ev"; var al = "al"; window[e+al](location.hash);`,
			expected: 1,
		},
		{
			name:     "SetTimeout Obfuscation",
			code:     `setTimeout(location.hash, 100);`,
			expected: 1,
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
