package dom

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
)

func TestDOMClobberingFalsePositives(t *testing.T) {
	// Quiet logger
	log := logger.NewLogger(0)
	scanner := NewDOMScanner(log)

	tests := []struct {
		name          string
		html          string
		shouldFind    bool
		expectedLevel string // "HIGH" or "MEDIUM"
	}{
		{
			name: "Unused ID (Sensitive Name) - Should be ignored",
			html: `
				<form id="userpass"></form>
				<script>
					var x = 1;
				</script>
			`,
			shouldFind: false, // Currently fails (finds MEDIUM)
		},
		{
			name: "Used ID - Should be found",
			html: `
				<form id="userpass"></form>
				<script>
					var x = userpass.value;
				</script>
			`,
			shouldFind:    true,
			expectedLevel: "HIGH",
		},
		{
			name: "Used ID via window - Should be found",
			html: `
				<div id="config"></div>
				<script>
					window.config.debug = true;
				</script>
			`,
			shouldFind:    true,
			expectedLevel: "HIGH",
		},
		{
			name: "Unused ID (Non-Sensitive) - Should be ignored",
			html: `
				<div id="randomthing"></div>
				<script>
					var x = 1;
				</script>
			`,
			shouldFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.ScanDOM(tt.html)
			found := false
			var confidence string
			for _, f := range findings {
				if f.Sink == "Global Variable Clobbering" {
					found = true
					confidence = f.Confidence
					break
				}
			}

			if tt.shouldFind && !found {
				t.Errorf("Expected to find DOM Clobbering, but got none")
			}
			if !tt.shouldFind && found {
				t.Errorf("Expected NO DOM Clobbering, but got one (Confidence: %s)", confidence)
			}
			if tt.shouldFind && found && tt.expectedLevel != "" && confidence != tt.expectedLevel {
				t.Errorf("Expected confidence %s, got %s", tt.expectedLevel, confidence)
			}
		})
	}
}
