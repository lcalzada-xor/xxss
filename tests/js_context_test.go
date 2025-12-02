package tests

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/reflected/analysis"
)

func TestGranularJSContext(t *testing.T) {
	tests := []struct {
		name            string
		context         string
		probe           string
		expectedContext models.ReflectionContext
		expectedPayload string
	}{
		{
			name:            "JS Single Quote",
			context:         "<script>var x = 'PROBE';</script>",
			probe:           "PROBE",
			expectedContext: models.ContextJSSingleQuote,
			expectedPayload: "';alert(1);//",
		},
		{
			name:            "JS Double Quote",
			context:         "<script>var x = \"PROBE\";</script>",
			probe:           "PROBE",
			expectedContext: models.ContextJSDoubleQuote,
			expectedPayload: "\";alert(1);\"",
		},
		{
			name:            "JS Raw",
			context:         "<script>var x = PROBE;</script>",
			probe:           "PROBE",
			expectedContext: models.ContextJSRaw,
			expectedPayload: "\\\"-alert(1)}//",
		},
		{
			name:            "JS Raw No Semicolon",
			context:         "<script>if(PROBE){}</script>",
			probe:           "PROBE",
			expectedContext: models.ContextJSRaw,
			expectedPayload: "\\\"-alert(1)}//",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := analysis.DetectContext(tt.context, tt.probe, -1)
			if ctx != tt.expectedContext {
				t.Errorf("DetectContext() = %v, want %v", ctx, tt.expectedContext)
			}

			// Test payload suggestion
			unfiltered := []string{"'", "\"", ";", "(", ")", "/"}
			payload := payloads.GenerateReflectedPayload(ctx, unfiltered, nil)
			if payload != tt.expectedPayload {
				t.Errorf("GetSuggestedPayload() = %q, want %q", payload, tt.expectedPayload)
			}
		})
	}
}
