package payloads

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/models"
)

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name    string
		vector  PayloadVector
		allowed []string
		want    bool
	}{
		{
			name: "Allowed empty (unknown constraints)",
			vector: PayloadVector{
				Content:       "<script>alert(1)</script>",
				RequiredChars: []string{"<", ">"},
			},
			allowed: []string{},
			want:    true,
		},
		{
			name: "All required chars present",
			vector: PayloadVector{
				Content:       "<script>alert(1)</script>",
				RequiredChars: []string{"<", ">"},
			},
			allowed: []string{"<", ">", "a", "b", "c"},
			want:    true,
		},
		{
			name: "Missing required char",
			vector: PayloadVector{
				Content:       "<script>alert(1)</script>",
				RequiredChars: []string{"<", ">"},
			},
			allowed: []string{"<", "a", "b", "c"}, // Missing >
			want:    false,
		},
		{
			name: "Fallback logic (No RequiredChars)",
			vector: PayloadVector{
				Content:       "alert(1)",
				RequiredChars: nil,
			},
			allowed: []string{"(", ")"},
			want:    true,
		},
		{
			name: "Fallback logic (Missing char)",
			vector: PayloadVector{
				Content:       "<script>",
				RequiredChars: nil,
			},
			allowed: []string{"a", "b"}, // Missing < and >
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAllowed(tt.vector, tt.allowed); got != tt.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateReflectedPayload_SmartSelection(t *testing.T) {
	// Test that it selects a payload that fits the allowed chars
	allowed := []string{"'", ";", "(", ")", "/"} // Single quote allowed, double quote blocked

	// We expect a single quote payload
	payload := GenerateReflectedPayload(models.ContextJSSingleQuote, allowed, nil)

	if payload == "" {
		t.Fatal("Expected a payload, got empty string")
	}

	// Should pick one of the single quote payloads
	// e.g., ';alert(1);//
	expected := "';alert(1);//"
	if payload != expected && payload != "');alert(1);//" && payload != "')};alert(1);//" {
		t.Errorf("Expected single quote payload, got: %s", payload)
	}
}
