package payloads

import (
	"strings"
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/models"
)

// TestPayloadRanking verifies that payloads are recommended in the correct order
func TestPayloadRanking(t *testing.T) {
	// Test HTML Context - Should prefer SVG/IMG over SCRIPT
	t.Run("HTML Context Ranking", func(t *testing.T) {
		// Allow everything
		allowed := []string{"<", ">", "\"", "'", "/", "=", ";", "(", ")", " ", "`"}

		payload := GenerateReflectedPayload(models.ContextHTML, allowed, nil)

		// We expect SVG or IMG, not SCRIPT
		if strings.HasPrefix(payload, "<script") {
			t.Errorf("Expected non-script payload (SVG/IMG) to be prioritized, got: %s", payload)
		}

		if !strings.Contains(payload, "<svg") && !strings.Contains(payload, "<img") {
			t.Errorf("Expected SVG or IMG payload, got: %s", payload)
		}
	})

	// Test Attribute Context - Should prefer breakout with quotes
	t.Run("Attribute Context Ranking", func(t *testing.T) {
		allowed := []string{"<", ">", "\"", "'", "/", "=", ";", "(", ")", " ", "`"}

		payload := GenerateReflectedPayload(models.ContextAttribute, allowed, nil)

		// We expect double quote breakout first as it's most common
		if !strings.HasPrefix(payload, "\">") {
			t.Errorf("Expected double quote breakout payload first, got: %s", payload)
		}
	})
}
