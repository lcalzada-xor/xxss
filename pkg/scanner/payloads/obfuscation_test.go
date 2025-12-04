package payloads

import (
	"strings"
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/models"
)

func TestObfuscate(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		method   ObfuscationType
		expected string
	}{
		{
			name:     "JS Unicode",
			payload:  "alert(1)",
			method:   ObfuscateJSUnicode,
			expected: "alert\\u00281\\u0029",
		},
		{
			name:     "JS Concat Alert",
			payload:  "alert(1)",
			method:   ObfuscateJSConcat,
			expected: "'al'+'ert'(1)",
		},
		{
			name:     "HTML Entities",
			payload:  "<script>",
			method:   ObfuscateHTMLEntities,
			expected: "&#60;script&#62;",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Obfuscate(tc.payload, tc.method)
			if got != tc.expected {
				t.Errorf("Obfuscate(%q) = %q, want %q", tc.payload, got, tc.expected)
			}
		})
	}
}

func TestGenerateReflectedPayload_Obfuscation(t *testing.T) {
	// Scenario 1: JS Context, parens blocked, but \ and u allowed -> Unicode
	t.Run("JS Unicode Fallback", func(t *testing.T) {
		allowed := []string{"'", ";", "\\", "u", "a", "l", "e", "r", "t", "1"} // Parens missing
		payload := GenerateReflectedPayload(models.ContextJSSingleQuote, allowed, nil)

		// Expect Unicode encoded parens
		if !strings.Contains(payload, "\\u0028") {
			t.Errorf("Expected Unicode obfuscation, got: %s", payload)
		}
	})

	// Scenario 2: JS Context, parens blocked, \ blocked, but ' and + allowed -> Concat
	// Note: Concat doesn't fix blocked parens, it fixes blocked keywords.
	// Let's assume 'alert' keyword is blocked (not simulated by IsAllowed yet)
	// Actually IsAllowed only checks chars.
	// So let's test that Concat is tried if clean fails.
	// But clean fails if chars are missing. Concat uses ' and +.
	// If clean payload has "alert" and we pretend "alert" is blocked... IsAllowed doesn't support that.
	// Wait, ObfuscateJSConcat replaces "alert" with "'al'+'ert'".
	// This increases char requirements (needs ' and +).
	// So if clean payload is allowed, it returns clean.
	// Obfuscation is only tried if clean is NOT allowed.
	// So we need a case where clean is NOT allowed, but Concat IS allowed.
	// Clean: "alert(1)" -> needs (, )
	// Concat: "'al'+'ert'(1)" -> needs ', +, (, )
	// So Concat is strictly MORE demanding on chars if we only check chars.
	// Unless... clean payload uses chars that are blocked?
	// Example: Clean uses " (double quote) but allowed has ' (single quote).
	// But vectors have both single and double quote versions.

	// The current ObfuscateJSConcat is useful for WAF bypass (keyword filtering),
	// but IsAllowed doesn't check keywords.
	// So GenerateReflectedPayload won't pick it unless clean is blocked by chars.
	// But Concat adds chars, so it won't help with char blocking unless it REPLACES blocked chars.
	// It doesn't replace blocked chars, it splits strings.

	// However, JS Unicode DOES replace blocked chars (parens -> \u0028).
	// So Scenario 1 is valid.

	// Scenario 3: Attribute Context, < blocked, but & # ; allowed -> HTML Entities
	t.Run("HTML Entity Fallback", func(t *testing.T) {
		// ContextAttribute usually uses handlers like onmouseover=...
		// Vector: " onmouseover=alert(1) x="
		// Needs: " = ( )
		// If " is blocked?
		// Entity: &#34; onmouseover=alert(1) x=&#34;
		// This might work if & # ; are allowed.

		allowed := []string{"&", "#", ";", "=", "(", ")", " ", "o", "n", "m", "o", "u", "s", "e", "o", "v", "e", "r", "a", "l", "e", "r", "t", "1", "x"}
		// " is missing.

		payload := GenerateReflectedPayload(models.ContextAttribute, allowed, nil)

		if !strings.Contains(payload, "&#34;") {
			t.Errorf("Expected HTML Entity obfuscation, got: %s", payload)
		}
	})
}
