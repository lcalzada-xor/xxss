package reflection

import (
	"regexp"
	"strings"
)

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

	if lastTagStart == -1 || lastTagEnd > lastTagStart {
		return false // Not inside a tag
	}

	// Count quotes to see if we're inside the style value
	afterStyle := before[lastTagStart:]
	doubleQuotes := strings.Count(afterStyle, "\"")
	singleQuotes := strings.Count(afterStyle, "'")

	return (doubleQuotes%2 == 1) || (singleQuotes%2 == 1)
}
