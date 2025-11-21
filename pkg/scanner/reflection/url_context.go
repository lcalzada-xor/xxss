package reflection

import (
	"regexp"
	"strings"
)

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

	if lastTagStart == -1 || lastTagEnd > lastTagStart {
		return false // Not inside a tag
	}

	// Count quotes to see if we're inside the URL value
	afterAttr := before[lastTagStart:]
	doubleQuotes := strings.Count(afterAttr, "\"")
	singleQuotes := strings.Count(afterAttr, "'")

	return (doubleQuotes%2 == 1) || (singleQuotes%2 == 1)
}

// isInDataURI checks if probe is inside a data URI
func isInDataURI(context, probe string) bool {
	// Check for data: URI scheme
	dataURIPattern := regexp.MustCompile(`(?i)(href|src|action|data|formaction)\s*=\s*["']?data:[^"'\s>]*` + regexp.QuoteMeta(probe))
	return dataURIPattern.MatchString(context)
}
