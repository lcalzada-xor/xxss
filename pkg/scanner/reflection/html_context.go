package reflection

import (
	"regexp"
	"strings"
)

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
	if lastTagStart == -1 {
		return false
	}
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
