package reflection

import (
	"regexp"
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

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

	if lastTagStart == -1 || lastTagEnd > lastTagStart {
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
