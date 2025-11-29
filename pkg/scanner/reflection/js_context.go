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
	probeIndex := strings.Index(context, probe)
	if probeIndex == -1 {
		return false, models.ContextUnknown
	}

	before := context[:probeIndex]
	lastTagStart := strings.LastIndex(before, "<")
	if lastTagStart == -1 {
		return false, models.ContextUnknown
	}

	// Check if we are inside a tag (no closing > after <)
	if strings.LastIndex(before, ">") > lastTagStart {
		return false, models.ContextUnknown
	}

	tagContent := before[lastTagStart+1:]

	// Parse attributes to find which one we are inside
	var lastAttrName string
	var buffer strings.Builder
	inQuote := false
	var quoteChar rune

	for _, c := range tagContent {
		if inQuote {
			if rune(c) == quoteChar {
				inQuote = false
			}
			continue
		}

		if c == '"' || c == '\'' {
			inQuote = true
			quoteChar = rune(c)
			continue
		}

		if c == '=' {
			name := strings.TrimSpace(buffer.String())
			if name != "" {
				lastAttrName = name
			}
			buffer.Reset()
			continue
		}

		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if buffer.Len() > 0 {
				name := strings.TrimSpace(buffer.String())
				if name != "" {
					lastAttrName = name
				}
				buffer.Reset()
			}
			continue
		}

		buffer.WriteRune(c)
	}

	// Check if the last attribute name starts with "on"
	if strings.HasPrefix(strings.ToLower(lastAttrName), "on") {
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
