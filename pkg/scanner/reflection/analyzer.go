package reflection

import (
	"strings"
)

// SpecialChars is the set of characters we want to probe for XSS.
// Expanded list to catch XSS without quotes and other edge cases.
var SpecialChars = []string{
	"\"", "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}",
	"&", "#", "=", "/", " ", "\t", "%", "\\", ".", "[", "]", "+", "-", "*",
}

// htmlEncodings maps special characters to their HTML entity equivalents
var htmlEncodings = map[string][]string{
	"<":  {"&lt;", "&#60;", "&#x3c;", "&#x3C;"},
	">":  {"&gt;", "&#62;", "&#x3e;", "&#x3E;"},
	"\"": {"&quot;", "&#34;", "&#x22;"},
	"'":  {"&#39;", "&#x27;", "&apos;"},
	"&":  {"&amp;", "&#38;", "&#x26;"},
	"/":  {"&#47;", "&#x2f;", "&#x2F;"},
}

// isHTMLEncoded checks if a character appears in its HTML-encoded form in the body
func isHTMLEncoded(body, char string) bool {
	encodings, exists := htmlEncodings[char]
	if !exists {
		return false
	}

	for _, encoding := range encodings {
		if strings.Contains(body, encoding) {
			return true
		}
	}
	return false
}

// AnalyzeResponse checks if the probe string and special characters are reflected in the body.
func AnalyzeResponse(body, probe string) []string {
	unfiltered := []string{}
	uniqueUnfiltered := make(map[string]bool)

	// We inject: probe + chars + probe
	// So we look for content strictly between two occurrences of the probe.
	parts := strings.Split(body, probe)

	// If we have fewer than 3 parts, it means we didn't find two probes surrounding content.
	// e.g. "prefix probe chars suffix" -> 2 parts.
	// We need at least "prefix probe chars probe suffix" -> 3 parts.
	if len(parts) < 3 {
		return unfiltered
	}

	// Check all parts that are "between" probes.
	// parts[0] is the content before the first probe.
	// parts[len-1] is the content after the last probe.
	// Everything else is sandwiched between probes.
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]

		// Increased limit from 200 to 1000 to avoid missing legitimate reflections
		// while still preventing analysis of huge HTML chunks
		if len(part) > 1000 {
			continue
		}

		for _, char := range SpecialChars {
			if strings.Contains(part, char) {
				// Check if this character is HTML-encoded in the full body
				// If it's encoded, it's likely not exploitable (reduce false positives)
				// But we still report it since xxss is a screening tool (dalfox will verify)
				if isHTMLEncoded(body, char) {
					// Character appears encoded somewhere, but also appears unencoded in this part
					// This is still worth reporting for dalfox to analyze
					uniqueUnfiltered[char] = true
				} else {
					// Character appears unencoded - definitely report it
					uniqueUnfiltered[char] = true
				}
			}
		}
	}

	for char := range uniqueUnfiltered {
		unfiltered = append(unfiltered, char)
	}

	return unfiltered
}
