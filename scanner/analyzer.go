package scanner

import (
	"strings"
)

// SpecialChars is the set of characters we want to probe for XSS.
var SpecialChars = []string{"\"", "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}"}

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
		
		// Heuristic: The reflected chars shouldn't be excessively long.
		// If it's > 200 chars, it might be a large chunk of HTML between two coincidental probes
		// (unlikely with "xssprobe", but safe to check).
		if len(part) > 200 {
			continue
		}

		for _, char := range SpecialChars {
			if strings.Contains(part, char) {
				uniqueUnfiltered[char] = true
			}
		}
	}

	for char := range uniqueUnfiltered {
		unfiltered = append(unfiltered, char)
	}

	return unfiltered
}
