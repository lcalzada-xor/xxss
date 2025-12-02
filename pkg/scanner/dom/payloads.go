package dom

import (
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/technologies"
)

// GenerateDOMPayload suggests a payload based on the sink type and context
func GenerateDOMPayload(sink string, context models.ReflectionContext, techs []*technologies.Technology) string {
	// Standard allowed characters for static analysis assumption
	allowed := []string{"<", ">", "\"", "'", "/", "=", ";", "(", ")", " ", "`"}

	// If context is unknown, try to infer from sink (legacy behavior support)
	if context == models.ContextUnknown {
		sink = strings.ToLower(sink)
		if strings.Contains(sink, "innerhtml") || strings.Contains(sink, "outerhtml") || strings.Contains(sink, "document.write") {
			context = models.ContextHTML
		} else if strings.Contains(sink, "eval") || strings.Contains(sink, "settimeout") || strings.Contains(sink, "function") {
			context = models.ContextJSRaw // or ContextJSSingleQuote/DoubleQuote depending on injection
		} else if strings.Contains(sink, "location") || strings.Contains(sink, "href") || strings.Contains(sink, "src") {
			context = models.ContextAttribute // Often attribute injection or javascript: protocol
		}
	}

	// Special handling for innerHTML/outerHTML/jQuery to avoid <script> tags which don't execute
	lowerSink := strings.ToLower(sink)
	if strings.Contains(lowerSink, "innerhtml") || strings.Contains(lowerSink, "outerhtml") || sink == "$" || sink == "jQuery" {
		context = models.ContextHTML
		// Iterate over vectors to find a non-script payload
		for _, v := range payloads.Vectors {
			if v.Context == models.ContextHTML &&
				payloads.IsAllowed(v, allowed) &&
				!strings.HasPrefix(strings.ToLower(v.Content), "<script") {
				return v.Content
			}
		}
	}

	return payloads.GenerateReflectedPayload(context, allowed, techs)
}
