package dom

// Sources: inputs controlled by attacker
var sourcePatterns = []string{
	`location\.search`,
	`location\.hash`,
	`location\.href`,
	`location\.pathname`,
	`location\.ancestorOrigins`,
	`document\.URL`,
	`document\.documentURI`,
	`document\.referrer`,
	`window\.name`,
	`window\.opener\.location`,
	`URLSearchParams`,
	`document\.cookie`,
	`localStorage`,
	`sessionStorage`,
	`navigation\.currentEntry`, // Modern Navigation API
	`document\.baseURI`,
	`event\.data`, // postMessage
	`e\.data`,     // postMessage (common alias)
}

// Sinks: dangerous execution points
var sinkPatterns = []string{
	// Execution
	`eval\(`,
	`setTimeout\(`,
	`setInterval\(`,
	`setImmediate\(`,
	`execScript\(`,
	`Function\(`,
	`importScripts\(`, // Web Workers
	// HTML Injection
	`innerHTML`,
	`outerHTML`,
	`insertAdjacentHTML`,
	`document\.write\(`,
	`document\.writeln\(`,
	`createContextualFragment\(`,
	`document\.implementation\.createHTMLDocument\(`,
	// Navigation / Open Redirect
	`location\.href\s*=`,
	`location\.replace\(`,
	`location\.assign\(`,
	`navigation\.navigate\(`, // Modern Navigation API
	`javascript:`,            // Pseudo-protocol
	// DOM Attributes & Methods
	`\.src\s*=`,
	`\.href\s*=`,
	`\.srcdoc\s*=`,
	`setAttribute\(`, // Needs careful checking
	// jQuery Sinks
	`\.html\(`,
	`\.append\(`,
	`\.prepend\(`,
	`\.wrap\(`,
	`\.after\(`,
	`\.before\(`,
	`\.attr\(`,
	// AngularJS Sinks
	`\$compile\(`,
	`\$sce\.trustAsHtml\(`,
	// React Sinks
	`dangerouslySetInnerHTML`,
	// Prototype Pollution
	`__proto__`,
	`prototype`,
	`constructor`,
}
