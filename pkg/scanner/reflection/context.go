package reflection

import (
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// DetectContext analyzes the HTML around the probe to determine reflection context
func DetectContext(body, probe string) models.ReflectionContext {
	// Find first occurrence of probe
	index := strings.Index(body, probe)
	if index == -1 {
		return models.ContextUnknown
	}

	// Get surrounding context (500 chars before and after)
	start := max(0, index-500)
	end := min(len(body), index+len(probe)+500)
	context := body[start:end]

	// Check for AngularJS first (before other checks)
	// We keep the explicit template check here for high confidence
	// Check for AngularJS first (before other checks)
	// We keep the explicit template check here for high confidence
	isAngularApp := detectAngularJS(body)
	if isAngularApp {
		if isInAngularTemplate(context, probe) {
			return models.ContextAngular
		}
	}

	// Check contexts in order of specificity
	if isInComment(context, probe) {
		return models.ContextComment
	}

	if isInMetaRefresh(context, probe) {
		return models.ContextMetaRefresh
	}

	if isInDataURI(context, probe) {
		return models.ContextDataURI
	}

	if isInSVG(context, probe) {
		return models.ContextSVG
	}

	if isInTemplateLiteral(context, probe) {
		return models.ContextTemplateLiteral
	}

	if isJS, jsContext := analyzeJavaScriptContext(context, probe); isJS {
		return jsContext
	}

	if isInCSS(context, probe) {
		return models.ContextCSS
	}

	if isInURL(context, probe) {
		return models.ContextURL
	}

	if isInTagName(context, probe) {
		return models.ContextTagName
	}

	if isInRCDATA(context, probe) {
		return models.ContextRCDATA
	}

	if isInAttribute(context, probe) {
		return models.ContextAttribute
	}

	// Default to HTML
	// If it's an Angular app and we are in HTML context, it's likely CSTI
	if isAngularApp {
		return models.ContextAngular
	}
	return models.ContextHTML
}

// DetectContextVerbose is like DetectContext but logs detailed information for debugging
func DetectContextVerbose(body, probe string, logger interface {
	VV(string, ...interface{})
	Detail(string, ...interface{})
}) models.ReflectionContext {
	// Find first occurrence of probe
	index := strings.Index(body, probe)
	if index == -1 {
		logger.Detail("Type: Unknown (probe not found)")
		return models.ContextUnknown
	}

	// Get surrounding context (500 chars before and after)
	start := max(0, index-500)
	end := min(len(body), index+len(probe)+500)
	context := body[start:end]

	// Get snippet around probe (±50 chars)
	snippetStart := max(0, index-50)
	snippetEnd := min(len(body), index+len(probe)+50)
	snippet := body[snippetStart:snippetEnd]
	// Truncate snippet for display
	if len(snippet) > 100 {
		snippet = snippet[:100] + "..."
	}

	// Check for AngularJS first (before other checks)
	isAngularApp := detectAngularJS(body)
	if isAngularApp {
		if isInAngularTemplate(context, probe) {
			logger.Detail("Type: %s", models.ContextAngular)
			logger.VV("Snippet: %s", snippet)
			logger.Detail("Reason: Inside AngularJS template expression")
			return models.ContextAngular
		}
	}

	// Check contexts in order of specificity
	if isInComment(context, probe) {
		logger.Detail("Type: %s", models.ContextComment)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside HTML comment")
		return models.ContextComment
	}

	if isInMetaRefresh(context, probe) {
		logger.Detail("Type: %s", models.ContextMetaRefresh)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside meta refresh tag")
		return models.ContextMetaRefresh
	}

	if isInDataURI(context, probe) {
		logger.Detail("Type: %s", models.ContextDataURI)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside data URI")
		return models.ContextDataURI
	}

	if isInSVG(context, probe) {
		logger.Detail("Type: %s", models.ContextSVG)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside SVG element")
		return models.ContextSVG
	}

	if isInTemplateLiteral(context, probe) {
		logger.Detail("Type: %s", models.ContextTemplateLiteral)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside JavaScript template literal")
		return models.ContextTemplateLiteral
	}

	if isJS, jsContext := analyzeJavaScriptContext(context, probe); isJS {
		logger.Detail("Type: %s", jsContext)
		logger.VV("Snippet: %s", snippet)
		switch jsContext {
		case models.ContextJSSingleQuote:
			logger.Detail("Reason: Inside single-quoted JavaScript string")
		case models.ContextJSDoubleQuote:
			logger.Detail("Reason: Inside double-quoted JavaScript string")
		case models.ContextJSRaw:
			logger.Detail("Reason: Inside raw JavaScript code")
		default:
			logger.Detail("Reason: Inside JavaScript context")
		}
		return jsContext
	}

	if isInCSS(context, probe) {
		logger.Detail("Type: %s", models.ContextCSS)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside CSS style block")
		return models.ContextCSS
	}

	if isInURL(context, probe) {
		logger.Detail("Type: %s", models.ContextURL)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside URL attribute (href, src, etc.)")
		return models.ContextURL
	}

	if isInTagName(context, probe) {
		logger.Detail("Type: %s", models.ContextTagName)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside HTML tag name")
		return models.ContextTagName
	}

	if isInRCDATA(context, probe) {
		logger.Detail("Type: %s", models.ContextRCDATA)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside RCDATA element (title, textarea)")
		return models.ContextRCDATA
	}

	if isInAttribute(context, probe) {
		logger.Detail("Type: %s", models.ContextAttribute)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: Inside HTML attribute value")
		return models.ContextAttribute
	}

	// Default to HTML
	if isAngularApp {
		logger.Detail("Type: %s", models.ContextAngular)
		logger.VV("Snippet: %s", snippet)
		logger.Detail("Reason: HTML context in AngularJS application (CSTI)")
		return models.ContextAngular
	}

	logger.Detail("Reason: Default HTML context")
	return models.ContextHTML
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// detectAngularJS checks if the response contains AngularJS indicators
func detectAngularJS(body string) bool {
	indicators := []string{
		"ng-app",
		"ng-controller",
		"angular.js",
		"angular.min.js",
		"data-ng-app",
		"x-ng-app",
		"ng-bind",
		"ng-model",
	}

	bodyLower := strings.ToLower(body)
	for _, indicator := range indicators {
		if strings.Contains(bodyLower, indicator) {
			return true
		}
	}
	return false
}

// isInAngularTemplate checks if probe is inside AngularJS template syntax
func isInAngularTemplate(context, probe string) bool {
	// Look for probe inside {{ }} expressions
	beforeProbe := context[:strings.Index(context, probe)]
	afterProbe := context[strings.Index(context, probe)+len(probe):]

	// Count {{ and }} before probe
	openBraces := strings.Count(beforeProbe, "{{")
	closeBraces := strings.Count(beforeProbe, "}}")

	// If more {{ than }}, we're inside a template
	if openBraces > closeBraces {
		// Check if there's a closing }} after probe
		if strings.Contains(afterProbe, "}}") {
			return true
		}
	}

	// Also check if inside ng-* attributes
	if strings.Contains(beforeProbe, "ng-") {
		// Look for attribute value context
		lastQuote := strings.LastIndexAny(beforeProbe, "\"'")
		if lastQuote != -1 {
			// Check if there's a closing quote after probe
			if strings.ContainsAny(afterProbe, "\"'") {
				return true
			}
		}
	}

	return false
}
