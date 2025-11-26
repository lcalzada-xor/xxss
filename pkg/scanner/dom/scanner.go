package dom

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/dom/analysis"
)

// DOMScanner handles static analysis for DOM XSS.
// It uses regex patterns and simple AST analysis to detect potential vulnerabilities.
type DOMScanner struct {
	sources     []*regexp.Regexp
	sinks       []*regexp.Regexp
	scriptCache sync.Map // map[string]string (URL -> Content)
	logger      *logger.Logger
}

// NewDOMScanner creates a new DOM scanner with compiled regexes for sources and sinks.
func NewDOMScanner(logger *logger.Logger) *DOMScanner {
	ds := &DOMScanner{
		logger: logger,
	}

	for _, p := range sourcePatterns {
		ds.sources = append(ds.sources, regexp.MustCompile(p))
	}

	for _, p := range sinkPatterns {
		ds.sinks = append(ds.sinks, regexp.MustCompile(p))
	}

	return ds
}

// SetVerboseLevel sets the verbosity level for the DOM scanner.
func (ds *DOMScanner) SetVerboseLevel(level int) {
	ds.logger = logger.NewLogger(level)
}

// ScanDOM analyzes the HTML/JS content for DOM XSS patterns using AST analysis.
// It extracts scripts and checks for dangerous flows from sources to sinks.
func (ds *DOMScanner) ScanDOM(body string) []models.DOMFinding {
	var findings []models.DOMFinding

	ds.logger.Section("DOM XSS Scan")

	// 1. Extract Scripts (Inline and External)
	// We need to parse JS code, but the input is likely HTML.
	// Simple extraction of <script> content for now.
	// In a real browser, we'd have the DOM, but here we are static.

	// Extract inline script content
	scriptContentRegex := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
	matches := scriptContentRegex.FindAllStringSubmatch(body, -1)

	var jsCodeBlocks []string
	for _, match := range matches {
		if len(match) > 1 {
			jsCodeBlocks = append(jsCodeBlocks, match[1])
		}
	}

	// NEW: Extract Event Handlers (onload, onerror, etc.)
	// Regex to find attributes starting with "on"
	eventHandlerRegex := regexp.MustCompile(`\s(on\w+)\s*=\s*["']([^"']+)["']`)
	eventMatches := eventHandlerRegex.FindAllStringSubmatch(body, -1)
	for _, match := range eventMatches {
		if len(match) > 2 {
			attrName := match[1]
			jsCode := match[2]
			ds.logger.VV("DOM: Found event handler '%s' with code: %s", attrName, jsCode)
			jsCodeBlocks = append(jsCodeBlocks, jsCode)
		}
	}

	// NEW: Extract Framework Directives (v-html, ng-bind-html)
	// These are sinks themselves, so we check if the value is a source
	frameworkDirectiveRegex := regexp.MustCompile(`\s(v-html|ng-bind-html)\s*=\s*["']([^"']+)["']`)
	directiveMatches := frameworkDirectiveRegex.FindAllStringSubmatch(body, -1)
	for _, match := range directiveMatches {
		if len(match) > 2 {
			directive := match[1]
			value := match[2]
			ds.logger.VV("DOM: Found framework directive '%s' with value: %s", directive, value)

			// Check if value is a source
			// We can reuse isSource logic if we parse it as an expression,
			// or just regex check the value string for known sources.
			// Since it's likely a simple variable or expression, regex check is faster here.
			for _, srcPattern := range ds.sources {
				if srcPattern.MatchString(value) {
					ds.logger.VV("DOM: SINK DETECTED! Framework directive '%s' with source '%s'", directive, value)
					findings = append(findings, models.DOMFinding{
						Source:      value,
						Sink:        directive,
						Line:        "HTML Attribute",
						LineNumber:  0, // Hard to get line number with regex
						Confidence:  "HIGH",
						Description: fmt.Sprintf("Framework directive '%s' assigned with source '%s'", directive, value),
					})
				}
			}
		}
	}

	// NEW: Detect javascript: pseudo-protocol in href/src
	// Regex to find href/src with javascript:
	jsProtocolRegex := regexp.MustCompile(`\s(href|src)\s*=\s*["']\s*javascript:([^"']+)["']`)
	protocolMatches := jsProtocolRegex.FindAllStringSubmatch(body, -1)
	for _, match := range protocolMatches {
		if len(match) > 2 {
			attr := match[1]
			code := match[2]

			// Check for safe patterns (False Positive Reduction)
			cleanCode := strings.TrimSpace(code)
			cleanCode = strings.TrimSuffix(cleanCode, ";")

			safePatterns := []string{
				"void(0)",
				"void(0)", // duplicate but harmless
				"false",
				"true",
				"undefined",
				"", // empty
			}

			isSafe := false
			for _, safe := range safePatterns {
				if cleanCode == safe {
					isSafe = true
					break
				}
			}

			if isSafe {
				ds.logger.VV("DOM: Ignoring safe javascript: protocol usage: %s", code)
				continue
			}

			ds.logger.VV("DOM: Found javascript: protocol in %s: %s", attr, code)
			// Treat as sink
			findings = append(findings, models.DOMFinding{
				Source:      "javascript: pseudo-protocol",
				Sink:        attr,
				Line:        "HTML Attribute",
				LineNumber:  0,
				Confidence:  "HIGH",
				Description: fmt.Sprintf("Dangerous 'javascript:' protocol usage in '%s' attribute", attr),
			})
			// Also analyze the code inside
			jsCodeBlocks = append(jsCodeBlocks, code)
		}
	}

	// DOM Clobbering Detection moved to after JS analysis

	// Also treat the whole body as JS if it doesn't look like HTML (e.g. external script file)
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<body") && !strings.Contains(body, "<script") {
		jsCodeBlocks = append(jsCodeBlocks, body)
	}

	ds.logger.Detail("Found %d inline script blocks", len(jsCodeBlocks))

	ds.logger.Detail("Found %d inline script blocks", len(jsCodeBlocks))

	// Collect all global accesses from all scripts
	allGlobalAccesses := make(map[string]bool)

	for i, jsCode := range jsCodeBlocks {
		ds.logger.VV("Parsing JS block %d (%d bytes)", i+1, len(jsCode))
		// 2. Parse and Analyze JS (AST-based)
		// We pass the sources and sinks from the scanner configuration
		scriptFindings, globalAccesses := analysis.AnalyzeJS(jsCode, ds.sources, ds.sinks, ds.logger)
		findings = append(findings, scriptFindings...)

		// Merge global accesses
		for k, v := range globalAccesses {
			allGlobalAccesses[k] = v
		}
	}

	// NEW: DOM Clobbering Detection (Refined)
	// Look for id/name attributes that clash with global window properties
	// Common clobbering targets: window.test, window.config, etc.
	// We'll flag any id/name that looks like a variable name and is not standard HTML
	clobberRegexNew := regexp.MustCompile(`\s(id|name)\s*=\s*["']([a-zA-Z_$][a-zA-Z0-9_$]*)["']`)
	clobberMatchesNew := clobberRegexNew.FindAllStringSubmatch(body, -1)
	for _, match := range clobberMatchesNew {
		if len(match) > 2 {
			attr := match[1]
			val := match[2]

			// Check if this ID/Name is actually accessed as a global variable in JS
			isAccessed := allGlobalAccesses[val]

			// Fallback: Check sensitive list if not explicitly accessed (for robustness)
			sensitiveVars := []string{"config", "debug", "user", "auth", "admin", "role", "state"}
			isSensitive := false
			for _, sensitive := range sensitiveVars {
				if strings.Contains(strings.ToLower(val), sensitive) {
					isSensitive = true
					break
				}
			}

			if isAccessed {
				ds.logger.VV("DOM: CONFIRMED DOM Clobbering target: %s=%s (accessed in JS)", attr, val)
				findings = append(findings, models.DOMFinding{
					Source:      "HTML Attribute",
					Sink:        "Global Variable Clobbering",
					Line:        "HTML Attribute",
					LineNumber:  0,
					Confidence:  "HIGH",
					Description: fmt.Sprintf("DOM Clobbering: Element with %s='%s' shadows a global variable accessed in JS", attr, val),
				})
			} else if isSensitive {
				ds.logger.VV("DOM: Potential DOM Clobbering target (Sensitive Name): %s=%s", attr, val)
				findings = append(findings, models.DOMFinding{
					Source:      "HTML Attribute",
					Sink:        "Global Variable Clobbering",
					Line:        "HTML Attribute",
					LineNumber:  0,
					Confidence:  "MEDIUM",
					Description: fmt.Sprintf("Potential DOM Clobbering: Element with %s='%s' may shadow global variable", attr, val),
				})
			} else {
				ds.logger.VV("DOM: Ignoring unused ID/Name for clobbering: %s", val)
			}
		}
	}

	return findings
}

// ScanDeepDOM fetches external scripts and analyzes them concurrently.
// It recursively scans referenced scripts for DOM XSS vulnerabilities.
func (ds *DOMScanner) ScanDeepDOM(targetURL string, body string, client *http.Client) []models.DOMFinding {
	findings := ds.ScanDOM(body)

	// Extract script src
	scriptSrcRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptSrcRegex.FindAllStringSubmatch(body, -1)

	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Limit concurrency to avoid overwhelming the client/server
	sem := make(chan struct{}, 5)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		scriptURL := match[1]

		// Skip common 3rd party libs to save time/noise? (optional optimization)
		if strings.Contains(scriptURL, "jquery") || strings.Contains(scriptURL, "google-analytics") {
			continue
		}

		fullURL := resolveURL(targetURL, scriptURL)

		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			var scriptBody string

			// Check cache
			if cached, ok := ds.scriptCache.Load(url); ok {
				scriptBody = cached.(string)
			} else {
				// Fetch
				resp, err := client.Get(url)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					return
				}
				scriptBody = string(bodyBytes)

				// Store in cache
				ds.scriptCache.Store(url, scriptBody)
			}

			scriptFindings := ds.ScanDOM(scriptBody)

			mutex.Lock()
			for i := range scriptFindings {
				scriptFindings[i].Description += fmt.Sprintf(" (in %s)", url)
				findings = append(findings, scriptFindings[i])
			}
			mutex.Unlock()
		}(fullURL)
	}

	wg.Wait()
	return findings
}

func resolveURL(baseURL, scriptPath string) string {
	// Handle absolute URLs
	if strings.HasPrefix(scriptPath, "http") || strings.HasPrefix(scriptPath, "//") {
		if strings.HasPrefix(scriptPath, "//") {
			return "https:" + scriptPath
		}
		return scriptPath
	}

	// Handle relative URLs
	// Simple join. For robust handling use net/url
	// Assuming baseURL is the page URL

	// If scriptPath starts with /, it's relative to root
	// If not, it's relative to current path

	// Let's use net/url for safety
	base, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return scriptPath
	}

	u, err := base.URL.Parse(scriptPath)
	if err != nil {
		return scriptPath
	}

	return u.String()
}
