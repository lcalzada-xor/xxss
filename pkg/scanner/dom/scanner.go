package dom

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/html"

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

	// Parse HTML
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		// Fallback to treating as raw JS if HTML parsing fails (e.g. it's a JS file)
		ds.logger.VV("HTML parsing failed, treating as raw JS: %v", err)
		return ds.analyzeJSContent(body)
	}

	var jsCodeBlocks []string
	var eventHandlers []string

	// Traversal function
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// 1. Extract Scripts
			if n.Data == "script" {
				// Extract content
				if n.FirstChild != nil {
					jsCodeBlocks = append(jsCodeBlocks, n.FirstChild.Data)
				}
			}

			// Check attributes
			for _, attr := range n.Attr {
				// 2. Extract Event Handlers
				if strings.HasPrefix(strings.ToLower(attr.Key), "on") {
					ds.logger.VV("DOM: Found event handler '%s' with code: %s", attr.Key, attr.Val)
					jsCodeBlocks = append(jsCodeBlocks, attr.Val)
					eventHandlers = append(eventHandlers, attr.Val)
				}

				// 3. Extract Framework Directives
				if attr.Key == "v-html" || attr.Key == "ng-bind-html" {
					ds.logger.VV("DOM: Found framework directive '%s' with value: %s", attr.Key, attr.Val)
					// Check if value is a source
					for _, srcPattern := range ds.sources {
						if srcPattern.MatchString(attr.Val) {
							ds.logger.VV("DOM: SINK DETECTED! Framework directive '%s' with source '%s'", attr.Key, attr.Val)
							findings = append(findings, models.DOMFinding{
								Evidence:         fmt.Sprintf(` %s="%s"`, attr.Key, attr.Val),
								Source:           attr.Val,
								Sink:             attr.Key,
								Line:             "HTML Attribute",
								LineNumber:       0,
								Confidence:       "HIGH",
								Description:      fmt.Sprintf("Framework directive '%s' assigned with source '%s'", attr.Key, attr.Val),
								Context:          models.ContextAttribute,
								SuggestedPayload: GenerateDOMPayload(attr.Key, models.ContextAttribute, nil),
							})
						}
					}
				}

				// 4. Detect javascript: pseudo-protocol
				if (attr.Key == "href" || attr.Key == "src") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(attr.Val)), "javascript:") {
					code := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(attr.Val)), "javascript:")

					// Check for safe patterns
					cleanCode := strings.TrimSpace(code)
					cleanCode = strings.TrimSuffix(cleanCode, ";")
					safePatterns := []string{"void(0)", "false", "true", "undefined", ""}
					isSafe := false
					for _, safe := range safePatterns {
						if cleanCode == safe {
							isSafe = true
							break
						}
					}

					if !isSafe {
						ds.logger.VV("DOM: Found javascript: protocol in %s: %s", attr.Key, code)
						findings = append(findings, models.DOMFinding{
							Evidence:         fmt.Sprintf(` %s="%s"`, attr.Key, attr.Val),
							Source:           "javascript: pseudo-protocol",
							Sink:             attr.Key,
							Line:             "HTML Attribute",
							LineNumber:       0,
							Confidence:       "HIGH",
							Description:      fmt.Sprintf("Dangerous 'javascript:' protocol usage in '%s' attribute", attr.Key),
							Context:          models.ContextAttribute,
							SuggestedPayload: "javascript:alert(1)",
						})
						jsCodeBlocks = append(jsCodeBlocks, code)
					}
				}

				// 5. DOM Clobbering (Basic Check)
				if attr.Key == "id" || attr.Key == "name" {
					// We collect these to check against global accesses later
					// For now, we just store them?
					// The original logic checked against global accesses.
					// We need to pass these to the analyzer or check after.
					// Let's store them in a map for now.
					// But we need to know if they are accessed.
					// We'll do a second pass or check after JS analysis.
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	// Also check if the body itself is JS (no html tags found or just text)
	// If doc only has text nodes or we found no scripts/html structure, might be raw JS.
	// But html.Parse usually creates a structure even for raw text.
	// If we found no scripts and the body doesn't look like HTML, treat as JS.
	if len(jsCodeBlocks) == 0 && !strings.Contains(body, "<html") {
		jsCodeBlocks = append(jsCodeBlocks, body)
	}

	ds.logger.Detail("Found %d inline script blocks", len(jsCodeBlocks))

	// Analyze JS Blocks
	allGlobalAccesses := make(map[string]bool)
	for i, jsCode := range jsCodeBlocks {
		ds.logger.VV("Parsing JS block %d (%d bytes)", i+1, len(jsCode))
		scriptFindings, globalAccesses := analysis.AnalyzeJS(jsCode, ds.sources, ds.sinks, ds.logger)

		for i := range scriptFindings {
			ctx := scriptFindings[i].Context
			if ctx == "" {
				ctx = models.ContextUnknown
			}
			scriptFindings[i].SuggestedPayload = GenerateDOMPayload(scriptFindings[i].Sink, ctx, nil)
		}
		findings = append(findings, scriptFindings...)

		for k, v := range globalAccesses {
			allGlobalAccesses[k] = v
		}
	}

	// DOM Clobbering Verification
	// We need to traverse again or store the clobbering candidates.
	// Let's traverse again for clobbering candidates now that we have global accesses.
	var clobberCheck func(*html.Node)
	clobberCheck = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				if attr.Key == "id" || attr.Key == "name" {
					val := attr.Val
					if allGlobalAccesses[val] {
						ds.logger.VV("DOM: CONFIRMED DOM Clobbering target: %s=%s (accessed in JS)", attr.Key, val)
						findings = append(findings, models.DOMFinding{
							Evidence:         fmt.Sprintf(` %s="%s"`, attr.Key, val),
							Source:           "HTML Attribute",
							Sink:             "Global Variable Clobbering",
							Line:             "HTML Attribute",
							LineNumber:       0,
							Confidence:       "HIGH",
							Description:      fmt.Sprintf("DOM Clobbering: Element with %s='%s' shadows a global variable accessed in JS", attr.Key, val),
							SuggestedPayload: fmt.Sprintf("<a id=%s href=javascript:alert(1)>", val),
						})
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			clobberCheck(c)
		}
	}
	clobberCheck(doc)

	return deduplicateFindings(findings)
}

// analyzeJSContent is a helper for raw JS files
func (ds *DOMScanner) analyzeJSContent(jsCode string) []models.DOMFinding {
	scriptFindings, _ := analysis.AnalyzeJS(jsCode, ds.sources, ds.sinks, ds.logger)
	for i := range scriptFindings {
		ctx := scriptFindings[i].Context
		if ctx == "" {
			ctx = models.ContextUnknown
		}
		scriptFindings[i].SuggestedPayload = GenerateDOMPayload(scriptFindings[i].Sink, ctx, nil)
	}
	return deduplicateFindings(scriptFindings)
}

// deduplicateFindings removes duplicate findings based on Source, Sink, and Description
func deduplicateFindings(findings []models.DOMFinding) []models.DOMFinding {
	unique := make([]models.DOMFinding, 0, len(findings))
	seen := make(map[string]bool)

	for _, f := range findings {
		// Create a unique key for the finding
		key := fmt.Sprintf("%s|%s|%s", f.Source, f.Sink, f.Description)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
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
	return deduplicateFindings(findings)
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
