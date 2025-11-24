package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"sync"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/lcalzada-xor/xxss/pkg/models"
)

// DOMScanner handles static analysis for DOM XSS
type DOMScanner struct {
	sources     []*regexp.Regexp
	sinks       []*regexp.Regexp
	scriptCache sync.Map // map[string]string (URL -> Content)
}

// NewDOMScanner creates a new DOM scanner with compiled regexes
func NewDOMScanner() *DOMScanner {
	// Sources: inputs controlled by attacker
	sourcePatterns := []string{
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
	}

	// Sinks: dangerous execution points
	sinkPatterns := []string{
		// Execution
		`eval\(`,
		`setTimeout\(`,
		`setInterval\(`,
		`setImmediate\(`,
		`execScript\(`,
		`Function\(`,
		// HTML Injection
		`innerHTML`,
		`outerHTML`,
		`insertAdjacentHTML`,
		`document\.write\(`,
		`document\.writeln\(`,
		// Navigation / Open Redirect
		`location\.href\s*=`,
		`location\.replace\(`,
		`location\.assign\(`,
		`navigation\.navigate\(`, // Modern Navigation API
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
	}

	ds := &DOMScanner{}

	for _, p := range sourcePatterns {
		ds.sources = append(ds.sources, regexp.MustCompile(p))
	}

	for _, p := range sinkPatterns {
		ds.sinks = append(ds.sinks, regexp.MustCompile(p))
	}

	return ds
}

// ScanDOM analyzes the HTML/JS content for DOM XSS patterns using AST analysis
func (ds *DOMScanner) ScanDOM(body string) []models.DOMFinding {
	var findings []models.DOMFinding

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

	// Also treat the whole body as JS if it doesn't look like HTML (e.g. external script file)
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<body") && !strings.Contains(body, "<script") {
		jsCodeBlocks = append(jsCodeBlocks, body)
	}

	for _, jsCode := range jsCodeBlocks {
		findings = append(findings, ds.analyzeJS(jsCode)...)
	}

	return findings
}

func (ds *DOMScanner) analyzeJS(jsCode string) []models.DOMFinding {
	var findings []models.DOMFinding

	// Parse JS
	program, err := parser.ParseFile(nil, "", jsCode, 0)
	if err != nil {
		// If parsing fails, fall back to regex or just skip?
		// For now, let's skip but maybe log?
		return findings
	}

	// Taint Analysis State
	// Map of variable name -> Taint Source (if tainted)
	// We need scope handling. A simple stack of maps.
	scopes := []map[string]string{make(map[string]string)} // Global scope

	// Helper to get current scope
	currentScope := func() map[string]string {
		return scopes[len(scopes)-1]
	}

	// Helper to lookup variable in scope chain
	lookupTaint := func(name string) (string, bool) {
		for i := len(scopes) - 1; i >= 0; i-- {
			if val, ok := scopes[i][name]; ok {
				return val, true
			}
		}
		return "", false
	}

	// Forward declaration
	var recursiveWalk func(node ast.Node)

	// Helper to resolve DotExpression to string
	var resolveDot func(node ast.Node) string
	resolveDot = func(node ast.Node) string {
		if id, ok := node.(*ast.Identifier); ok {
			return string(id.Name)
		}
		if dot, ok := node.(*ast.DotExpression); ok {
			left := resolveDot(dot.Left)
			if left != "" {
				return left + "." + string(dot.Identifier.Name)
			}
		}
		return ""
	}

	// Helper to check if a node is a Source
	isSource := func(node ast.Node) (string, bool) {
		// Handle DotExpression (obj.prop, obj.prop.sub)
		if dot, ok := node.(*ast.DotExpression); ok {
			expr := resolveDot(dot)
			if expr != "" {
				for _, src := range ds.sources {
					if src.MatchString(expr) {
						return expr, true
					}
				}
			}
		}
		// Handle CallExpression (obj.method()) - e.g. localStorage.getItem()
		if call, ok := node.(*ast.CallExpression); ok {
			if dot, ok := call.Callee.(*ast.DotExpression); ok {
				expr := resolveDot(dot)
				if expr != "" {
					for _, src := range ds.sources {
						if src.MatchString(expr) {
							return expr, true
						}
					}
				}
			}
		}
		return "", false
	}

	// Walker function
	var walk func(node ast.Node)
	walk = func(node ast.Node) {
		if node == nil {
			return
		}

		switch n := node.(type) {
		case *ast.FunctionLiteral:
			// Push new scope
			scopes = append(scopes, make(map[string]string))
			// Walk body
			recursiveWalk(n.Body)
			// Pop scope
			scopes = scopes[:len(scopes)-1]
			return // Don't continue default walk

		case *ast.FunctionDeclaration:
			// Push new scope
			scopes = append(scopes, make(map[string]string))
			// Walk body (FunctionDeclaration has a Function field which contains the body)
			recursiveWalk(n.Function.Body)
			// Pop scope
			scopes = scopes[:len(scopes)-1]
			return // Don't continue default walk

		case *ast.Binding:
			decl := n
			if target, ok := decl.Target.(*ast.Identifier); ok {
				if decl.Initializer != nil {
					// Check if Init is a source or tainted
					source, isSrc := isSource(decl.Initializer)
					if isSrc {
						currentScope()[string(target.Name)] = source
					} else if id, ok := decl.Initializer.(*ast.Identifier); ok {
						// var x = y;
						if taintedSrc, ok := lookupTaint(string(id.Name)); ok {
							currentScope()[string(target.Name)] = taintedSrc
						}
					} else if call, ok := decl.Initializer.(*ast.CallExpression); ok {
						// Check for sanitization
						isSanitizer := false
						if dot, ok := call.Callee.(*ast.DotExpression); ok {
							if obj, ok := dot.Left.(*ast.Identifier); ok && string(obj.Name) == "DOMPurify" {
								isSanitizer = true
							}
						}

						if !isSanitizer {
							// Check if arguments are tainted (simplified propagation)
							for _, arg := range call.ArgumentList {
								if id, ok := arg.(*ast.Identifier); ok {
									if src, ok := lookupTaint(string(id.Name)); ok {
										if targetId, ok := decl.Target.(*ast.Identifier); ok {
											currentScope()[string(targetId.Name)] = src
										}
									}
								}
							}
						}
					} else if bin, ok := decl.Initializer.(*ast.BinaryExpression); ok {
						// var x = "safe" + tainted;
						// Check left and right
						tainted := false
						src := ""

						checkNode := func(e ast.Expression) {
							if id, ok := e.(*ast.Identifier); ok {
								if s, ok := lookupTaint(string(id.Name)); ok {
									tainted = true
									src = s
								}
							} else if s, ok := isSource(e); ok {
								tainted = true
								src = s
							}
						}

						checkNode(bin.Left)
						checkNode(bin.Right)

						if tainted {
							if targetId, ok := decl.Target.(*ast.Identifier); ok {
								currentScope()[string(targetId.Name)] = src
							}
						}
					}
				}
			}

		case *ast.AssignExpression:
			// 1. Taint Propagation (x = ...)
			if id, ok := n.Left.(*ast.Identifier); ok {
				if src, isSrc := isSource(n.Right); isSrc {
					currentScope()[string(id.Name)] = src
				} else if rhsId, ok := n.Right.(*ast.Identifier); ok {
					if src, ok := lookupTaint(string(rhsId.Name)); ok {
						currentScope()[string(id.Name)] = src
					}
				}
			}

			// 2. Sink Detection (element.innerHTML = ...)
			// Reconstruct Left side
			leftName := ""
			isProtoPollution := false

			// Helper to check for proto pollution in a DotExpression chain
			var checkProto func(node ast.Node) bool
			checkProto = func(node ast.Node) bool {
				if dot, ok := node.(*ast.DotExpression); ok {
					prop := string(dot.Identifier.Name)
					if prop == "__proto__" || prop == "prototype" || prop == "constructor" {
						return true
					}
					return checkProto(dot.Left)
				}
				if bracket, ok := node.(*ast.BracketExpression); ok {
					if lit, ok := bracket.Member.(*ast.StringLiteral); ok {
						prop := string(lit.Value)
						if prop == "__proto__" || prop == "prototype" || prop == "constructor" {
							return true
						}
					}
					return checkProto(bracket.Left)
				}
				return false
			}

			if checkProto(n.Left) {
				isProtoPollution = true
				leftName = "PROTOTYPE_POLLUTION"
			} else {
				// Normal sink name resolution
				leftName = resolveDot(n.Left)
			}

			if isProtoPollution {
				lineNumber := program.File.Position(int(n.Idx0())).Line
				findings = append(findings, models.DOMFinding{
					Source:      "Assignment",
					Sink:        "Prototype Pollution",
					Line:        "AST Node",
					LineNumber:  lineNumber,
					Confidence:  "HIGH",
					Description: fmt.Sprintf("Potential Prototype Pollution: Assignment to sensitive property on line %d", lineNumber),
				})
			}

			// Check against Sinks
			isSink := false
			for _, sink := range ds.sinks {
				// Clean regex: remove \( and =
				// This is to allow matching patterns like `innerHTML` against `element.innerHTML`
				// and `location.href` against `location.href = ...`
				cleanSinkPattern := strings.ReplaceAll(sink.String(), `\(`, "")
				cleanSinkPattern = strings.ReplaceAll(cleanSinkPattern, `\`, "")
				cleanSinkPattern = strings.ReplaceAll(cleanSinkPattern, `=`, "")
				cleanSinkPattern = strings.TrimSpace(cleanSinkPattern)

				// Recompile for matching against the leftName string
				// This is a bit inefficient, but ensures correct matching for property sinks
				// A better approach might be to categorize sinks (call vs assign)
				if re, err := regexp.Compile(cleanSinkPattern); err == nil {
					if re.MatchString(leftName) {
						isSink = true
						break
					}
				}
			}

			if isSink {
				// Check Right side for taint
				if src, isSrc := isSource(n.Right); isSrc {
					lineNumber := program.File.Position(int(n.Idx0())).Line
					findings = append(findings, models.DOMFinding{
						Source:      src,
						Sink:        leftName,
						Line:        "AST Node",
						LineNumber:  lineNumber,
						Confidence:  "HIGH",
						Description: fmt.Sprintf("Direct flow: Source '%s' flows into Sink '%s'", src, leftName),
					})
				} else if id, ok := n.Right.(*ast.Identifier); ok {
					if src, ok := lookupTaint(string(id.Name)); ok {
						lineNumber := program.File.Position(int(n.Idx0())).Line
						findings = append(findings, models.DOMFinding{
							Source:      src,
							Sink:        leftName,
							Line:        "AST Node",
							LineNumber:  lineNumber,
							Confidence:  "HIGH",
							Description: fmt.Sprintf("Tainted variable '%s' (from %s) flows into Sink '%s'", string(id.Name), src, leftName),
						})
					}
				}
			}

		case *ast.CallExpression:
			// Check if it's a sink
			calleeName := ""
			if id, ok := n.Callee.(*ast.Identifier); ok {
				calleeName = string(id.Name)
			} else if dot, ok := n.Callee.(*ast.DotExpression); ok {
				objName := ""
				propName := ""
				if id, ok := dot.Left.(*ast.Identifier); ok {
					objName = string(id.Name)
				}
				propName = string(dot.Identifier.Name)
				calleeName = fmt.Sprintf("%s.%s", objName, propName)
			}

			isSink := false
			for _, sink := range ds.sinks {
				// Clean regex: remove \( and =
				cleanSinkPattern := strings.ReplaceAll(sink.String(), `\(`, "")
				cleanSinkPattern = strings.ReplaceAll(cleanSinkPattern, `\`, "")
				cleanSinkPattern = strings.ReplaceAll(cleanSinkPattern, `=`, "")
				cleanSinkPattern = strings.TrimSpace(cleanSinkPattern)

				// Recompile for matching
				if re, err := regexp.Compile(cleanSinkPattern); err == nil {
					if re.MatchString(calleeName) {
						isSink = true
						break
					}
				}
			}

			if isSink {
				for _, arg := range n.ArgumentList {
					if src, isSrc := isSource(arg); isSrc {
						lineNumber := program.File.Position(int(n.Idx0())).Line
						findings = append(findings, models.DOMFinding{
							Source:      src,
							Sink:        calleeName,
							Line:        "AST Node",
							LineNumber:  lineNumber,
							Confidence:  "HIGH",
							Description: fmt.Sprintf("Direct flow: Source '%s' flows into Sink '%s'", src, calleeName),
						})
					} else if id, ok := arg.(*ast.Identifier); ok {
						if src, ok := lookupTaint(string(id.Name)); ok {
							lineNumber := program.File.Position(int(n.Idx0())).Line
							findings = append(findings, models.DOMFinding{
								Source:      src,
								Sink:        calleeName,
								Line:        "AST Node",
								LineNumber:  lineNumber,
								Confidence:  "HIGH",
								Description: fmt.Sprintf("Tainted variable '%s' (from %s) flows into Sink '%s'", string(id.Name), src, calleeName),
							})
						}
					}
				}
			}
		}

		// Continue walking children
		// We need to manually walk children for generic nodes if we want to be thorough
		// But for this prototype, we rely on specific handling or generic recursion?
		// goja/parser doesn't have a generic Walk?
		// Actually it doesn't seem to have a generic Inspect/Walk like go/ast.
		// We have to implement it or just handle specific nodes we care about.
		// For now, let's just handle the top level statements and recurse into Blocks/Functions.

		// Wait, goja/parser returns *ast.Program which has Body []ast.Statement.
		// We need a recursive walker.
	}

	// Simple recursive walker since goja/parser might not provide one
	recursiveWalk = func(node ast.Node) {
		if node == nil {
			return
		}
		walk(node)

		// Manually recurse for common container nodes
		switch n := node.(type) {
		case *ast.Program:
			for _, stmt := range n.Body {
				recursiveWalk(stmt)
			}
		case *ast.BlockStatement:
			for _, stmt := range n.List {
				recursiveWalk(stmt)
			}
		case *ast.ExpressionStatement:
			recursiveWalk(n.Expression)
		case *ast.IfStatement:
			recursiveWalk(n.Test)
			recursiveWalk(n.Consequent)
			recursiveWalk(n.Alternate)
		case *ast.ReturnStatement:
			recursiveWalk(n.Argument)
			// ... add more as needed
		case *ast.FunctionDeclaration:
			// Already handled in walk, but need to recurse if we didn't walk body there?
			// We handled it in walk switch case.
		case *ast.FunctionLiteral:
			// Handled in walk
		case *ast.VariableStatement:
			for _, expr := range n.List {
				recursiveWalk(expr)
			}
		}
	}

	recursiveWalk(program)

	return findings
}

// ScanDeepDOM fetches external scripts and analyzes them concurrently
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
