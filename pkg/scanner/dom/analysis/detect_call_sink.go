package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func (ctx *AnalysisContext) checkCallSink(n *ast.CallExpression) {
	calleeName := resolveDot(n.Callee)
	ctx.Logger.VV("DOM: CallExpression callee resolved to: %s", calleeName)

	isSink := false
	for _, sink := range ctx.Sinks {
		cleanSinkPattern := strings.ReplaceAll(sink.String(), `\(`, "")
		cleanSinkPattern = strings.ReplaceAll(cleanSinkPattern, `=`, "")
		cleanSinkPattern = strings.TrimSpace(cleanSinkPattern)

		if re, err := regexp.Compile(cleanSinkPattern); err == nil {
			if re.MatchString(calleeName) {
				isSink = true
				break
			}
		}
	}

	// Special check for jQuery selector sink: $(...) or jQuery(...)
	if !isSink && (calleeName == "$" || calleeName == "jQuery") {
		// Only consider it a sink if the argument is tainted
		// This covers $(location.hash) or $('selector' + location.hash)
		isSink = true
	}

	if isSink {
		// FALSE POSITIVE REDUCTION: jQuery Sinks
		if strings.Contains(calleeName, ".html") || strings.Contains(calleeName, ".append") || strings.Contains(calleeName, ".prepend") {
			if len(n.ArgumentList) > 0 {
				if lit, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
					val := strings.TrimSpace(string(lit.Value))
					if (strings.HasPrefix(val, "#") || strings.HasPrefix(val, ".")) && !strings.HasPrefix(val, "<") {
						ctx.Logger.VV("DOM: Ignoring safe jQuery selector: %s", val)
						isSink = false
					}
				}
			}
		}

		// FALSE POSITIVE REDUCTION: document.write
		if strings.Contains(calleeName, "document.write") {
			if len(n.ArgumentList) > 0 {
				if lit, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
					ctx.Logger.VV("DOM: Ignoring static document.write: %s", lit.Value)
					isSink = false
				}
			}
		}

		// FALSE POSITIVE REDUCTION: importScripts (Web Workers)
		if strings.Contains(calleeName, "importScripts") {
			if len(n.ArgumentList) > 0 {
				if lit, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
					ctx.Logger.VV("DOM: Ignoring static importScripts: %s", lit.Value)
					isSink = false
				}
			}
		}
	}

	if isSink {
		// Infer context from sink name
		context := models.ContextUnknown
		lowerSink := strings.ToLower(calleeName)
		if strings.Contains(lowerSink, "innerhtml") || strings.Contains(lowerSink, "outerhtml") || strings.Contains(lowerSink, "document.write") || strings.Contains(lowerSink, "insertadjacenthtml") {
			context = models.ContextHTML
		} else if strings.Contains(lowerSink, "eval") || strings.Contains(lowerSink, "settimeout") || strings.Contains(lowerSink, "setinterval") || strings.Contains(lowerSink, "function") {
			context = models.ContextJSRaw
		} else if strings.Contains(lowerSink, "location") || strings.Contains(lowerSink, "href") || strings.Contains(lowerSink, "src") {
			context = models.ContextURL
		} else if strings.Contains(lowerSink, "html") || strings.Contains(lowerSink, "append") || strings.Contains(lowerSink, "prepend") {
			// jQuery sinks
			context = models.ContextHTML
		} else if calleeName == "$" || calleeName == "jQuery" {
			// jQuery selector sink
			context = models.ContextHTML
		}

		for _, arg := range n.ArgumentList {
			if src, isSrc := ctx.containsSource(arg); isSrc {
				lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
				ctx.Logger.VV("DOM: SINK DETECTED! %s() called with %s (line %d)", calleeName, src, lineNumber)
				ctx.AddFinding(models.DOMFinding{
					Source:      src,
					Sink:        calleeName,
					Line:        "AST Node",
					LineNumber:  lineNumber,
					Confidence:  "HIGH",
					Description: fmt.Sprintf("Direct flow: Source '%s' flows into Sink '%s'", src, calleeName),
					Evidence:    ctx.GetSnippet(n),
					Context:     context,
				})
			} else if id, ok := arg.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(id.Name)); ok {
					lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
					ctx.Logger.VV("DOM: SINK DETECTED! %s() called with tainted var '%s' from %s (line %d)", calleeName, string(id.Name), src, lineNumber)
					ctx.AddFinding(models.DOMFinding{
						Source:      src,
						Sink:        calleeName,
						Line:        "AST Node",
						LineNumber:  lineNumber,
						Confidence:  "HIGH",
						Description: fmt.Sprintf("Tainted variable '%s' (from %s) flows into Sink '%s'", string(id.Name), src, calleeName),
						Evidence:    ctx.GetSnippet(n),
						Context:     context,
					})
				}
			} else if dot, ok := arg.(*ast.DotExpression); ok {
				if id, ok := dot.Left.(*ast.Identifier); ok {
					if src, ok := ctx.LookupTaint(string(id.Name)); ok {
						lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
						ctx.Logger.VV("DOM: SINK DETECTED! %s() called with tainted var '%s' (property access) from %s (line %d)", calleeName, string(id.Name), src, lineNumber)
						ctx.AddFinding(models.DOMFinding{
							Source:      src,
							Sink:        calleeName,
							Line:        "AST Node",
							LineNumber:  lineNumber,
							Confidence:  "HIGH",
							Description: fmt.Sprintf("Tainted variable '%s' (property of %s) flows into Sink '%s'", string(dot.Identifier.Name), src, calleeName),
							Evidence:    ctx.GetSnippet(n),
							Context:     context,
						})
					}
				}
			}
		}
	}

	// Special handling for eval: check if it declares a variable with tainted data
	// e.g. eval('var x = ' + tainted)
	if calleeName == "eval" && len(n.ArgumentList) > 0 {
		if bin, ok := n.ArgumentList[0].(*ast.BinaryExpression); ok {
			if lit, ok := bin.Left.(*ast.StringLiteral); ok {
				// Check for "var name =" pattern
				val := string(lit.Value)
				if strings.HasPrefix(strings.TrimSpace(val), "var ") {
					parts := strings.Split(strings.TrimSpace(val), " ")
					if len(parts) >= 3 && parts[2] == "=" {
						varName := parts[1]
						// Check if Right is tainted
						if src, isSrc := ctx.containsSource(bin.Right); isSrc {
							ctx.Logger.VV("DOM: Tainting variable '%s' from eval declaration with source '%s'", varName, src)
							ctx.CurrentScope()[varName] = src
						} else if id, ok := bin.Right.(*ast.Identifier); ok {
							if src, ok := ctx.LookupTaint(string(id.Name)); ok {
								ctx.Logger.VV("DOM: Tainting variable '%s' from eval declaration with tainted var '%s'", varName, string(id.Name))
								ctx.CurrentScope()[varName] = src
							}
						} else if dot, ok := bin.Right.(*ast.DotExpression); ok {
							// Handle this.responseText or similar
							// For now, assume this.responseText is a source if we are in an XHR context?
							// Or if we just want to be aggressive:
							if strings.Contains(resolveDot(dot), "responseText") {
								// We assume responseText might contain reflected input if we are in this context
								// This is a heuristic.
								ctx.Logger.VV("DOM: Tainting variable '%s' from eval declaration with responseText", varName)
								ctx.CurrentScope()[varName] = "xhr.responseText"
							}
						}
					}
				}
			}
		}
	}
}
