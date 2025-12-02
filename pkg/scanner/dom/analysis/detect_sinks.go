package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// HandleAssignExpression checks assignments for sinks and taint propagation.
func (ctx *AnalysisContext) HandleAssignExpression(n *ast.AssignExpression, walker func(ast.Node)) {
	ctx.Logger.VV("DOM: Visiting AssignExpression")

	// 1. Taint Propagation (x = ...)
	if id, ok := n.Left.(*ast.Identifier); ok {
		// Check for Sanitization
		if isSanitized(n.Right) {
			ctx.Logger.VV("DOM: Assignment to '%s' is sanitized", string(id.Name))
			delete(ctx.CurrentScope(), string(id.Name))
		} else {
			if src, isSrc := ctx.isSource(n.Right); isSrc {
				// Check safe props/methods
				isSafe := false
				if dot, ok := n.Right.(*ast.DotExpression); ok {
					if isSafeProperty(string(dot.Identifier.Name)) {
						isSafe = true
					}
				} else if call, ok := n.Right.(*ast.CallExpression); ok {
					methodName := ""
					if dot, ok := call.Callee.(*ast.DotExpression); ok {
						methodName = string(dot.Identifier.Name)
					}
					if isSafeMethod(methodName) {
						isSafe = true
					}
				}

				if !isSafe {
					ctx.CurrentScope()[string(id.Name)] = src
				}
			} else if rightId, ok := n.Right.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(rightId.Name)); ok {
					ctx.CurrentScope()[string(id.Name)] = src
				}
			} else if call, ok := n.Right.(*ast.CallExpression); ok {
				// Check safe method
				methodName := ""
				if dot, ok := call.Callee.(*ast.DotExpression); ok {
					methodName = string(dot.Identifier.Name)
				}
				if isSafeMethod(methodName) {
					// Safe result
				} else {
					// Propagate from args
					for _, arg := range call.ArgumentList {
						if idArg, ok := arg.(*ast.Identifier); ok {
							if src, ok := ctx.LookupTaint(string(idArg.Name)); ok {
								ctx.CurrentScope()[string(id.Name)] = src
							}
						}
					}
				}
			}
		}
	}

	// Taint Propagation to 'this' in callbacks (e.g. xhr.onreadystatechange = function() { ... })
	if dot, ok := n.Left.(*ast.DotExpression); ok {
		if objIdent, ok := dot.Left.(*ast.Identifier); ok {
			if src, ok := ctx.LookupTaint(string(objIdent.Name)); ok {
				// We are assigning to a property of a tainted object
				// Check if RHS is a function
				var funcBody ast.ConciseBody
				switch fn := n.Right.(type) {
				case *ast.FunctionLiteral:
					funcBody = fn.Body
				}

				if funcBody != nil {
					// We found a function assigned to a tainted object's property
					// We need to taint 'this' inside that function
					// But we can't easily inject into the scope *before* walking the body because
					// the walker handles the scope push/pop for FunctionLiteral.
					// However, we can add a special "TaintedThis" map to the context or handle it in the Walker.
					// OR, simpler: we can manually walk the body with a new scope here?
					// No, that would duplicate walking.

					// Better approach:
					// Store this "pending taint" in the context and apply it when visiting the function.
					// But we don't have a map from FunctionLiteral to Taint.

					// Alternative:
					// Since we are in HandleAssignExpression, and the walker will recurse into n.Right (the function),
					// we can set a flag or add to a map keyed by the function node address? No, pointers change? No.
					// Let's use a map in Context: TaintedThisFunctions map[*ast.FunctionLiteral]string
					if fn, ok := n.Right.(*ast.FunctionLiteral); ok {
						if ctx.TaintedThisFunctions == nil {
							ctx.TaintedThisFunctions = make(map[*ast.FunctionLiteral]string)
						}
						ctx.TaintedThisFunctions[fn] = src
						ctx.Logger.VV("DOM: Tainting 'this' in callback assigned to '%s.%s' with source '%s' (Func Ptr: %p)", string(objIdent.Name), string(dot.Identifier.Name), src, fn)
					}
				}
			} else {
				// Object is NOT tainted yet. Register as pending callback.
				if fn, ok := n.Right.(*ast.FunctionLiteral); ok {
					objName := string(objIdent.Name)
					if ctx.PendingCallbacks[objName] == nil {
						ctx.PendingCallbacks[objName] = []*ast.FunctionLiteral{}
					}
					ctx.PendingCallbacks[objName] = append(ctx.PendingCallbacks[objName], fn)
					ctx.Logger.VV("DOM: Registered pending callback for '%s' (Func Ptr: %p)", objName, fn)
				}
			}
		}
	}

	// 2. Sink Detection (element.innerHTML = ...)
	// Check for Prototype Pollution first (delegated)
	if ctx.DetectPrototypePollution(n) {
		return
	}

	// Normal sink name resolution
	leftName := resolveDot(n.Left)

	// Check against Sinks
	ctx.Logger.VV("DOM: Checking assignment to '%s'", leftName)
	isSink := false
	for _, sink := range ctx.Sinks {
		// Clean regex
		cleanSinkPattern := strings.ReplaceAll(sink.String(), `\(`, "")
		cleanSinkPattern = strings.ReplaceAll(cleanSinkPattern, `=`, "")
		cleanSinkPattern = strings.TrimSpace(cleanSinkPattern)

		if re, err := regexp.Compile(cleanSinkPattern); err == nil {
			if re.MatchString(leftName) {
				isSink = true
				ctx.Logger.VV("DOM: '%s' matched sink pattern '%s'", leftName, cleanSinkPattern)
				break
			}
		}
	}

	// Special check for jQuery selector sink: $(...) or jQuery(...)
	// This is often used with location.hash in older jQuery versions
	if !isSink && (leftName == "$" || leftName == "jQuery") {
		// This is likely a CallExpression, but here we are in AssignExpression?
		// Wait, HandleAssignExpression handles assignments.
		// The vulnerability is $(window).on('hashchange', function(){ var post = $('section... ' + decodeURIComponent(window.location.hash) ...); })
		// This is a VariableDeclaration or just a CallExpression, not necessarily an Assignment to a sink.
		// We need to check HandleCallExpression too.
	}

	if isSink {
		// FALSE POSITIVE REDUCTION: Navigation Sinks
		if strings.Contains(leftName, "location") || strings.Contains(leftName, "href") {
			if ctx.isSafeNavigation(n) {
				return
			}
		}

		ctx.Logger.VV("DOM: Detected sink assignment to '%s'", leftName)
		ctx.reportSinkFlow(leftName, n.Right, n)
	}
}

func (ctx *AnalysisContext) isSafeNavigation(n *ast.AssignExpression) bool {
	// 1. Static String Literal
	if lit, ok := n.Right.(*ast.StringLiteral); ok {
		if !strings.Contains(strings.ToLower(string(lit.Value)), "javascript:") {
			ctx.Logger.VV("DOM: Ignoring safe navigation to static URL: %s", lit.Value)
			return true
		}
	}

	// 2. Self-assignment / Reload
	rightName := ""
	if id, ok := n.Right.(*ast.Identifier); ok {
		rightName = string(id.Name)
	} else if dot, ok := n.Right.(*ast.DotExpression); ok {
		rightName = resolveDot(dot)
	}

	if rightName == "location.href" || rightName == "window.location.href" ||
		rightName == "location.pathname" || rightName == "window.location.pathname" ||
		rightName == "location.reload" {
		ctx.Logger.VV("DOM: Ignoring safe reload/self-assignment: %s", rightName)
		return true
	}
	return false
}

func (ctx *AnalysisContext) reportSinkFlow(sinkName string, rhs ast.Expression, node ast.Node) {
	lineNumber := ctx.Program.File.Position(int(node.Idx0())).Line

	// Infer context from sink name
	context := models.ContextUnknown
	lowerSink := strings.ToLower(sinkName)
	if strings.Contains(lowerSink, "innerhtml") || strings.Contains(lowerSink, "outerhtml") || strings.Contains(lowerSink, "document.write") || strings.Contains(lowerSink, "insertadjacenthtml") {
		context = models.ContextHTML
	} else if strings.Contains(lowerSink, "eval") || strings.Contains(lowerSink, "settimeout") || strings.Contains(lowerSink, "setinterval") || strings.Contains(lowerSink, "function") {
		context = models.ContextJSRaw
	} else if strings.Contains(lowerSink, "location") || strings.Contains(lowerSink, "href") || strings.Contains(lowerSink, "src") {
		context = models.ContextURL
	} else if strings.Contains(lowerSink, "html") || strings.Contains(lowerSink, "append") || strings.Contains(lowerSink, "prepend") {
		// jQuery sinks
		context = models.ContextHTML
	}

	if src, isSrc := ctx.isSource(rhs); isSrc {
		ctx.Logger.VV("DOM: SINK DETECTED! %s = %s (line %d)", sinkName, src, lineNumber)
		ctx.AddFinding(models.DOMFinding{
			Source:      src,
			Sink:        sinkName,
			Line:        "AST Node",
			LineNumber:  lineNumber,
			Confidence:  "HIGH",
			Description: fmt.Sprintf("Direct flow: Source '%s' flows into Sink '%s'", src, sinkName),
			Evidence:    ctx.GetSnippet(node),
			Context:     context,
		})
	} else if id, ok := rhs.(*ast.Identifier); ok {
		if src, ok := ctx.LookupTaint(string(id.Name)); ok {
			ctx.Logger.VV("DOM: SINK DETECTED! %s = tainted var '%s' from %s (line %d)", sinkName, string(id.Name), src, lineNumber)
			ctx.AddFinding(models.DOMFinding{
				Source:      src,
				Sink:        sinkName,
				Line:        "AST Node",
				LineNumber:  lineNumber,
				Confidence:  "HIGH",
				Description: fmt.Sprintf("Tainted variable '%s' (from %s) flows into Sink '%s'", string(id.Name), src, sinkName),
				Evidence:    ctx.GetSnippet(node),
				Context:     context,
			})
		}
	} else if dot, ok := rhs.(*ast.DotExpression); ok {
		if id, ok := dot.Left.(*ast.Identifier); ok {
			if src, ok := ctx.LookupTaint(string(id.Name)); ok {
				ctx.Logger.VV("DOM: SINK DETECTED! %s = tainted var '%s' (property access) from %s (line %d)", sinkName, string(id.Name), src, lineNumber)
				ctx.AddFinding(models.DOMFinding{
					Source:      src,
					Sink:        sinkName,
					Line:        "AST Node",
					LineNumber:  lineNumber,
					Confidence:  "HIGH",
					Description: fmt.Sprintf("Tainted variable '%s' (property of %s) flows into Sink '%s'", string(dot.Identifier.Name), src, sinkName),
					Evidence:    ctx.GetSnippet(node),
					Context:     context,
				})
			}
		}
	}
}
