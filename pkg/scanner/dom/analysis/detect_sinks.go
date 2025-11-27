package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// HandleAssignExpression checks assignments for sinks and taint propagation.
func (ctx *AnalysisContext) HandleAssignExpression(n *ast.AssignExpression) {
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
				})
			}
		}
	}
}
