package analysis

import (
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// HandleCallExpression checks function calls for sinks and event listeners.
func (ctx *AnalysisContext) HandleCallExpression(n *ast.CallExpression, walker func(ast.Node)) {
	// Check for window.addEventListener('message', ...)
	if ctx.isAddEventListener(n) {
		ctx.handleMessageListener(n, walker)
		return
	}

	// Track tainted function calls
	if ident, ok := n.Callee.(*ast.Identifier); ok {
		funcName := string(ident.Name)
		for i, arg := range n.ArgumentList {
			if id, ok := arg.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(id.Name)); ok {
					if ctx.TaintedCalls[funcName] == nil {
						ctx.TaintedCalls[funcName] = make(map[int]string)
					}
					ctx.TaintedCalls[funcName][i] = src
					ctx.Logger.VV("DOM: Function '%s' called with tainted arg[%d] ('%s') from '%s'",
						funcName, i, string(id.Name), src)
				}
			}
		}
	}

	// Check Sinks
	ctx.checkCallSink(n)
}

func (ctx *AnalysisContext) isAddEventListener(n *ast.CallExpression) bool {
	if sel, ok := n.Callee.(*ast.DotExpression); ok {
		if string(sel.Identifier.Name) == "addEventListener" {
			return true
		}
	} else if ident, ok := n.Callee.(*ast.Identifier); ok {
		if string(ident.Name) == "addEventListener" {
			return true
		}
	}
	return false
}

func (ctx *AnalysisContext) handleMessageListener(n *ast.CallExpression, walker func(ast.Node)) {
	ctx.Logger.VV("DOM: Found addEventListener call")
	if len(n.ArgumentList) < 2 {
		return
	}

	// Check first arg is 'message'
	if arg0, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
		if arg0.Value == "message" {
			// Check second arg is a function
			var callbackParams *ast.ParameterList
			var callbackBody ast.ConciseBody

			switch cb := n.ArgumentList[1].(type) {
			case *ast.FunctionLiteral:
				callbackParams = cb.ParameterList
				callbackBody = cb.Body
			case *ast.ArrowFunctionLiteral:
				callbackParams = cb.ParameterList
				callbackBody = cb.Body
			}

			if callbackParams != nil && callbackBody != nil {
				if len(callbackParams.List) > 0 {
					// Found message listener!
					param := callbackParams.List[0]
					if paramIdent, ok := param.Target.(*ast.Identifier); ok {
						eventVar := string(paramIdent.Name)

						// Push new scope
						ctx.PushScope()

						// Taint event.data
						ctx.CurrentScope()[eventVar] = "event.data"
						ctx.Logger.VV("DOM: Found 'message' event listener. Tainting param '%s' as 'event.data'", eventVar)

						// Check origin validation
						originValidated := false
						checkOrigin := func(n ast.Node) {
							if ifStmt, ok := n.(*ast.IfStatement); ok {
								if ctx.checkOriginCondition(ifStmt.Test) {
									originValidated = true
									ctx.Logger.VV("DOM: Found origin validation check")
								}
							}
						}

						// Walk callback body
						if blockStmt, ok := callbackBody.(*ast.BlockStatement); ok {
							for _, stmt := range blockStmt.List {
								checkOrigin(stmt)
							}
							walker(blockStmt)
						} else if expr, ok := callbackBody.(ast.Expression); ok {
							walker(expr)
						}

						if !originValidated {
							ctx.Logger.VV("DOM: Missing origin validation in message listener")
							ctx.AddFinding(models.DOMFinding{
								Source:      "postMessage",
								Sink:        "Missing Origin Validation",
								Line:        "AST Node",
								LineNumber:  ctx.Program.File.Position(int(n.Idx0())).Line,
								Confidence:  "MEDIUM",
								Description: "Message event listener does not appear to validate event.origin",
							})
						}

						// Pop scope
						ctx.PopScope()
					}
				}
			}
		}
	}
}

func (ctx *AnalysisContext) checkOriginCondition(expr ast.Expression) bool {
	if bin, ok := expr.(*ast.BinaryExpression); ok {
		if strings.Contains(resolveDot(bin.Left), "origin") || strings.Contains(resolveDot(bin.Right), "origin") {
			return true
		}
	}
	if call, ok := expr.(*ast.CallExpression); ok {
		if strings.Contains(resolveDot(call.Callee), "origin") {
			return true
		}
		for _, arg := range call.ArgumentList {
			if strings.Contains(resolveDot(arg), "origin") {
				return true
			}
		}
	}
	return false
}
