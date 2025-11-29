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

	// XHR Response Tainting
	// If xhr.open(method, tainted_url) is called, taint the xhr object (and thus xhr.responseText)
	if dot, ok := n.Callee.(*ast.DotExpression); ok {
		if string(dot.Identifier.Name) == "open" {
			if len(n.ArgumentList) >= 2 {
				// Check if 2nd arg (URL) is tainted
				if src, isSrc := ctx.containsSource(n.ArgumentList[1]); isSrc {
					// Taint the object (xhr)
					if objIdent, ok := dot.Left.(*ast.Identifier); ok {
						objName := string(objIdent.Name)
						ctx.CurrentScope()[objName] = src
						ctx.Logger.VV("DOM: XHR '%s' tainted via open() with tainted URL '%s'", objName, src)

						// Process Pending Callbacks
						if callbacks, ok := ctx.PendingCallbacks[objName]; ok {
							ctx.Logger.VV("DOM: Processing %d pending callbacks for '%s'", len(callbacks), objName)
							for _, cb := range callbacks {
								// Add to TaintedThisFunctions
								if ctx.TaintedThisFunctions == nil {
									ctx.TaintedThisFunctions = make(map[*ast.FunctionLiteral]string)
								}
								ctx.TaintedThisFunctions[cb] = src
								ctx.Logger.VV("DOM: Tainting 'this' in pending callback with source '%s'", src)

								// Re-walk the callback
								// We must walk the FunctionLiteral itself so that Walker can push the scope
								// and apply the 'this' taint we just added to TaintedThisFunctions.
								walker(cb)
							}
							// Clear pending callbacks to avoid re-processing
							delete(ctx.PendingCallbacks, objName)
						}
					}
				}
			}
		} else if string(dot.Identifier.Name) == "then" {
			// Promise Chaining: obj.then(callback)
			// Check if 'obj' is tainted (either variable or expression taint)
			taintedSrc := ""
			if leftIdent, ok := dot.Left.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(leftIdent.Name)); ok {
					taintedSrc = src
				}
			} else if src, ok := ctx.ExpressionTaint[dot.Left]; ok {
				taintedSrc = src
			}

			if taintedSrc != "" {
				// Taint the first argument of the callback
				if len(n.ArgumentList) > 0 {
					var callbackParams *ast.ParameterList

					switch cb := n.ArgumentList[0].(type) {
					case *ast.FunctionLiteral:
						callbackParams = cb.ParameterList
					case *ast.ArrowFunctionLiteral:
						callbackParams = cb.ParameterList
					}

					if callbackParams != nil && len(callbackParams.List) > 0 {
						param := callbackParams.List[0]
						if paramIdent, ok := param.Target.(*ast.Identifier); ok {
							paramName := string(paramIdent.Name)
							// We need to taint this parameter in the callback's scope.
							// Since we can't easily inject into the future scope walk,
							// we'll use a similar approach to TaintedThisFunctions but for parameters.
							// OR, simpler: since we are in HandleCallExpression, the walker will visit args next.
							// But the walker creates a NEW scope for the function.
							// We can use a map: TaintedCallbackParams map[*ast.FunctionLiteral/Arrow]map[string]string
							// Let's add TaintedCallbackParams to Context.
							// Actually, for now, let's just use TaintedThisFunctions logic but adapted?
							// No, 'this' is special. Params are normal vars.

							// Let's add TaintedFunctionParams to AnalysisContext.
							// map[ast.Node]map[string]string  (Node is the FunctionLiteral/Arrow)
							if cbNode, ok := n.ArgumentList[0].(ast.Node); ok {
								ctx.AddTaintedParam(cbNode, paramName, taintedSrc)
								ctx.Logger.VV("DOM: Tainting param '%s' in .then() callback from source '%s'", paramName, taintedSrc)
								// Re-walk the callback to apply the new taint
								walker(cbNode)
							}
						}
					}

					// Also, the return value of .then() should be tainted if the callback returns something tainted.
					// But that requires analyzing the callback return.
					// For now, let's assume if the promise is tainted, the result of .then is also tainted (conservative).
					ctx.ExpressionTaint[n] = taintedSrc
				}
			}
		} else if string(dot.Identifier.Name) == "text" || string(dot.Identifier.Name) == "json" {
			// response.text(), response.json()
			// Check if 'response' is tainted
			taintedSrc := ""
			if leftIdent, ok := dot.Left.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(leftIdent.Name)); ok {
					taintedSrc = src
				}
			} else if src, ok := ctx.ExpressionTaint[dot.Left]; ok {
				taintedSrc = src
			}

			if taintedSrc != "" {
				ctx.ExpressionTaint[n] = taintedSrc
				ctx.Logger.VV("DOM: Tainted result of %s() from source '%s'", string(dot.Identifier.Name), taintedSrc)
			}
		}
	} else if ident, ok := n.Callee.(*ast.Identifier); ok {
		if string(ident.Name) == "fetch" {
			if len(n.ArgumentList) > 0 {
				if src, isSrc := ctx.containsSource(n.ArgumentList[0]); isSrc {
					ctx.ExpressionTaint[n] = src
					ctx.Logger.VV("DOM: Tainted fetch() result from source '%s'", src)
				}
			}
		}
	}
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
