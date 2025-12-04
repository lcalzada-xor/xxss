package analysis

import (
	"fmt"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v3/pkg/models"
)

// Walk traverses the AST and analyzes nodes.
func (ctx *AnalysisContext) Walk(node ast.Node) {
	if node == nil {
		return
	}
	ctx.Logger.VV("DOM: Visiting node type: %T", node)

	// Recursive walker helper
	var recursiveWalk func(n ast.Node)
	recursiveWalk = func(n ast.Node) {
		ctx.Walk(n)
	}

	switch n := node.(type) {
	case *ast.ArrowFunctionLiteral:
		ctx.PushScope()
		if params, ok := ctx.TaintedFunctionParams[n]; ok {
			for param, src := range params {
				ctx.CurrentScope()[param] = src
				ctx.Logger.VV("DOM: Tainted param '%s' in arrow function scope with source '%s'", param, src)
			}
		}
		recursiveWalk(n.Body)
		ctx.PopScope()
		return

	case *ast.FunctionLiteral:
		ctx.PushScope()
		if taint, ok := ctx.TaintedThisFunctions[n]; ok {
			ctx.CurrentScope()["this"] = taint
			ctx.Logger.VV("DOM: Tainted 'this' in function scope with source '%s'", taint)
		}
		if params, ok := ctx.TaintedFunctionParams[n]; ok {
			for param, src := range params {
				ctx.CurrentScope()[param] = src
				ctx.Logger.VV("DOM: Tainted param '%s' in function scope with source '%s'", param, src)
			}
		}
		recursiveWalk(n.Body)
		ctx.PopScope()
		return

	case *ast.FunctionDeclaration:
		funcName := string(n.Function.Name.Name)
		ctx.PushScope()

		// Interprocedural taint
		if taintedArgs, ok := ctx.TaintedCalls[funcName]; ok {
			for argIdx, taintSrc := range taintedArgs {
				if argIdx < len(n.Function.ParameterList.List) {
					param := n.Function.ParameterList.List[argIdx]
					if paramIdent, ok := param.Target.(*ast.Identifier); ok {
						ctx.CurrentScope()[string(paramIdent.Name)] = taintSrc
						ctx.Logger.VV("DOM: Parameter '%s' of function '%s' tainted from '%s'",
							string(paramIdent.Name), funcName, taintSrc)
					}
				}
			}
		}

		recursiveWalk(n.Function.Body)
		ctx.PopScope()
		return

	case *ast.Binding:
		ctx.HandleBinding(n)
		if n.Initializer != nil {
			recursiveWalk(n.Initializer)
		}

	case *ast.AssignExpression:
		ctx.HandleAssignExpression(n, recursiveWalk)
		// Recurse
		recursiveWalk(n.Left)
		recursiveWalk(n.Right)

	case *ast.CallExpression:
		// Recurse args first to resolve taint
		recursiveWalk(n.Callee)
		for _, arg := range n.ArgumentList {
			recursiveWalk(arg)
		}
		ctx.HandleCallExpression(n, recursiveWalk)

	case *ast.ObjectLiteral:
		// Handle React dangerouslySetInnerHTML
		for _, prop := range n.Value {
			if keyed, ok := prop.(*ast.PropertyKeyed); ok {
				// Get property name - can be Identifier or StringLiteral
				var propName string
				if id, ok := keyed.Key.(*ast.Identifier); ok {
					propName = string(id.Name)
				} else if str, ok := keyed.Key.(*ast.StringLiteral); ok {
					propName = string(str.Value)
				}

				if propName == "dangerouslySetInnerHTML" {
					// Check if value is an object with __html property
					if objLit, ok := keyed.Value.(*ast.ObjectLiteral); ok {
						for _, innerProp := range objLit.Value {
							if innerKeyed, ok := innerProp.(*ast.PropertyKeyed); ok {
								var innerPropName string
								if innerId, ok := innerKeyed.Key.(*ast.Identifier); ok {
									innerPropName = string(innerId.Name)
								} else if innerStr, ok := innerKeyed.Key.(*ast.StringLiteral); ok {
									innerPropName = string(innerStr.Value)
								}

								if innerPropName == "__html" {
									// Check if __html value is tainted
									if src, isSrc := ctx.isSource(innerKeyed.Value); isSrc {
										lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
										ctx.AddFinding(models.DOMFinding{
											Source:      src,
											Sink:        "dangerouslySetInnerHTML",
											Line:        "AST Node",
											LineNumber:  lineNumber,
											Confidence:  "HIGH",
											Description: fmt.Sprintf("React dangerouslySetInnerHTML with tainted value from '%s'", src),
											Evidence:    ctx.GetSnippet(n),
										})
									} else if id, ok := innerKeyed.Value.(*ast.Identifier); ok {
										if src, ok := ctx.LookupTaint(string(id.Name)); ok {
											lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
											ctx.AddFinding(models.DOMFinding{
												Source:      src,
												Sink:        "dangerouslySetInnerHTML",
												Line:        "AST Node",
												LineNumber:  lineNumber,
												Confidence:  "HIGH",
												Description: fmt.Sprintf("React dangerouslySetInnerHTML with tainted variable '%s' from '%s'", string(id.Name), src),
												Evidence:    ctx.GetSnippet(n),
											})
										}
									}
								}
							}
						}
					}
				}
				recursiveWalk(keyed.Value)
			}
		}

	// Default recursion for containers
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
	case *ast.VariableStatement:
		for _, expr := range n.List {
			recursiveWalk(expr)
		}
	case *ast.LexicalDeclaration:
		for _, expr := range n.List {
			recursiveWalk(expr)
		}
	case *ast.BinaryExpression:
		recursiveWalk(n.Left)
		recursiveWalk(n.Right)
	case *ast.DotExpression:
		recursiveWalk(n.Left)
	case *ast.BracketExpression:
		recursiveWalk(n.Left)
		recursiveWalk(n.Member)
	case *ast.SequenceExpression:
		for _, expr := range n.Sequence {
			recursiveWalk(expr)
		}
	case *ast.UnaryExpression:
		recursiveWalk(n.Operand)
	case *ast.ConditionalExpression:
		recursiveWalk(n.Test)
		recursiveWalk(n.Consequent)
		recursiveWalk(n.Alternate)
	case *ast.NewExpression:
		recursiveWalk(n.Callee)
		for _, arg := range n.ArgumentList {
			recursiveWalk(arg)
		}
	}
}

// HandleBinding processes variable declarations.
func (ctx *AnalysisContext) HandleBinding(n *ast.Binding) {
	decl := n
	if target, ok := decl.Target.(*ast.Identifier); ok {
		if decl.Initializer != nil {
			// Check for Sanitization FIRST
			if isSanitized(decl.Initializer) {
				ctx.Logger.VV("DOM: Variable '%s' is sanitized", string(target.Name))
			} else {
				// Check if Init is a source or contains a source
				source, isSrc := ctx.containsSource(decl.Initializer)
				if isSrc {
					// Check for Safe Properties/Methods
					isSafe := false
					if dot, ok := decl.Initializer.(*ast.DotExpression); ok {
						if isSafeProperty(string(dot.Identifier.Name)) {
							isSafe = true
							ctx.Logger.VV("DOM: Ignoring safe property access: %s", string(dot.Identifier.Name))
						}
					} else if call, ok := decl.Initializer.(*ast.CallExpression); ok {
						methodName := ""
						if dot, ok := call.Callee.(*ast.DotExpression); ok {
							methodName = string(dot.Identifier.Name)
						}
						if isSafeMethod(methodName) {
							isSafe = true
							ctx.Logger.VV("DOM: Ignoring safe method call: %s", methodName)
						}
					}

					if !isSafe {
						ctx.CurrentScope()[string(target.Name)] = source
						ctx.Logger.VV("DOM: Variable '%s' tainted from '%s'", string(target.Name), source)
					}
				} else if id, ok := decl.Initializer.(*ast.Identifier); ok {
					if taintedSrc, ok := ctx.LookupTaint(string(id.Name)); ok {
						ctx.CurrentScope()[string(target.Name)] = taintedSrc
					}
				} else if call, ok := decl.Initializer.(*ast.CallExpression); ok {
					// Check safe method
					methodName := ""
					if dot, ok := call.Callee.(*ast.DotExpression); ok {
						methodName = string(dot.Identifier.Name)
					}
					if isSafeMethod(methodName) {
						// Safe
					} else {
						for _, arg := range call.ArgumentList {
							if id, ok := arg.(*ast.Identifier); ok {
								if src, ok := ctx.LookupTaint(string(id.Name)); ok {
									ctx.CurrentScope()[string(target.Name)] = src
								}
							}
						}
					}
				} else if bin, ok := decl.Initializer.(*ast.BinaryExpression); ok {
					// Binary expression taint check
					tainted := false
					src := ""
					checkNode := func(e ast.Expression) {
						if id, ok := e.(*ast.Identifier); ok {
							if s, ok := ctx.LookupTaint(string(id.Name)); ok {
								tainted = true
								src = s
							}
						} else if s, ok := ctx.isSource(e); ok {
							tainted = true
							src = s
						}
					}
					checkNode(bin.Left)
					checkNode(bin.Right)

					if tainted {
						ctx.CurrentScope()[string(target.Name)] = src
					}
				}
			}
		}
	}
}
