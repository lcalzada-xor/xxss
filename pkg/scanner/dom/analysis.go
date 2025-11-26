package dom

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

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

	// NEW: Track tainted function calls for interprocedural analysis
	// Map: functionName -> map[argIndex]taintSource
	taintedCalls := make(map[string]map[int]string)

	// Helper to get current scope
	currentScope := func() map[string]string {
		return scopes[len(scopes)-1]
	}

	// Helper to lookup variable in scope chain
	lookupTaint := func(name string) (string, bool) {
		// fmt.Println("DEBUG: lookupTaint", name, "scopes:", len(scopes))
		for i := len(scopes) - 1; i >= 0; i-- {
			if val, ok := scopes[i][name]; ok {
				ds.logger.VV("DOM: lookupTaint('%s') found '%s' in scope %d", name, val, i)
				return val, true
			}
		}
		ds.logger.VV("DOM: lookupTaint('%s') NOT found. Scopes: %v", name, scopes)
		return "", false
	}

	// Forward declaration
	var recursiveWalk func(node ast.Node)

	// Walker function
	var walk func(node ast.Node)
	walk = func(node ast.Node) {
		if node == nil {
			return
		}
		ds.logger.VV("DOM: Visiting node type: %T", node)
		// Process node based on its type
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
			funcName := string(n.Function.Name.Name)

			// Push new scope
			scopes = append(scopes, make(map[string]string))

			// NEW: Check if this function was called with tainted arguments
			if taintedArgs, ok := taintedCalls[funcName]; ok {
				// Taint the corresponding parameters
				for argIdx, taintSrc := range taintedArgs {
					if argIdx < len(n.Function.ParameterList.List) {
						param := n.Function.ParameterList.List[argIdx]
						// param is already a *ast.Binding
						if paramIdent, ok := param.Target.(*ast.Identifier); ok {
							currentScope()[string(paramIdent.Name)] = taintSrc
							ds.logger.VV("DOM: Parameter '%s' of function '%s' tainted from '%s' (interprocedural)",
								string(paramIdent.Name), funcName, taintSrc)
						}
					}
				}
			}

			// Walk body (FunctionDeclaration has a Function field which contains the body)
			recursiveWalk(n.Function.Body)
			// Pop scope
			scopes = scopes[:len(scopes)-1]
			return // Don't continue default walk

		case *ast.Binding:
			decl := n
			if target, ok := decl.Target.(*ast.Identifier); ok {
				if decl.Initializer != nil {
					// Check for Sanitization FIRST
					isSanitized := false
					if call, ok := decl.Initializer.(*ast.CallExpression); ok {
						if dot, ok := call.Callee.(*ast.DotExpression); ok {
							if obj, ok := dot.Left.(*ast.Identifier); ok && string(obj.Name) == "DOMPurify" {
								isSanitized = true
							}
						}
					}

					if isSanitized {
						ds.logger.VV("DOM: Variable '%s' is sanitized via DOMPurify", string(target.Name))
					} else {
						// Check if Init is a source or contains a source (ENHANCED)
						source, isSrc := ds.containsSource(decl.Initializer)
						if isSrc {
							currentScope()[string(target.Name)] = source
							ds.logger.VV("DOM: Variable '%s' tainted from '%s'", string(target.Name), source)
						} else if id, ok := decl.Initializer.(*ast.Identifier); ok {
							// var x = y;
							if taintedSrc, ok := lookupTaint(string(id.Name)); ok {
								currentScope()[string(target.Name)] = taintedSrc
								ds.logger.VV("DOM: Variable '%s' tainted from '%s' (via '%s')", string(target.Name), taintedSrc, string(id.Name))
							}
						} else if call, ok := decl.Initializer.(*ast.CallExpression); ok {
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
								} else if s, ok := ds.isSource(e); ok {
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
			}
			if decl.Initializer != nil {
				recursiveWalk(decl.Initializer)
			}

		case *ast.AssignExpression:
			ds.logger.VV("DOM: Visiting AssignExpression")
			// 1. Taint Propagation (x = ...)
			if id, ok := n.Left.(*ast.Identifier); ok {
				if src, isSrc := ds.isSource(n.Right); isSrc {
					currentScope()[string(id.Name)] = src
				} else if rightId, ok := n.Right.(*ast.Identifier); ok {
					if src, ok := lookupTaint(string(rightId.Name)); ok {
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
			ds.logger.VV("DOM: Checking assignment to '%s'", leftName)
			isSink := false
			for _, sink := range ds.sinks {
				// Clean regex: remove \( and = but keep \ for other escapes (like \$)
				cleanSinkPattern := strings.ReplaceAll(sink.String(), `\(`, "")
				cleanSinkPattern = strings.ReplaceAll(cleanSinkPattern, `=`, "")
				cleanSinkPattern = strings.TrimSpace(cleanSinkPattern)

				// Recompile for matching
				if re, err := regexp.Compile(cleanSinkPattern); err == nil {
					if re.MatchString(leftName) {
						isSink = true
						ds.logger.VV("DOM: '%s' matched sink pattern '%s'", leftName, cleanSinkPattern)
						break
					}
				}
			}

			if isSink {
				ds.logger.VV("DOM: Detected sink assignment to '%s'", leftName)
				ds.logger.VV("DOM: RHS type: %T", n.Right)
				// Check Right side for taint
				if src, isSrc := ds.isSource(n.Right); isSrc {
					lineNumber := program.File.Position(int(n.Idx0())).Line
					ds.logger.VV("DOM: SINK DETECTED! %s = %s (line %d)", leftName, src, lineNumber)
					findings = append(findings, models.DOMFinding{
						Source:      src,
						Sink:        leftName,
						Line:        "AST Node",
						LineNumber:  lineNumber,
						Confidence:  "HIGH",
						Description: fmt.Sprintf("Direct flow: Source '%s' flows into Sink '%s'", src, leftName),
					})
				} else if id, ok := n.Right.(*ast.Identifier); ok {
					ds.logger.VV("DOM: Checking if identifier '%s' is tainted", string(id.Name))
					if src, ok := lookupTaint(string(id.Name)); ok {
						lineNumber := program.File.Position(int(n.Idx0())).Line
						ds.logger.VV("DOM: SINK DETECTED! %s = tainted var '%s' from %s (line %d)", leftName, string(id.Name), src, lineNumber)
						findings = append(findings, models.DOMFinding{
							Source:      src,
							Sink:        leftName,
							Line:        "AST Node",
							LineNumber:  lineNumber,
							Confidence:  "HIGH",
							Description: fmt.Sprintf("Tainted variable '%s' (from %s) flows into Sink '%s'", string(id.Name), src, leftName),
						})
					}
				} else if dot, ok := n.Right.(*ast.DotExpression); ok {
					ds.logger.VV("DOM: Checking DotExpression on RHS")
					// Check if object is tainted (e.g. e.data where e is tainted)
					if id, ok := dot.Left.(*ast.Identifier); ok {
						ds.logger.VV("DOM: DotExpression Left: %s", string(id.Name))
						if src, ok := lookupTaint(string(id.Name)); ok {
							lineNumber := program.File.Position(int(n.Idx0())).Line
							ds.logger.VV("DOM: SINK DETECTED! %s = tainted var '%s' (property access) from %s (line %d)", leftName, string(id.Name), src, lineNumber)
							findings = append(findings, models.DOMFinding{
								Source:      src,
								Sink:        leftName,
								Line:        "AST Node",
								LineNumber:  lineNumber,
								Confidence:  "HIGH",
								Description: fmt.Sprintf("Tainted variable '%s' (property of %s) flows into Sink '%s'", string(dot.Identifier.Name), src, leftName),
							})
						} else {
							ds.logger.VV("DOM: Variable '%s' is NOT tainted", string(id.Name))
						}
					}
				} else {
					ds.logger.VV("DOM: Identifier '%s' is NOT tainted", "expression")
				}
			}

		case *ast.CallExpression:
			// Check for window.addEventListener('message', ...) or addEventListener('message', ...)
			isAddEventListener := false
			if sel, ok := n.Callee.(*ast.DotExpression); ok {
				if string(sel.Identifier.Name) == "addEventListener" {
					isAddEventListener = true
				}
			} else if ident, ok := n.Callee.(*ast.Identifier); ok {
				if string(ident.Name) == "addEventListener" {
					isAddEventListener = true
				}
			}

			if isAddEventListener {
				ds.logger.VV("DOM: Found addEventListener call")
				if len(n.ArgumentList) >= 2 {
					// Check first arg is 'message'
					if arg0, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
						ds.logger.VV("DOM: Event type: %s", arg0.Value)
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
							default:
								ds.logger.VV("DOM: Callback is not a function literal or arrow function: %T", n.ArgumentList[1])
							}

							if callbackParams != nil && callbackBody != nil {
								if len(callbackParams.List) > 0 {
									// Found message listener!
									// The first parameter is the event object. Taint it.
									param := callbackParams.List[0]
									if paramIdent, ok := param.Target.(*ast.Identifier); ok {
										eventVar := string(paramIdent.Name)

										// We need to process the callback body with this new tainted variable
										// Push new scope
										scopes = append(scopes, make(map[string]string))

										// Taint event.data (and event itself)
										// We represent "event.data" as the source string
										currentScope()[eventVar] = "event.data"
										ds.logger.VV("DOM: Found 'message' event listener. Tainting param '%s' as 'event.data'", eventVar)

										// Check if origin is validated in the callback
										originValidated := false
										checkOrigin := func(n ast.Node) {
											if ifStmt, ok := n.(*ast.IfStatement); ok {
												// Check condition for event.origin
												// Simple check: if condition contains "origin"
												// Better: check if it compares event.origin
												var checkCond func(expr ast.Expression) bool
												checkCond = func(expr ast.Expression) bool {
													if bin, ok := expr.(*ast.BinaryExpression); ok {
														if strings.Contains(resolveDot(bin.Left), "origin") || strings.Contains(resolveDot(bin.Right), "origin") {
															return true
														}
													}
													if call, ok := expr.(*ast.CallExpression); ok {
														// e.g. allowedOrigins.includes(event.origin)
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

												if checkCond(ifStmt.Test) {
													originValidated = true
													ds.logger.VV("DOM: Found origin validation check")
												}
											}
										}

										// Walk the callback body to find origin check
										if blockStmt, ok := callbackBody.(*ast.BlockStatement); ok {
											for _, stmt := range blockStmt.List {
												checkOrigin(stmt)
											}
											recursiveWalk(blockStmt)
										} else if expr, ok := callbackBody.(ast.Expression); ok {
											// If it's an expression (concise body), walk it directly
											recursiveWalk(expr)
										}

										if !originValidated {
											ds.logger.VV("DOM: Missing origin validation in message listener")
											findings = append(findings, models.DOMFinding{
												Source:      "postMessage",
												Sink:        "Missing Origin Validation",
												Line:        "AST Node",
												LineNumber:  program.File.Position(int(n.Idx0())).Line,
												Confidence:  "MEDIUM",
												Description: "Message event listener does not appear to validate event.origin",
											})
										}

										// Pop scope
										scopes = scopes[:len(scopes)-1]

										// Don't continue default walk for the callback, we just did it
										return
									}
								} else {
									ds.logger.VV("DOM: Callback has no parameters")
								}
							}
						}
					} else {
						ds.logger.VV("DOM: First arg is not string literal: %T", n.ArgumentList[0])
					}
				}
			}

			// NEW: Track function calls with tainted arguments (for interprocedural analysis)
			if ident, ok := n.Callee.(*ast.Identifier); ok {
				funcName := string(ident.Name)

				// Check if any arguments are tainted
				for i, arg := range n.ArgumentList {
					if id, ok := arg.(*ast.Identifier); ok {
						if src, ok := lookupTaint(string(id.Name)); ok {
							// Record tainted call
							if taintedCalls[funcName] == nil {
								taintedCalls[funcName] = make(map[int]string)
							}
							taintedCalls[funcName][i] = src
							ds.logger.VV("DOM: Function '%s' called with tainted arg[%d] ('%s') from '%s'",
								funcName, i, string(id.Name), src)
						}
					}
				}
			}

			// Check if it's a sink
			calleeName := resolveDot(n.Callee)
			ds.logger.VV("DOM: CallExpression callee resolved to: %s", calleeName)

			isSink := false
			for _, sink := range ds.sinks {
				// Clean regex: remove \( and =
				cleanSinkPattern := strings.ReplaceAll(sink.String(), `\(`, "")
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
					if src, isSrc := ds.isSource(arg); isSrc {
						lineNumber := program.File.Position(int(n.Idx0())).Line
						ds.logger.VV("DOM: SINK DETECTED! %s() called with %s (line %d)", calleeName, src, lineNumber)
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
							ds.logger.VV("DOM: SINK DETECTED! %s() called with tainted var '%s' from %s (line %d)", calleeName, string(id.Name), src, lineNumber)
							findings = append(findings, models.DOMFinding{
								Source:      src,
								Sink:        calleeName,
								Line:        "AST Node",
								LineNumber:  lineNumber,
								Confidence:  "HIGH",
								Description: fmt.Sprintf("Tainted variable '%s' (from %s) flows into Sink '%s'", string(id.Name), src, calleeName),
							})
						}
					} else if dot, ok := arg.(*ast.DotExpression); ok {
						// Check if object is tainted (e.g. e.data where e is tainted)
						if id, ok := dot.Left.(*ast.Identifier); ok {
							if src, ok := lookupTaint(string(id.Name)); ok {
								lineNumber := program.File.Position(int(n.Idx0())).Line
								ds.logger.VV("DOM: SINK DETECTED! %s() called with tainted var '%s' (property access) from %s (line %d)", calleeName, string(id.Name), src, lineNumber)
								findings = append(findings, models.DOMFinding{
									Source:      src,
									Sink:        calleeName,
									Line:        "AST Node",
									LineNumber:  lineNumber,
									Confidence:  "HIGH",
									Description: fmt.Sprintf("Tainted variable '%s' (property of %s) flows into Sink '%s'", string(dot.Identifier.Name), src, calleeName),
								})
							}
						}
					}
				}
			}

		case *ast.ObjectLiteral:
			ds.logger.VV("DOM: ObjectLiteral has %d properties", len(n.Value))
			for i, prop := range n.Value {
				ds.logger.VV("DOM: ObjectLiteral prop %d type: %T", i, prop)
				if keyed, ok := prop.(*ast.PropertyKeyed); ok {
					// Check for React sink: dangerouslySetInnerHTML
					keyName := ""
					if id, ok := keyed.Key.(*ast.Identifier); ok {
						keyName = string(id.Name)
					} else if lit, ok := keyed.Key.(*ast.StringLiteral); ok {
						keyName = string(lit.Value)
					}

					if keyName == "dangerouslySetInnerHTML" {
						ds.logger.VV("DOM: Found dangerouslySetInnerHTML")
						// Check value
						if obj, ok := keyed.Value.(*ast.ObjectLiteral); ok {
							for _, innerProp := range obj.Value {
								if innerKeyed, ok := innerProp.(*ast.PropertyKeyed); ok {
									innerKeyName := ""
									if innerKey, ok := innerKeyed.Key.(*ast.Identifier); ok {
										innerKeyName = string(innerKey.Name)
									} else if innerKey, ok := innerKeyed.Key.(*ast.StringLiteral); ok {
										innerKeyName = string(innerKey.Value)
									}

									if innerKeyName == "__html" {
										// Check if value is tainted
										checkTaint := func(v ast.Expression) {
											if id, ok := v.(*ast.Identifier); ok {
												ds.logger.VV("DOM: Checking inner value: %s", id.Name)
												if src, ok := lookupTaint(string(id.Name)); ok {
													lineNumber := program.File.Position(int(keyed.Idx0())).Line // Approx line
													ds.logger.VV("DOM: SINK DETECTED! dangerouslySetInnerHTML = tainted var '%s' from %s", string(id.Name), src)
													findings = append(findings, models.DOMFinding{
														Source:      src,
														Sink:        "dangerouslySetInnerHTML",
														Line:        "AST Node",
														LineNumber:  lineNumber,
														Confidence:  "HIGH",
														Description: fmt.Sprintf("Tainted variable '%s' flows into React Sink 'dangerouslySetInnerHTML'", string(id.Name)),
													})
												} else {
													ds.logger.VV("DOM: Inner value '%s' is NOT tainted", id.Name)
												}
											} else {
												ds.logger.VV("DOM: Inner value is not identifier: %T", v)
											}
										}
										checkTaint(innerKeyed.Value)
									}
								}
							}
						} else {
							ds.logger.VV("DOM: dangerouslySetInnerHTML value is not ObjectLiteral: %T", keyed.Value)
						}
					}
					recursiveWalk(keyed.Value)
				} else {
					ds.logger.VV("DOM: Property is not PropertyKeyed: %T", prop)
				}
			}
		}
	}

	// Simple recursive walker since goja/parser might not provide one
	recursiveWalk = func(node ast.Node) {
		if node == nil {
			return
		}
		ds.logger.VV("DOM: recursiveWalk called with %T", node)
		walk(node)

		// Manually recurse for common container nodes
		switch n := node.(type) {
		case *ast.Program:
			for _, stmt := range n.Body {
				recursiveWalk(stmt)
			}
		case *ast.BlockStatement:
			ds.logger.VV("DOM: BlockStatement has %d statements", len(n.List))
			for i, stmt := range n.List {
				ds.logger.VV("DOM: BlockStatement stmt %d type: %T", i, stmt)
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
		case *ast.FunctionDeclaration:
			// Already handled in walk
		case *ast.FunctionLiteral:
			// Handled in walk
		case *ast.VariableStatement:
			for _, expr := range n.List {
				recursiveWalk(expr)
			}
		case *ast.CallExpression:
			recursiveWalk(n.Callee)
			for _, arg := range n.ArgumentList {
				recursiveWalk(arg)
			}
		case *ast.AssignExpression:
			recursiveWalk(n.Left)
			recursiveWalk(n.Right)
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

	// TWO-PASS ANALYSIS for interprocedural taint tracking

	// PASS 1: Collect tainted function calls (but don't analyze function bodies yet)
	ds.logger.VV("DOM: Starting Pass 1 - Collecting tainted function calls")
	var pass1Walk func(node ast.Node)
	pass1Walk = func(node ast.Node) {
		if node == nil {
			return
		}
		switch n := node.(type) {
		case *ast.Program:
			for _, stmt := range n.Body {
				pass1Walk(stmt)
			}
		case *ast.VariableStatement:
			for _, expr := range n.List {
				recursiveWalk(expr) // Use recursiveWalk for variable declarations
			}
		case *ast.ExpressionStatement:
			recursiveWalk(n.Expression) // Use recursiveWalk to ensure deep traversal
		case *ast.IfStatement:
			walk(n.Test)
			pass1Walk(n.Consequent)
			if n.Alternate != nil {
				pass1Walk(n.Alternate)
			}
		case *ast.BlockStatement:
			for _, stmt := range n.List {
				pass1Walk(stmt)
			}
		// Skip function declarations in pass 1
		case *ast.FunctionDeclaration:
			// Don't analyze body yet
			return
		}
	}
	pass1Walk(program)

	// PASS 2: Analyze function declarations with tainted call information
	ds.logger.VV("DOM: Starting Pass 2 - Analyzing function declarations")
	var pass2Walk func(node ast.Node)
	pass2Walk = func(node ast.Node) {
		if node == nil {
			return
		}
		switch n := node.(type) {
		case *ast.Program:
			for _, stmt := range n.Body {
				pass2Walk(stmt)
			}
		case *ast.FunctionDeclaration:
			// Now analyze function bodies with tainted parameter info
			walk(n)
		case *ast.BlockStatement:
			for _, stmt := range n.List {
				pass2Walk(stmt)
			}
		}
	}
	pass2Walk(program)

	return findings
}
