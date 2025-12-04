package taint

import (
	"fmt"
	"strings"

	"github.com/dop251/goja/ast"
	domast "github.com/lcalzada-xor/xxss/v3/pkg/scanner/dom/ast"
)

// Propagator traverses the AST and propagates taint
type Propagator struct {
	Tracker        *Tracker
	GlobalAccesses map[string]bool
	Findings       []Finding
}

// NewPropagator creates a new Propagator
func NewPropagator(tracker *Tracker) *Propagator {
	return &Propagator{
		Tracker:        tracker,
		GlobalAccesses: make(map[string]bool),
	}
}

// Run executes the taint analysis on the program
func (p *Propagator) Run(program *ast.Program) []Finding {
	for _, stmt := range program.Body {
		p.walk(stmt)
	}
	return p.Findings
}

func (p *Propagator) walk(node ast.Node) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.Program:
		for _, stmt := range n.Body {
			p.walk(stmt)
		}
	case *ast.ObjectLiteral:
		for _, item := range n.Value {
			if prop, ok := item.(*ast.PropertyKeyed); ok {
				// Check key for sink (e.g. dangerouslySetInnerHTML)
				keyName := ""
				if id, ok := prop.Key.(*ast.Identifier); ok {
					keyName = id.Name.String()
				} else if str, ok := prop.Key.(*ast.StringLiteral); ok {
					keyName = str.Value.String()
				}

				if keyName != "" && p.Tracker.IsSink(keyName) {
					tainted, source := p.evaluate(prop.Value)
					if tainted {
						f := Finding{
							Source:     source,
							Sink:       keyName,
							Line:       0,
							Confidence: "High",
							Evidence:   keyName + ": " + source, // Populate Evidence
						}
						fmt.Printf("DEBUG: Appending finding: %+v\n", f)
						p.Findings = append(p.Findings, f)
					}
				} else {
					// Walk value
					p.walk(prop.Value)
				}
			}
		}
	case *ast.VariableStatement:
		for _, decl := range n.List {
			p.handleVarDecl(decl)
		}
	case *ast.LexicalDeclaration:
		for _, decl := range n.List {
			p.handleVarDecl(decl)
		}
	case *ast.AssignExpression:
		p.handleAssignment(n)
	case *ast.FunctionDeclaration:
		p.Tracker.EnterScope(domast.ScopeFunction)
		// Define params
		for _, param := range n.Function.ParameterList.List {
			if id, ok := param.Target.(*ast.Identifier); ok {
				p.Tracker.CurrentScope.Define(id.Name.String())
			}
		}
		// Walk body
		p.walk(n.Function.Body)
		p.Tracker.LeaveScope()
	case *ast.BlockStatement:
		p.Tracker.EnterScope(domast.ScopeBlock)
		for _, stmt := range n.List {
			p.walk(stmt)
		}
		p.Tracker.LeaveScope()
	case *ast.ExpressionStatement:
		p.walk(n.Expression)
	case *ast.CallExpression:
		p.handleCall(n)
	case *ast.IfStatement:
		p.walk(n.Test)
		p.walk(n.Consequent)
		if n.Alternate != nil {
			p.walk(n.Alternate)
		}
	case *ast.ReturnStatement:
		if n.Argument != nil {
			p.walk(n.Argument)
		}
	default:
		// fmt.Printf("DEBUG: Unknown node type %T\n", n)
	}
}

func (p *Propagator) handleVarDecl(decl *ast.Binding) {
	target, ok := decl.Target.(*ast.Identifier)
	if !ok {
		return // Complex destructuring not supported yet
	}
	name := target.Name.String()
	v := p.Tracker.CurrentScope.Define(name)

	if decl.Initializer != nil {
		// Walk the initializer to catch sinks inside it (e.g. ObjectLiteral)
		p.walk(decl.Initializer)

		tainted, source := p.evaluate(decl.Initializer)
		if tainted {
			// fmt.Printf("DEBUG: Tainted variable %s with source %s\n", name, source)
			v.Taint(source)
		}
	}
}

func (p *Propagator) handleAssignment(expr *ast.AssignExpression) {
	tainted, source := p.evaluate(expr.Right)

	// 1. Propagate taint to variable
	if id, ok := expr.Left.(*ast.Identifier); ok {
		v := p.Tracker.CurrentScope.Lookup(id.Name.String())
		if tainted {
			if v != nil {
				v.Taint(source)
			} else {
				// Implicit global assignment
				v = p.Tracker.GlobalScope.Define(id.Name.String())
				v.Taint(source)
				p.GlobalAccesses[id.Name.String()] = true
			}
		} else {
			// If right side is safe, untaint the variable
			if v != nil {
				v.Untaint()
			}
		}
	}

	// 2. Check if assignment target is a Sink (e.g. element.innerHTML = tainted)
	leftName := ""
	if id, ok := expr.Left.(*ast.Identifier); ok {
		leftName = id.Name.String()
	} else {
		leftName = p.reconstructPath(expr.Left)
	}

	// Normalize for pattern matching (append = for assignments)
	// Some patterns like innerHTML don't have =, others like location.href= do.
	// We check both raw and with =
	if leftName != "" {
		isSink := p.Tracker.IsSink(leftName)
		if !isSink {
			isSink = p.Tracker.IsSink(leftName + "=")
		}

		if isSink {
			// Special case: Prototype Pollution is dangerous regardless of value taint
			// (or at least we want to flag it as suspicious)
			isProto := false
			if strings.Contains(leftName, "__proto__") || strings.Contains(leftName, "prototype") || strings.Contains(leftName, "constructor") {
				isProto = true
			}

			if tainted || isProto {
				p.Findings = append(p.Findings, Finding{
					Source:     source,
					Sink:       leftName,
					Line:       0,
					Confidence: "High",
				})
			}
		}
	}
}

func (p *Propagator) handleCall(expr *ast.CallExpression) {
	// Check if it's a sink
	calleeName := ""
	if id, ok := expr.Callee.(*ast.Identifier); ok {
		calleeName = id.Name.String()
	} else {
		calleeName = p.reconstructPath(expr.Callee)
	}

	// Normalize for pattern matching (append ( for calls)
	isSink := p.Tracker.IsSink(calleeName)
	if !isSink {
		isSink = p.Tracker.IsSink(calleeName + "(")
	}

	if isSink {
		// Check arguments for taint
		for _, arg := range expr.ArgumentList {
			tainted, source := p.evaluate(arg)
			if tainted {
				p.Findings = append(p.Findings, Finding{
					Source:     source,
					Sink:       calleeName,
					Line:       0, // AST doesn't easily give line numbers without file set, need to improve
					Confidence: "High",
				})
			}
		}
	}
}

// evaluate returns (isTainted, sourceName)
func (p *Propagator) evaluate(expr ast.Expression) (bool, string) {
	switch e := expr.(type) {
	case *ast.Identifier:
		name := e.Name.String()
		v := p.Tracker.CurrentScope.Lookup(name)
		if v != nil {
			// fmt.Printf("DEBUG: Identifier %s found in scope\n", name)
			if v.Tainted {
				return true, v.Source
			}
		} else {
			// Global access
			p.GlobalAccesses[name] = true
		}
		// Check if the identifier itself is a source (e.g. "location")
		if p.Tracker.IsSource(name) {
			return true, name
		}
	case *ast.BinaryExpression:
		t1, s1 := p.evaluate(e.Left)
		if t1 {
			return true, s1
		}
		t2, s2 := p.evaluate(e.Right)
		if t2 {
			return true, s2
		}
	case *ast.DotExpression:
		// Check for safe properties
		propName := e.Identifier.Name.String()
		if propName == "length" || propName == "constructor" || propName == "prototype" {
			// Unless we are checking for sinks/pollution?
			// For evaluation (source), these are usually safe.
			return false, ""
		}

		// Check if it's a source like location.hash
		// Reconstruct string
		str := p.reconstructPath(e)
		if p.Tracker.IsSource(str) {
			return true, str
		}
		// Also check if object is tainted?
		// e.g. taintedObj.prop -> maybe?
		t, s := p.evaluate(e.Left)
		if t {
			return true, s
		}
	case *ast.BracketExpression:
		// Handle obj['prop']
		str := p.reconstructPath(e)
		if p.Tracker.IsSource(str) {
			return true, str
		}
		t, s := p.evaluate(e.Left)
		if t {
			return true, s
		}

	case *ast.CallExpression:
		// Check if it's a source function call (e.g. localStorage.getItem)
		// Use reconstructPath
		obj := p.reconstructPath(e.Callee)
		if p.Tracker.IsSource(obj) {
			return true, obj
		}
	case *ast.ObjectLiteral:
		for _, item := range e.Value {
			if prop, ok := item.(*ast.PropertyKeyed); ok {
				t, s := p.evaluate(prop.Value)
				if t {
					return true, s
				}
			}
		}
	}
	return false, ""
}

func (p *Propagator) reconstructPath(expr ast.Expression) string {
	switch e := expr.(type) {
	case *ast.Identifier:
		return e.Name.String()
	case *ast.DotExpression:
		obj := p.reconstructPath(e.Left)
		prop := e.Identifier.Name.String()
		if obj != "" {
			return obj + "." + prop
		}
		return "." + prop
	case *ast.BracketExpression:
		obj := p.reconstructPath(e.Left)
		// Handle string literal index
		if str, ok := e.Member.(*ast.StringLiteral); ok {
			// Treat ['prop'] as .prop for regex matching
			prop := str.Value.String()
			if obj != "" {
				return obj + "." + prop // Normalize to dot notation for regex
			}
			return "." + prop
		}
		return obj + "[]" // Unknown index
	case *ast.CallExpression:
		// Handle method chaining
		return "$()"
	}
	return ""
}
