package analysis

import (
	"regexp"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// AnalyzeJS parses and analyzes JavaScript code for DOM XSS vulnerabilities.
// It returns a list of findings and a map of global variable accesses (for clobbering detection).
func AnalyzeJS(jsCode string, sources, sinks []*regexp.Regexp, logger *logger.Logger) ([]models.DOMFinding, map[string]bool) {
	var findings []models.DOMFinding

	// Parse JS
	program, err := parser.ParseFile(nil, "", jsCode, 0)
	if err != nil {
		// If parsing fails, we might want to log it but continue
		logger.VV("DOM: Failed to parse JS: %v", err)
		return findings, nil
	}

	// Initialize Analysis Context
	ctx := NewAnalysisContext(program, jsCode, sources, sinks, logger)

	// TWO-PASS ANALYSIS for interprocedural taint tracking

	// PASS 1: Collect tainted function calls (but don't analyze function bodies yet)
	logger.VV("DOM: Starting Pass 1 - Collecting tainted function calls")
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
				ctx.Walk(expr) // Use full Walk for variable declarations
			}
		case *ast.ExpressionStatement:
			ctx.Walk(n.Expression) // Use full Walk to ensure deep traversal
		case *ast.IfStatement:
			ctx.Walk(n.Test)
			pass1Walk(n.Consequent)
			if n.Alternate != nil {
				pass1Walk(n.Alternate)
			}
		case *ast.BlockStatement:
			for _, stmt := range n.List {
				pass1Walk(stmt)
			}
		case *ast.FunctionDeclaration:
			// Skip body in Pass 1
		case *ast.FunctionLiteral:
			// Skip body in Pass 1
		default:
			// For other nodes, use the full walker if needed, or skip
			// Ideally we want to process top-level code
			ctx.Walk(node)
		}
	}
	pass1Walk(program)

	// PASS 2: Analyze function declarations with tainted call information
	logger.VV("DOM: Starting Pass 2 - Analyzing function declarations")
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
			ctx.Walk(n)
		case *ast.BlockStatement:
			for _, stmt := range n.List {
				pass2Walk(stmt)
			}
		}
	}
	pass2Walk(program)

	// Extract Global Variable Accesses for DOM Clobbering
	logger.VV("DOM: Starting Global Variable Extraction")
	globalAccesses := make(map[string]bool)
	// We can reuse the context or create a new light walker
	// Since we just need to find identifiers that are NOT defined in scope
	// But our scope analysis in Walk is complex.
	// Let's do a simple separate walk for globals, or reuse the scopes if we kept them?
	// The scopes are transient in Walk.
	// Let's implement a simple global extractor here or in a separate file.
	// For now, let's keep it simple and inline or extract to detect_clobber.go

	extractGlobals(program, globalAccesses)

	logger.VV("DOM: Found %d potential global accesses: %v", len(globalAccesses), globalAccesses)

	return ctx.Findings, globalAccesses
}

// extractGlobals finds identifiers that are accessed but not defined in the local scope.
// This is a simplified check for DOM Clobbering.
func extractGlobals(program *ast.Program, globals map[string]bool) {
	// Simple scope tracking
	// Stack of scopes (sets of defined variables)
	scopes := []map[string]bool{make(map[string]bool)} // Global scope (empty initially)

	var globalWalk func(node ast.Node)
	globalWalk = func(node ast.Node) {
		if node == nil {
			return
		}

		switch n := node.(type) {
		case *ast.Program:
			for _, stmt := range n.Body {
				globalWalk(stmt)
			}
		case *ast.BlockStatement:
			for _, stmt := range n.List {
				globalWalk(stmt)
			}
		case *ast.ExpressionStatement:
			globalWalk(n.Expression)
		case *ast.IfStatement:
			globalWalk(n.Test)
			globalWalk(n.Consequent)
			globalWalk(n.Alternate)
		case *ast.ReturnStatement:
			globalWalk(n.Argument)
		case *ast.FunctionLiteral:
			scopes = append(scopes, make(map[string]bool))
			// Add params
			for _, param := range n.ParameterList.List {
				if id, ok := param.Target.(*ast.Identifier); ok {
					scopes[len(scopes)-1][string(id.Name)] = true
				}
			}
			globalWalk(n.Body)
			scopes = scopes[:len(scopes)-1]

		case *ast.FunctionDeclaration:
			scopes = append(scopes, make(map[string]bool))
			// Add params
			for _, param := range n.Function.ParameterList.List {
				if id, ok := param.Target.(*ast.Identifier); ok {
					scopes[len(scopes)-1][string(id.Name)] = true
				}
			}
			globalWalk(n.Function.Body)
			scopes = scopes[:len(scopes)-1]

		case *ast.VariableStatement:
			for _, binding := range n.List {
				if id, ok := binding.Target.(*ast.Identifier); ok {
					// Add to current scope
					scopes[len(scopes)-1][string(id.Name)] = true
				}
				// Walk initializer
				if binding.Initializer != nil {
					globalWalk(binding.Initializer)
				}
			}

		case *ast.Identifier:
			name := string(n.Name)
			// Check if defined in any scope
			defined := false
			for i := len(scopes) - 1; i >= 0; i-- {
				if scopes[i][name] {
					defined = true
					break
				}
			}
			if !defined {
				globals[name] = true
			}

		case *ast.AssignExpression:
			globalWalk(n.Left)
			globalWalk(n.Right)
		case *ast.BinaryExpression:
			globalWalk(n.Left)
			globalWalk(n.Right)
		case *ast.CallExpression:
			globalWalk(n.Callee)
			for _, arg := range n.ArgumentList {
				globalWalk(arg)
			}
		case *ast.DotExpression:
			globalWalk(n.Left)
			// Check for window.property or self.property
			if id, ok := n.Left.(*ast.Identifier); ok {
				objName := string(id.Name)
				if objName == "window" || objName == "self" || objName == "top" || objName == "parent" {
					globals[string(n.Identifier.Name)] = true
				}
			}
		case *ast.BracketExpression:
			globalWalk(n.Left)
			globalWalk(n.Member)
		case *ast.NewExpression:
			globalWalk(n.Callee)
			for _, arg := range n.ArgumentList {
				globalWalk(arg)
			}
		}
	}
	globalWalk(program)
}
