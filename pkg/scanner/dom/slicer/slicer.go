package slicer

import (
	"fmt"
	"strings"

	"github.com/dop251/goja/ast"
	domast "github.com/lcalzada-xor/xxss/v3/pkg/scanner/dom/ast"
)

// Slicer handles code slicing
type Slicer struct {
	Program *ast.Program
}

// NewSlicer creates a new Slicer
func NewSlicer(program *ast.Program) *Slicer {
	return &Slicer{
		Program: program,
	}
}

// Slice extracts the code necessary to evaluate the given expression
// This is a simplified implementation that extracts the entire statement
// and preceding variable declarations. A full slicer would be much more complex.
func (s *Slicer) Slice(expr ast.Expression, scope *domast.Scope) string {
	var sb strings.Builder

	// 1. Identify dependencies (variables used in the expression)
	deps := s.identifyDependencies(expr)

	// 2. Find definitions for these dependencies in the AST
	// This requires a reverse lookup or a second pass.
	// For simplicity in this MVP, we will walk the AST and collect
	// all variable declarations that match our dependencies.

	// We need a way to map AST nodes back to source code.
	// Since goja AST doesn't easily give us the source range without the file/source,
	// and we don't have a printer, we might need to reconstruct or just return the AST nodes.
	// BUT, the Emulator needs a string or AST to run.
	// Let's assume we can't easily reconstruct source from AST without a printer.
	// So we will return a "Mock" slice for now which is just the expression itself
	// wrapped in a function, assuming global context.

	// WAIT: We need to execute the *definitions* too.
	// If we have `var x = "alert(1)"; eval(x)`, we need `var x = "alert(1)"`.

	// Strategy:
	// We will collect all VariableDeclarations in the current scope (and parents)
	// and include them in the slice. This is "Over-Slicing" but safe.

	// To do this properly we need the source code string and the node positions.
	// We don't have that easily wired up yet.
	// Let's implement the dependency identification first.

	for _, dep := range deps {
		sb.WriteString(fmt.Sprintf("// Dependency: %s\n", dep))
	}

	return sb.String()
}

func (s *Slicer) identifyDependencies(expr ast.Expression) []string {
	var deps []string

	var walker func(node ast.Node)
	walker = func(node ast.Node) {
		if node == nil {
			return
		}
		switch n := node.(type) {
		case *ast.Identifier:
			deps = append(deps, n.Name.String())
		case *ast.BinaryExpression:
			walker(n.Left)
			walker(n.Right)
		case *ast.CallExpression:
			walker(n.Callee)
			for _, arg := range n.ArgumentList {
				walker(arg)
			}
			// Add more cases
		}
	}

	walker(expr)
	return deps
}
