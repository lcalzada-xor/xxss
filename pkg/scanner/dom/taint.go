package dom

import (
	"github.com/dop251/goja/ast"
)

// Helper to resolve DotExpression to string
func resolveDot(node ast.Node) string {
	if id, ok := node.(*ast.Identifier); ok {
		return string(id.Name)
	}
	if dot, ok := node.(*ast.DotExpression); ok {
		left := resolveDot(dot.Left)
		if left != "" {
			return left + "." + string(dot.Identifier.Name)
		}
		// If left is empty (e.g., CallExpression), just return the property name
		return string(dot.Identifier.Name)
	}
	// Handle CallExpression - extract the callee name
	if call, ok := node.(*ast.CallExpression); ok {
		return resolveDot(call.Callee)
	}
	return ""
}

// Helper to check if an expression is a tainted source
func (ds *DOMScanner) isSource(node ast.Expression) (string, bool) {
	// Handle DotExpression (obj.prop) - e.g. location.search
	if dot, ok := node.(*ast.DotExpression); ok {
		expr := resolveDot(dot)
		if expr != "" {
			for _, src := range ds.sources {
				if src.MatchString(expr) {
					return expr, true
				}
			}
		}
	}
	// Handle CallExpression (obj.method()) - e.g. localStorage.getItem()
	if call, ok := node.(*ast.CallExpression); ok {
		if dot, ok := call.Callee.(*ast.DotExpression); ok {
			expr := resolveDot(dot)
			if expr != "" {
				for _, src := range ds.sources {
					if src.MatchString(expr) {
						return expr, true
					}
				}
			}
		}
	}
	return "", false
}

// Helper to recursively check if expression contains a tainted source
// This handles complex expressions like: new URLSearchParams(window.location.search)
func (ds *DOMScanner) containsSource(node ast.Expression) (string, bool) {
	// First check if this node itself is a source
	if src, ok := ds.isSource(node); ok {
		return src, true
	}

	// Then recursively check sub-expressions
	switch n := node.(type) {
	case *ast.NewExpression:
		// Check constructor arguments
		for _, arg := range n.ArgumentList {
			if src, ok := ds.containsSource(arg); ok {
				return src, true
			}
		}

	case *ast.CallExpression:
		// Check method/function arguments
		for _, arg := range n.ArgumentList {
			if src, ok := ds.containsSource(arg); ok {
				return src, true
			}
		}
		// Also check the callee itself (for chained calls)
		if src, ok := ds.containsSource(n.Callee); ok {
			return src, true
		}

	case *ast.DotExpression:
		// Check the left side (e.g., for (new URLSearchParams(...)).get())
		if src, ok := ds.containsSource(n.Left); ok {
			return src, true
		}

	case *ast.BinaryExpression:
		// Check both operands
		if src, ok := ds.containsSource(n.Left); ok {
			ds.logger.VV("DOM: Found nested source '%s' in BinaryExpression", src)
			return src, true
		}
		if src, ok := ds.containsSource(n.Right); ok {
			ds.logger.VV("DOM: Found nested source '%s' in BinaryExpression", src)
			return src, true
		}

	case *ast.ArrayLiteral:
		// Check array elements
		for _, elem := range n.Value {
			if src, ok := ds.containsSource(elem); ok {
				ds.logger.VV("DOM: Found nested source '%s' in ArrayLiteral", src)
				return src, true
			}
		}

	case *ast.ConditionalExpression:
		// Check ternary operator parts
		if src, ok := ds.containsSource(n.Consequent); ok {
			return src, true
		}
		if src, ok := ds.containsSource(n.Alternate); ok {
			return src, true
		}
	}

	return "", false
}
