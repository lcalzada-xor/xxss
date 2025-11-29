package analysis

import (
	"strings"

	"github.com/dop251/goja/ast"
)

// isSource checks if an expression is a known source.
func (ctx *AnalysisContext) isSource(node ast.Expression) (string, bool) {
	name := resolveDot(node)
	if name == "" {
		return "", false
	}

	for _, pattern := range ctx.Sources {
		if pattern.MatchString(name) {
			return name, true
		}
	}
	return "", false
}

// containsSource checks if an expression contains a source (recursive).
func (ctx *AnalysisContext) containsSource(node ast.Expression) (string, bool) {
	found := ""
	var check func(n ast.Node)
	check = func(n ast.Node) {
		if n == nil || found != "" {
			return
		}
		if expr, ok := n.(ast.Expression); ok {
			if src, isSrc := ctx.isSource(expr); isSrc {
				found = src
				return
			}
			if id, ok := expr.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(id.Name)); ok {
					found = src
					return
				}
			}
			if _, ok := expr.(*ast.ThisExpression); ok {
				if src, ok := ctx.LookupTaint("this"); ok {
					found = src
					return
				}
			}
		}
		// Recurse
		switch t := n.(type) {
		case *ast.BinaryExpression:
			check(t.Left)
			check(t.Right)
		case *ast.CallExpression:
			check(t.Callee)
			for _, arg := range t.ArgumentList {
				check(arg)
			}
		case *ast.AssignExpression:
			check(t.Right)
		case *ast.NewExpression:
			check(t.Callee)
			for _, arg := range t.ArgumentList {
				check(arg)
			}
		case *ast.DotExpression:
			check(t.Left)
		case *ast.BracketExpression:
			check(t.Left)
			check(t.Member)
		}
	}
	check(node)
	return found, found != ""
}

// isSafeProperty checks if a property name is considered safe (e.g. length).
func isSafeProperty(name string) bool {
	safeProps := []string{"length", "byteLength", "size", "count", "index", "lastIndex"}
	for _, p := range safeProps {
		if name == p {
			return true
		}
	}
	return false
}

// isSafeMethod checks if a method name is considered safe (e.g. indexOf).
func isSafeMethod(name string) bool {
	safeMethods := []string{
		"indexOf", "lastIndexOf", "includes", "startsWith", "endsWith",
		"charCodeAt", "codePointAt", "localeCompare", "search", "match",
		"test",
	}
	for _, m := range safeMethods {
		if name == m {
			return true
		}
	}
	return false
}

// isSanitized checks if a node involves a known sanitization function.
func isSanitized(node ast.Node) bool {
	if call, ok := node.(*ast.CallExpression); ok {
		callee := resolveDot(call.Callee)
		sanitizers := []string{
			"DOMPurify.sanitize",
			"escapeHTML",
			"encodeURIComponent",
			"encodeURI",
			"_.escape",
		}
		for _, s := range sanitizers {
			if strings.Contains(callee, s) {
				return true
			}
		}
	}
	return false
}

// resolveDot resolves a DotExpression or Identifier to a string.
// This was previously in analysis.go, moving it here or to a utils file.
// Since it's used by taint logic, putting it here is fine, or maybe in walker.go.
// It's a general helper.
func resolveDot(node ast.Node) string {
	switch n := node.(type) {
	case *ast.Identifier:
		return string(n.Name)
	case *ast.DotExpression:
		left := resolveDot(n.Left)
		if left != "" {
			return left + "." + string(n.Identifier.Name)
		}
		// If left is complex (e.g. CallExpression) but resolveDot returned empty,
		// we might still want to prepend a dot if we know it's a member access.
		// However, adding CallExpression support below is better.
		return string(n.Identifier.Name)
	case *ast.CallExpression:
		// Handle method chaining: $().html()
		return resolveDot(n.Callee) + "()"
	}
	return ""
}
