package ast

import (
	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

// Parse parses the given JavaScript code and returns the AST program.
func Parse(code string) (*ast.Program, error) {
	// ParseFile(filename, src, mode)
	// We pass empty filename and 0 mode (default)
	return parser.ParseFile(nil, "", code, 0)
}
