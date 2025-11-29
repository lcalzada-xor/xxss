package analysis

import (
	"regexp"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// AnalysisContext holds the state for a single JS analysis run.
type AnalysisContext struct {
	Sources               []*regexp.Regexp
	Sinks                 []*regexp.Regexp
	Program               *ast.Program
	Scopes                []map[string]string
	TaintedCalls          map[string]map[int]string
	Findings              []models.DOMFinding
	Logger                *logger.Logger
	SourceCode            string
	TaintedThisFunctions  map[*ast.FunctionLiteral]string
	PendingCallbacks      map[string][]*ast.FunctionLiteral
	ExpressionTaint       map[ast.Expression]string
	TaintedFunctionParams map[ast.Node]map[string]string
}

// NewAnalysisContext creates a new context.
func NewAnalysisContext(program *ast.Program, jsCode string, sources, sinks []*regexp.Regexp, logger *logger.Logger) *AnalysisContext {
	return &AnalysisContext{
		Sources:               sources,
		Sinks:                 sinks,
		Program:               program,
		Scopes:                []map[string]string{make(map[string]string)}, // Global scope
		TaintedCalls:          make(map[string]map[int]string),
		TaintedThisFunctions:  make(map[*ast.FunctionLiteral]string),
		PendingCallbacks:      make(map[string][]*ast.FunctionLiteral),
		ExpressionTaint:       make(map[ast.Expression]string),
		TaintedFunctionParams: make(map[ast.Node]map[string]string),
		Logger:                logger,
		SourceCode:            jsCode,
	}
}

// PushScope adds a new scope to the stack.
func (ctx *AnalysisContext) PushScope() {
	ctx.Scopes = append(ctx.Scopes, make(map[string]string))
}

// PopScope removes the top scope from the stack.
func (ctx *AnalysisContext) PopScope() {
	if len(ctx.Scopes) > 1 {
		ctx.Scopes = ctx.Scopes[:len(ctx.Scopes)-1]
	}
}

// CurrentScope returns the current scope map.
func (ctx *AnalysisContext) CurrentScope() map[string]string {
	return ctx.Scopes[len(ctx.Scopes)-1]
}

// LookupTaint checks if a variable is tainted in the current scope chain.
func (ctx *AnalysisContext) LookupTaint(name string) (string, bool) {
	for i := len(ctx.Scopes) - 1; i >= 0; i-- {
		if val, ok := ctx.Scopes[i][name]; ok {
			ctx.Logger.VV("DOM: lookupTaint('%s') found '%s' in scope %d", name, val, i)
			return val, true
		}
	}
	// ctx.Logger.VV("DOM: lookupTaint('%s') NOT found", name)
	return "", false
}

// AddFinding adds a finding to the list.
func (ctx *AnalysisContext) AddFinding(finding models.DOMFinding) {
	ctx.Findings = append(ctx.Findings, finding)
}

// GetSnippet extracts the source code for a given AST node.
func (ctx *AnalysisContext) GetSnippet(node ast.Node) string {
	if node == nil {
		return ""
	}
	start := int(node.Idx0()) - 1
	end := int(node.Idx1()) - 1

	if start < 0 {
		start = 0
	}
	if end > len(ctx.SourceCode) {
		end = len(ctx.SourceCode)
	}
	if start >= end {
		return ""
	}

	return ctx.SourceCode[start:end]
}

// AddTaintedParam registers a parameter to be tainted when visiting a function.
func (ctx *AnalysisContext) AddTaintedParam(funcNode ast.Node, paramName, source string) {
	if ctx.TaintedFunctionParams[funcNode] == nil {
		ctx.TaintedFunctionParams[funcNode] = make(map[string]string)
	}
	ctx.TaintedFunctionParams[funcNode][paramName] = source
}
