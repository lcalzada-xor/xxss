package analysis

import (
	"regexp"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// AnalysisContext holds the state for a single JS analysis run.
type AnalysisContext struct {
	Sources      []*regexp.Regexp
	Sinks        []*regexp.Regexp
	Program      *ast.Program
	Scopes       []map[string]string
	TaintedCalls map[string]map[int]string
	Findings     []models.DOMFinding
	Logger       *logger.Logger
}

// NewAnalysisContext creates a new context.
func NewAnalysisContext(program *ast.Program, sources, sinks []*regexp.Regexp, logger *logger.Logger) *AnalysisContext {
	return &AnalysisContext{
		Sources:      sources,
		Sinks:        sinks,
		Program:      program,
		Scopes:       []map[string]string{make(map[string]string)}, // Global scope
		TaintedCalls: make(map[string]map[int]string),
		Logger:       logger,
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
