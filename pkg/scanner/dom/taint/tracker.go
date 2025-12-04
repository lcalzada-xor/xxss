package taint

import (
	"regexp"

	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/dom/ast"
)

type Finding struct {
	Source      string
	Sink        string
	Line        int
	Confidence  string
	Description string
	Evidence    string
}

// Tracker holds the state of the taint analysis
type Tracker struct {
	GlobalScope    *ast.Scope
	CurrentScope   *ast.Scope
	SourcePatterns []*regexp.Regexp
	SinkPatterns   []*regexp.Regexp
}

// NewTracker creates a new Taint Tracker
func NewTracker(sources, sinks []string) *Tracker {
	global := ast.NewScope(nil, ast.ScopeGlobal)
	t := &Tracker{
		GlobalScope:  global,
		CurrentScope: global,
	}

	for _, p := range sources {
		t.SourcePatterns = append(t.SourcePatterns, regexp.MustCompile(p))
	}
	for _, p := range sinks {
		t.SinkPatterns = append(t.SinkPatterns, regexp.MustCompile(p))
	}

	return t
}

// EnterScope creates and enters a new scope
func (t *Tracker) EnterScope(scopeType ast.ScopeType) {
	t.CurrentScope = ast.NewScope(t.CurrentScope, scopeType)
}

// LeaveScope exits the current scope
func (t *Tracker) LeaveScope() {
	if t.CurrentScope.Parent != nil {
		t.CurrentScope = t.CurrentScope.Parent
	}
}

// IsSource checks if a given name matches a source pattern
func (t *Tracker) IsSource(name string) bool {
	for _, p := range t.SourcePatterns {
		if p.MatchString(name) {
			return true
		}
	}
	return false
}

// IsSink checks if a given name matches a sink pattern
func (t *Tracker) IsSink(name string) bool {
	for _, p := range t.SinkPatterns {
		if p.MatchString(name) {
			return true
		}
	}
	return false
}
