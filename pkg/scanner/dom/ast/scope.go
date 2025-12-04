package ast

// ScopeType defines the type of the scope
type ScopeType int

const (
	ScopeGlobal ScopeType = iota
	ScopeFunction
	ScopeBlock
)

// Scope represents a lexical scope in JavaScript
type Scope struct {
	Type      ScopeType
	Parent    *Scope
	Variables map[string]*Variable
}

// Variable represents a variable defined in a scope
type Variable struct {
	Name    string
	Tainted bool
	Source  string // Description of the source if tainted
}

// NewScope creates a new scope
func NewScope(parent *Scope, scopeType ScopeType) *Scope {
	return &Scope{
		Type:      scopeType,
		Parent:    parent,
		Variables: make(map[string]*Variable),
	}
}

// Define creates a new variable in the current scope
func (s *Scope) Define(name string) *Variable {
	v := &Variable{Name: name}
	s.Variables[name] = v
	return v
}

// Lookup finds a variable in the current or parent scopes
func (s *Scope) Lookup(name string) *Variable {
	if v, ok := s.Variables[name]; ok {
		return v
	}
	if s.Parent != nil {
		return s.Parent.Lookup(name)
	}
	return nil
}

// Taint marks a variable as tainted
func (v *Variable) Taint(source string) {
	v.Tainted = true
	v.Source = source
}

// Untaint marks a variable as safe
func (v *Variable) Untaint() {
	v.Tainted = false
	v.Source = ""
}
