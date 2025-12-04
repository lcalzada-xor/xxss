package emulator

import (
	"fmt"

	"github.com/dop251/goja"
)

// Emulator executes JS code
type Emulator struct {
	Runtime  *goja.Runtime
	Traps    map[string]func(goja.FunctionCall) goja.Value
	Findings []string
}

// NewEmulator creates a new Emulator
func NewEmulator() *Emulator {
	vm := goja.New()
	e := &Emulator{
		Runtime:  vm,
		Traps:    make(map[string]func(goja.FunctionCall) goja.Value),
		Findings: []string{},
	}
	e.setupMockDOM()
	return e
}

// setupMockDOM initializes the mock browser environment
func (e *Emulator) setupMockDOM() {
	vm := e.Runtime

	// Mock 'window' (self-reference)
	vm.Set("window", vm.GlobalObject())

	// Mock 'document'
	doc := vm.NewObject()
	doc.Set("write", func(call goja.FunctionCall) goja.Value {
		// Trap document.write
		if len(call.Arguments) > 0 {
			arg := call.Arguments[0].String()
			e.checkTrap("document.write", arg)
		}
		return goja.Undefined()
	})
	doc.Set("getElementById", func(call goja.FunctionCall) goja.Value {
		// Return a mock element
		elem := vm.NewObject()
		elem.Set("innerHTML", "")
		return elem
	})
	vm.Set("document", doc)

	// Mock 'location'
	loc := vm.NewObject()
	loc.Set("hash", "#payload")
	loc.Set("search", "?q=payload")
	loc.Set("href", "http://example.com/#payload")
	vm.Set("location", loc)

	// Mock 'eval'
	// Note: goja has built-in eval, but we want to trap it.
	// However, overriding eval is tricky.
	// We can try to set it on window.
	vm.Set("eval", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			arg := call.Arguments[0].String()
			e.checkTrap("eval", arg)
			// We can optionally execute it or just return
		}
		return goja.Undefined()
	})

	// Mock 'setTimeout'
	vm.Set("setTimeout", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			// If first arg is string, it's eval-like
			if call.Arguments[0].ExportType().Name() == "string" {
				arg := call.Arguments[0].String()
				e.checkTrap("setTimeout", arg)
			}
		}
		return goja.Undefined()
	})
}

// checkTrap checks if the argument matches a payload
func (e *Emulator) checkTrap(sink, arg string) {
	// Simple check for now
	if arg == "payload" || arg == "#payload" || arg == "?q=payload" {
		e.Findings = append(e.Findings, fmt.Sprintf("Emulator detected flow to %s with arg %s", sink, arg))
	}
}

// Run executes the given code
func (e *Emulator) Run(code string) error {
	_, err := e.Runtime.RunString(code)
	return err
}
