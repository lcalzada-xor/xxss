package analysis

import (
	"strings"

	"github.com/lcalzada-xor/xxss/v3/pkg/models"
)

// JSContextState represents the current state of the JS lexer
type JSContextState int

const (
	StateNone JSContextState = iota
	StateSingleQuote
	StateDoubleQuote
	StateTemplateLiteral
	StateCommentLine
	StateCommentBlock
	StateRegex
)

// analyzeJSContextWithLexer uses a state machine to determine the context of the probe
func analyzeJSContextWithLexer(code, probe string) (bool, models.ReflectionContext) {
	// Simple state machine
	state := StateNone

	// Stack for nested states (to handle template literals ${...})
	// We push the previous state when entering ${}
	// But actually, inside ${}, we are in StateNone (code block).
	// When we hit }, we pop the state.
	// Since we only care about template literals nesting, we can just push a marker.
	// But we need to know if } closes a block or is just a char.
	// } only closes a block if we are in StateNone and we have something on stack.
	stateStack := []JSContextState{}

	// Stack for nested template literals (simplified, just counting depth might be enough for basic cases,
	// but for accurate context we need to know if we are in ${} block)
	// For this specific task: "Is the probe inside a string/template/comment?"
	// We don't need a full AST, just the state at the point where 'probe' starts.

	// However, we need to find *where* the probe is.
	// Since the probe might appear multiple times, we should ideally look for the *first* occurrence
	// or check all. The existing logic usually checks the first one found by strings.Index.
	// But `analyzeJavaScriptContext` receives a `context` string which is a snippet around the probe.
	// The probe is guaranteed to be in `code`.

	// Let's iterate through the code and track state.
	// When we encounter the probe sequence, we check the current state.

	probeRunes := []rune(probe)
	if len(probeRunes) == 0 {
		return false, models.ContextUnknown
	}

	codeRunes := []rune(code)

	for i := 0; i < len(codeRunes); i++ {
		// Check if we hit the probe at this position
		if matchProbe(codeRunes, i, probeRunes) {
			// Found the probe! Return current state.
			switch state {
			case StateSingleQuote:
				return true, models.ContextJSSingleQuote
			case StateDoubleQuote:
				return true, models.ContextJSDoubleQuote
			case StateTemplateLiteral:
				return true, models.ContextTemplateLiteral
			case StateCommentLine, StateCommentBlock:
				return true, models.ContextComment // Or specific JS comment context if added
			case StateRegex:
				return true, models.ContextJSRaw // Regex is effectively raw
			default:
				return true, models.ContextJSRaw
			}
		}

		char := codeRunes[i]

		switch state {
		case StateNone:
			switch char {
			case '\'':
				state = StateSingleQuote
			case '"':
				state = StateDoubleQuote
			case '`':
				state = StateTemplateLiteral
			case '}':
				// Check if we need to pop stack (closing ${ })
				if len(stateStack) > 0 {
					// Pop
					state = stateStack[len(stateStack)-1]
					stateStack = stateStack[:len(stateStack)-1]
				}
			case '/':
				// Potential comment or regex
				if i+1 < len(codeRunes) {
					next := codeRunes[i+1]
					if next == '/' {
						state = StateCommentLine
						i++ // Skip next char
					} else if next == '*' {
						state = StateCommentBlock
						i++ // Skip next char
					} else {
						// Regex detection is hard (could be division).
						// Heuristic: check previous non-whitespace char.
						// If it's an operator or start of line, likely regex.
						// For now, let's assume division to be safe, or implement simple heuristic.
						// A simple heuristic: if previous char was ( = , : ? [ { or operator, it's regex.
						if isRegexStart(codeRunes, i) {
							state = StateRegex
						}
					}
				}
			}

		case StateSingleQuote:
			if char == '\'' {
				// Check for escape
				if !isEscaped(codeRunes, i) {
					state = StateNone
				}
			}

		case StateDoubleQuote:
			if char == '"' {
				if !isEscaped(codeRunes, i) {
					state = StateNone
				}
			}

		case StateTemplateLiteral:
			if char == '`' {
				if !isEscaped(codeRunes, i) {
					state = StateNone
				}
			} else if char == '$' {
				// Check for ${
				if i+1 < len(codeRunes) && codeRunes[i+1] == '{' {
					if !isEscaped(codeRunes, i) {
						// Enter code block
						// Push current state (TemplateLiteral)
						stateStack = append(stateStack, StateTemplateLiteral)
						state = StateNone
						i++ // Skip {
					}
				}
			}

		case StateCommentLine:
			if char == '\n' {
				state = StateNone
			}

		case StateCommentBlock:
			if char == '*' && i+1 < len(codeRunes) && codeRunes[i+1] == '/' {
				state = StateNone
				i++
			}

		case StateRegex:
			if char == '/' {
				if !isEscaped(codeRunes, i) {
					state = StateNone
				}
			}
		}
	}

	return false, models.ContextUnknown
}

func matchProbe(code []rune, pos int, probe []rune) bool {
	if pos+len(probe) > len(code) {
		return false
	}
	for j := 0; j < len(probe); j++ {
		if code[pos+j] != probe[j] {
			return false
		}
	}
	return true
}

func isEscaped(code []rune, pos int) bool {
	escaped := false
	for i := pos - 1; i >= 0; i-- {
		if code[i] == '\\' {
			escaped = !escaped
		} else {
			break
		}
	}
	return escaped
}

func isRegexStart(code []rune, pos int) bool {
	// Look backwards for non-whitespace
	for i := pos - 1; i >= 0; i-- {
		c := code[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		// Chars that usually precede a regex
		if strings.ContainsRune("(=,:?[{!", c) {
			return true
		}
		// Return keyword?
		// This is getting complicated for a simple lexer.
		// Let's stick to simple operator check.
		return false
	}
	return true // Start of string
}
