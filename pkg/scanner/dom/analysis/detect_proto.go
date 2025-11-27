package analysis

import (
	"fmt"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

// DetectPrototypePollution checks for prototype pollution patterns in assignments.
// Returns true if handled (whether found or ignored).
func (ctx *AnalysisContext) DetectPrototypePollution(n *ast.AssignExpression) bool {
	isProtoPollution := false
	isDynamicKeyPollution := false
	var dynamicKeySource string

	// Helper to check for proto pollution in a DotExpression chain
	var checkProto func(node ast.Node) bool
	checkProto = func(node ast.Node) bool {
		if dot, ok := node.(*ast.DotExpression); ok {
			prop := string(dot.Identifier.Name)
			if prop == "__proto__" || prop == "prototype" || prop == "constructor" {
				return true
			}
			return checkProto(dot.Left)
		}
		if bracket, ok := node.(*ast.BracketExpression); ok {
			// Check for static string literal keys
			if lit, ok := bracket.Member.(*ast.StringLiteral); ok {
				prop := string(lit.Value)
				if prop == "__proto__" || prop == "prototype" || prop == "constructor" {
					return true
				}
			}
			// Check for dynamic keys (tainted)
			if src, isSrc := ctx.isSource(bracket.Member); isSrc {
				// FALSE POSITIVE REDUCTION: Ignore location.* as keys
				// Only if used DIRECTLY (e.g. obj[location.href]).
				// If it's a variable (LookupTaint), it might be a substring/parsed value.
				if len(src) >= 8 && src[:8] == "location" {
					return false
				}
				if len(src) >= 10 && src[:10] == "w.location" {
					return false
				}

				isDynamicKeyPollution = true
				dynamicKeySource = src
				return false // It's dynamic, not static proto pollution
			} else if id, ok := bracket.Member.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(id.Name)); ok {
					// FALSE POSITIVE REDUCTION: Ignore location.* as keys
					// Even if it's a variable, if the source is explicitly location.*, it's safe.
					if len(src) >= 8 && src[:8] == "location" {
						return false
					}
					if len(src) >= 10 && src[:10] == "w.location" {
						return false
					}

					isDynamicKeyPollution = true
					dynamicKeySource = src
					return false
				}
			}

			return checkProto(bracket.Left)
		}
		return false
	}

	if checkProto(n.Left) {
		isProtoPollution = true
	}

	if isProtoPollution {
		// FALSE POSITIVE REDUCTION: Only report if RHS is tainted
		isTainted := false
		taintSrc := ""

		if src, isSrc := ctx.isSource(n.Right); isSrc {
			isTainted = true
			taintSrc = src
		} else if id, ok := n.Right.(*ast.Identifier); ok {
			if src, ok := ctx.LookupTaint(string(id.Name)); ok {
				isTainted = true
				taintSrc = src
			}
		}

		// Fix for CI: Always report __proto__ assignment as dangerous, even if value is static
		// The test case: obj.__proto__.polluted = true;
		if !isTainted {
			// Check if we are assigning to __proto__ directly
			if dot, ok := n.Left.(*ast.DotExpression); ok {
				prop := string(dot.Identifier.Name)
				// ONLY flag __proto__ as suspicious if untainted.
				// prototype and constructor are commonly modified by libraries (e.g. Bootstrap)
				if prop == "__proto__" {
					isTainted = true
					taintSrc = "Static/Untainted Value"
				}
			}
		}

		if !isTainted {
			// Only report static assignments if they explicitly use __proto__
			// Assignments to .prototype or .constructor are common in libraries (e.g. Bootstrap)
			// and are usually safe if the value is untainted.
			if hasProto(n.Left) {
				isTainted = true
				taintSrc = "Static/Untainted Value"
			}
		}

		if isTainted {
			confidence := "HIGH"
			if taintSrc == "Static/Untainted Value" {
				confidence = "LOW"
			}

			lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
			ctx.AddFinding(models.DOMFinding{
				Source:      taintSrc,
				Sink:        "Prototype Pollution",
				Line:        "AST Node",
				LineNumber:  lineNumber,
				Confidence:  confidence,
				Description: fmt.Sprintf("Prototype Pollution: Assignment to sensitive property with tainted value '%s'", taintSrc),
			})
		}
		return true
	} else if isDynamicKeyPollution {
		confidence := "MEDIUM"
		// Upgrade confidence if the key comes from a dangerous source
		if isHighValueSource(dynamicKeySource) {
			confidence = "HIGH"
		}

		lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
		ctx.AddFinding(models.DOMFinding{
			Source:      dynamicKeySource,
			Sink:        "Dynamic Property Assignment",
			Line:        "AST Node",
			LineNumber:  lineNumber,
			Confidence:  confidence,
			Description: fmt.Sprintf("Potential Prototype Pollution: Dynamic property assignment using tainted key '%s'", dynamicKeySource),
		})
		return true
	}

	return false
}

// hasProto checks if the node chain contains __proto__
func hasProto(node ast.Node) bool {
	if dot, ok := node.(*ast.DotExpression); ok {
		if string(dot.Identifier.Name) == "__proto__" {
			return true
		}
		return hasProto(dot.Left)
	}
	if bracket, ok := node.(*ast.BracketExpression); ok {
		if lit, ok := bracket.Member.(*ast.StringLiteral); ok {
			if string(lit.Value) == "__proto__" {
				return true
			}
		}
		return hasProto(bracket.Left)
	}
	return false
}

func isHighValueSource(src string) bool {
	// Check for common high-value sources
	highValue := []string{"location", "window.name", "document.referrer", "document.cookie"}
	for _, h := range highValue {
		if len(src) >= len(h) && src[:len(h)] == h {
			return true
		}
	}
	return false
}
