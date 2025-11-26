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
				isDynamicKeyPollution = true
				dynamicKeySource = src
				return false // It's dynamic, not static proto pollution
			} else if id, ok := bracket.Member.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(id.Name)); ok {
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

		if isTainted {
			lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
			ctx.AddFinding(models.DOMFinding{
				Source:      taintSrc,
				Sink:        "Prototype Pollution",
				Line:        "AST Node",
				LineNumber:  lineNumber,
				Confidence:  "HIGH",
				Description: fmt.Sprintf("Prototype Pollution: Assignment to sensitive property with tainted value '%s'", taintSrc),
			})
		} else {
			ctx.Logger.VV("DOM: Ignoring safe assignment to prototype property (RHS not tainted)")
		}
		return true
	} else if isDynamicKeyPollution {
		lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
		ctx.AddFinding(models.DOMFinding{
			Source:      dynamicKeySource,
			Sink:        "Dynamic Property Assignment",
			Line:        "AST Node",
			LineNumber:  lineNumber,
			Confidence:  "MEDIUM",
			Description: fmt.Sprintf("Potential Prototype Pollution: Dynamic property assignment using tainted key '%s'", dynamicKeySource),
		})
		return true
	}

	return false
}
