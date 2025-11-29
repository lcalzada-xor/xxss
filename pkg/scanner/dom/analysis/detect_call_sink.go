package analysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func (ctx *AnalysisContext) checkCallSink(n *ast.CallExpression) {
	calleeName := resolveDot(n.Callee)
	ctx.Logger.VV("DOM: CallExpression callee resolved to: %s", calleeName)

	isSink := false
	for _, sink := range ctx.Sinks {
		cleanSinkPattern := strings.ReplaceAll(sink.String(), `\(`, "")
		cleanSinkPattern = strings.ReplaceAll(cleanSinkPattern, `=`, "")
		cleanSinkPattern = strings.TrimSpace(cleanSinkPattern)

		if re, err := regexp.Compile(cleanSinkPattern); err == nil {
			if re.MatchString(calleeName) {
				isSink = true
				break
			}
		}
	}

	if isSink {
		// FALSE POSITIVE REDUCTION: jQuery Sinks
		if strings.Contains(calleeName, ".html") || strings.Contains(calleeName, ".append") || strings.Contains(calleeName, ".prepend") {
			if len(n.ArgumentList) > 0 {
				if lit, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
					val := strings.TrimSpace(string(lit.Value))
					if (strings.HasPrefix(val, "#") || strings.HasPrefix(val, ".")) && !strings.HasPrefix(val, "<") {
						ctx.Logger.VV("DOM: Ignoring safe jQuery selector: %s", val)
						isSink = false
					}
				}
			}
		}

		// FALSE POSITIVE REDUCTION: document.write
		if strings.Contains(calleeName, "document.write") {
			if len(n.ArgumentList) > 0 {
				if lit, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
					ctx.Logger.VV("DOM: Ignoring static document.write: %s", lit.Value)
					isSink = false
				}
			}
		}

		// FALSE POSITIVE REDUCTION: importScripts (Web Workers)
		if strings.Contains(calleeName, "importScripts") {
			if len(n.ArgumentList) > 0 {
				if lit, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
					ctx.Logger.VV("DOM: Ignoring static importScripts: %s", lit.Value)
					isSink = false
				}
			}
		}
	}

	if isSink {
		for _, arg := range n.ArgumentList {
			if src, isSrc := ctx.containsSource(arg); isSrc {
				lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
				ctx.Logger.VV("DOM: SINK DETECTED! %s() called with %s (line %d)", calleeName, src, lineNumber)
				ctx.AddFinding(models.DOMFinding{
					Source:      src,
					Sink:        calleeName,
					Line:        "AST Node",
					LineNumber:  lineNumber,
					Confidence:  "HIGH",
					Description: fmt.Sprintf("Direct flow: Source '%s' flows into Sink '%s'", src, calleeName),
					Evidence:    ctx.GetSnippet(n),
				})
			} else if id, ok := arg.(*ast.Identifier); ok {
				if src, ok := ctx.LookupTaint(string(id.Name)); ok {
					lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
					ctx.Logger.VV("DOM: SINK DETECTED! %s() called with tainted var '%s' from %s (line %d)", calleeName, string(id.Name), src, lineNumber)
					ctx.AddFinding(models.DOMFinding{
						Source:      src,
						Sink:        calleeName,
						Line:        "AST Node",
						LineNumber:  lineNumber,
						Confidence:  "HIGH",
						Description: fmt.Sprintf("Tainted variable '%s' (from %s) flows into Sink '%s'", string(id.Name), src, calleeName),
						Evidence:    ctx.GetSnippet(n),
					})
				}
			} else if dot, ok := arg.(*ast.DotExpression); ok {
				if id, ok := dot.Left.(*ast.Identifier); ok {
					if src, ok := ctx.LookupTaint(string(id.Name)); ok {
						lineNumber := ctx.Program.File.Position(int(n.Idx0())).Line
						ctx.Logger.VV("DOM: SINK DETECTED! %s() called with tainted var '%s' (property access) from %s (line %d)", calleeName, string(id.Name), src, lineNumber)
						ctx.AddFinding(models.DOMFinding{
							Source:      src,
							Sink:        calleeName,
							Line:        "AST Node",
							LineNumber:  lineNumber,
							Confidence:  "HIGH",
							Description: fmt.Sprintf("Tainted variable '%s' (property of %s) flows into Sink '%s'", string(dot.Identifier.Name), src, calleeName),
							Evidence:    ctx.GetSnippet(n),
						})
					}
				}
			}
		}
	}
}
