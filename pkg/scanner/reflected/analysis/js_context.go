package analysis

import (
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"golang.org/x/net/html"
)

func analyzeJavaScriptContext(context, probe string, probeIndex int) (bool, models.ReflectionContext) {
	// Check if we are inside <script> tags
	// We use a more robust approach than regex to handle cases where the probe itself
	// contains </script> (breaking the block).
	// We look backwards from the probe to find the last <script> tag.
	// probeIndex is passed directly to avoid finding the wrong probe occurrence.

	if probeIndex == -1 {
		probeIndex = strings.Index(context, probe)
	}

	if probeIndex != -1 {
		before := context[:probeIndex]
		beforeLower := strings.ToLower(before)
		lastScriptStart := strings.LastIndex(beforeLower, "<script")
		lastScriptEnd := strings.LastIndex(beforeLower, "</script")

		// If we found a <script> start, and it's after the last </script> end (or there is no end),
		// then we are likely inside a script block.
		if lastScriptStart != -1 && lastScriptStart > lastScriptEnd {
			// We are inside a script tag.
			// To use the lexer, we need the content of the script.
			// We find the end of the opening <script> tag.
			scriptTagEnd := strings.Index(before[lastScriptStart:], ">")
			if scriptTagEnd != -1 {
				// The script content starts after the opening tag
				scriptContentStart := lastScriptStart + scriptTagEnd + 1
				// We pass the content from the start of the script block to the lexer.
				// The lexer will find the probe inside it.
				return analyzeJSContextWithLexer(context[scriptContentStart:], probe)
			}
		}
	}

	// Check for inline event handlers (onclick, onload, etc.)
	// We use html.ParseFragment to robustly parse the tag, handling malformed/truncated HTML.

	if probeIndex == -1 {
		return false, models.ContextUnknown
	}

	before := context[:probeIndex]
	lastTagStart := strings.LastIndex(before, "<")
	if lastTagStart == -1 {
		return false, models.ContextUnknown
	}

	// Check if we are inside a tag (no closing > after <)
	// Actually, if the tag is incomplete (truncated), we might not have a closing >.
	// But we should ensure we are not just seeing a random < in text.
	// The heuristic "no > after <" implies we are inside the tag definition.
	if strings.LastIndex(before, ">") > lastTagStart {
		return false, models.ContextUnknown
	}

	// We attempt to parse the fragment starting from the tag start.
	// We use a dummy body context (nil defaults to body context).
	fragment := context[lastTagStart:]

	// Heuristic: if the fragment doesn't end with '>', append one to help the parser
	// handle truncated tags. We append ">" to try to close any open attribute quote as well.
	if !strings.HasSuffix(strings.TrimSpace(fragment), ">") {
		fragment += "\">"
	}

	nodes, err := html.ParseFragment(strings.NewReader(fragment), nil)
	if err != nil {
		return false, models.ContextUnknown
	}

	// Traverse the nodes to find the attribute containing the probe
	var found bool
	var resultCtx models.ReflectionContext
	var isJS bool

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if found {
			return
		}
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				if strings.HasPrefix(strings.ToLower(attr.Key), "on") {
					if strings.Contains(attr.Val, probe) {
						// Found it!
						isJS, resultCtx = analyzeJSContextWithLexer(attr.Val, probe)
						found = true
						return
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	for _, n := range nodes {
		traverse(n)
		if found {
			return isJS, resultCtx
		}
	}

	return false, models.ContextUnknown
}

func isInTemplateLiteral(context, probe string) bool {
	// Replaced by lexer logic, but kept for compatibility if needed by other files?
	// No, `context.go` calls `analyzeJavaScriptContext`.
	// But `context.go` also calls `isInTemplateLiteral` directly!
	// We should update `context.go` to remove direct call to `isInTemplateLiteral`
	// and let `analyzeJavaScriptContext` handle it, OR update this function to use lexer.

	// Since `context.go` checks `isInTemplateLiteral` *before* `analyzeJavaScriptContext`,
	// we should update this function to use the lexer too, or better yet,
	// remove the separate check in `context.go` and let `analyzeJavaScriptContext` handle it.
	// But `context.go` is in another file.

	// For now, let's make this function use the lexer.
	isJS, ctx := analyzeJSContextWithLexer(context, probe)
	return isJS && ctx == models.ContextTemplateLiteral
}
