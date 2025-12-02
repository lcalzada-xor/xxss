package analysis

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func TestAnalyzeJavaScriptContext_ScriptBreakout(t *testing.T) {
	// Simulate the lab scenario where the probe breaks the script block
	// The regex-based approach failed here because it looked for <script>...probe...</script>
	// But the probe contains </script>, so the regex matched <script>...probe... (partial)

	context := `
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <script>
                        var searchTerms = '</script><img src=x onerror=alert(1)>';
                        document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
                    </script>
`
	probe := "</script><img src=x onerror=alert(1)>"

	isJS, jsContext := analyzeJavaScriptContext(context, probe, -1)

	if !isJS {
		t.Errorf("Expected isJS to be true, got false")
	}

	if jsContext != models.ContextJSSingleQuote {
		t.Errorf("Expected context to be ContextJSSingleQuote, got %s", jsContext)
	}
}
