package dom

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
)

func TestDOMScanner_Extended(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{
			name: "postMessage: event.data to innerHTML",
			body: `
			<script>
				window.addEventListener("message", function(e) {
					document.getElementById("out").innerHTML = e.data;
				});
			</script>
			`,
			expected: 2, // 1 for sink, 1 for missing origin check
		},
		{
			name: "postMessage: event.data to innerHTML (Arrow Function)",
			body: `
			<script>
				window.addEventListener("message", (e) => {
					document.body.innerHTML = e.data;
				});
			</script>
			`,
			expected: 2, // 1 for sink, 1 for missing origin check
		},
		{
			name: "postMessage: Safe usage (console.log)",
			body: `
			<script>
				window.addEventListener("message", function(e) {
					console.log(e.data);
				});
			</script>
			`,
			expected: 1, // 1 for missing origin check
		},
		{
			name: "React: dangerouslySetInnerHTML",
			body: `
			<script>
				var user_input = location.search;
				var element = {
					dangerouslySetInnerHTML: {
						__html: user_input
					}
				};
			</script>
			`,
			expected: 1,
		},
		{
			name: "AngularJS: $compile",
			body: `
			<script>
				var input = location.hash;
				$compile(input)(scope);
			</script>
			`,
			expected: 1,
		},
		{
			name: "AngularJS: $sce.trustAsHtml",
			body: `
			<script>
				var html = location.search;
				$sce.trustAsHtml(html);
			</script>
			`,
			expected: 1,
		},
		{
			name: "Bare addEventListener (no window prefix)",
			body: `
			<script>
				addEventListener("message", function(e) {
					document.write(e.data);
				});
			</script>
			`,
			expected: 2, // 1 for sink, 1 for missing origin check
		},
		{
			name:     "HTML Event Handler: onerror",
			body:     `<img src=x onerror="document.write(location.search)">`,
			expected: 1,
		},
		{
			name:     "HTML Event Handler: onload",
			body:     `<body onload="var x = location.hash; eval(x)">`,
			expected: 1,
		},
		{
			name:     "Framework Directive: v-html",
			body:     `<div v-html="location.search"></div>`,
			expected: 1,
		},
		{
			name:     "Framework Directive: ng-bind-html",
			body:     `<div ng-bind-html="document.cookie"></div>`,
			expected: 1,
		},
		{
			name:     "New Source: document.baseURI",
			body:     `<script>document.write(document.baseURI)</script>`,
			expected: 1,
		},
		{
			name:     "New Sink: range.createContextualFragment",
			body:     `<script>document.createRange().createContextualFragment(location.search)</script>`,
			expected: 1,
		},
		{
			name:     "Protocol: javascript: in href",
			body:     `<a href="javascript:alert(1)">Click me</a>`,
			expected: 1,
		},
		{
			name:     "DOM Clobbering: Global Variable Shadowing",
			body:     `<a id="config"></a><script>if(window.config) { eval(config.xss) }</script>`,
			expected: 1, // Should detect clobbering
		},
		{
			name:     "postMessage: Missing Origin Check",
			body:     `<script>window.addEventListener("message", function(e) { eval(e.data); });</script>`,
			expected: 2, // 1 for sink, 1 for missing origin check
		},
		{
			name:     "postMessage: With Origin Check",
			body:     `<script>window.addEventListener("message", function(e) { if (e.origin === "https://trusted.com") { eval(e.data); } });</script>`,
			expected: 1, // 1 for sink (still a sink, but origin check found) -> Actually, we might want to flag sink anyway, but missing origin check should NOT be flagged.
			// Wait, if origin check is present, we still flag the sink usage? Yes, usually.
			// But we shouldn't flag "Missing Origin Validation".
			// So expected is 1 (the eval sink).
		},
		{
			name:     "Web Worker: importScripts",
			body:     `<script>importScripts(location.search)</script>`,
			expected: 1,
		},
	}

	ds := NewDOMScanner(logger.NewLogger(3))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ds.ScanDOM(tt.body)
			if len(findings) != tt.expected {
				t.Errorf("ScanDOM() = %d findings, want %d", len(findings), tt.expected)
				for i, f := range findings {
					t.Logf("Finding %d: %s -> %s", i, f.Source, f.Sink)
				}
			}
		})
	}
}
