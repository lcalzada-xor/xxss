package dom

import (
	"regexp"
	"testing"
)

func TestSourcePatterns(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		match   bool
		pattern string
	}{
		{"Location Search", "var x = location.search", true, `location\.search`},
		{"Location Hash", "eval(location.hash)", true, `location\.hash`},
		{"Document Cookie", "document.cookie", true, `document\.cookie`},
		{"Safe String", "var x = 'location.search'", true, `location\.search`}, // Regex matches string content too, context analysis handles false positives
		{"No Match", "var x = location.safe", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			for _, p := range sourcePatterns {
				re := regexp.MustCompile(p)
				if re.MatchString(tc.input) {
					matched = true
					if tc.match && p != tc.pattern && tc.pattern != "" {
						// Matched a different pattern than expected?
						// For now just check if it matched at all if we expect a match
					}
					break
				}
			}
			if matched != tc.match {
				t.Errorf("Expected match=%v for input '%s', got match=%v", tc.match, tc.input, matched)
			}
		})
	}
}

func TestSinkPatterns(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		match   bool
		pattern string
	}{
		{"Eval", "eval(x)", true, `eval\(`},
		{"InnerHTML", "el.innerHTML = x", true, `innerHTML`},
		{"Document Write", "document.write(x)", true, `document\.write\(`},
		{"Navigation API", "navigation.navigate(url)", true, `navigation\.navigate\(`},
		{"Javascript Protocol", "a.href = 'javascript:alert(1)'", true, `javascript:`},
		{"Safe Method", "document.writesafe(x)", false, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			for _, p := range sinkPatterns {
				re := regexp.MustCompile(p)
				if re.MatchString(tc.input) {
					matched = true
					break
				}
			}
			if matched != tc.match {
				t.Errorf("Expected match=%v for input '%s', got match=%v", tc.match, tc.input, matched)
			}
		})
	}
}
