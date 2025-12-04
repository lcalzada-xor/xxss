package technologies

import (
	"testing"
)

func TestNewSignatures(t *testing.T) {
	// Load signatures from the updated JSON file (via DefaultSignatures which reads the embedded file)
	// Since we modified the file on disk, we need to make sure the test reads it.
	// However, the production code uses //go:embed.
	// In a real scenario, changing the file on disk doesn't change the embedded content until recompilation.
	// BUT, for `go test`, if we run it in the directory, it might pick up the file if we load it manually for testing
	// OR we rely on the fact that `DefaultSignatures` reads `signaturesJSON`.
	// Since I cannot recompile the binary, I should probably manually load the JSON file in the test
	// to verify the *content* of the JSON file is correct, effectively testing the JSON structure and regexes.

	// Let's manually load the file for this test to be sure we are testing the new content.
	// We can reuse NewSignatureDetector but pass it signatures loaded from the file.

	// Wait, `DefaultSignatures` uses `json.Unmarshal(signaturesJSON, &signatures)`.
	// `signaturesJSON` is populated by `//go:embed signatures.json`.
	// If I run `go test`, `go` will recompile the test binary, which SHOULD include the updated `signatures.json`
	// because `go test` compiles the package.

	detector := NewSignatureDetector(DefaultSignatures())

	tests := []struct {
		name         string
		body         string
		expectedName string
		expectedVer  string
		shouldFind   bool
	}{
		// Axios
		{
			name:         "Axios File",
			body:         `<script src="axios.min.js"></script>`,
			expectedName: "Axios",
			shouldFind:   true,
		},
		{
			name:         "Axios Content",
			body:         `<script>/* axios v0.21.1 */</script>`,
			expectedName: "Axios",
			expectedVer:  "0.21.1",
			shouldFind:   true,
		},
		// Moment.js
		{
			name:         "Moment.js File",
			body:         `<script src="moment-2.29.1.min.js"></script>`,
			expectedName: "Moment.js",
			expectedVer:  "2.29.1",
			shouldFind:   true,
		},
		{
			name:         "Moment.js Content",
			body:         `<script>//! version : 2.29.1</script>`,
			expectedName: "Moment.js",
			expectedVer:  "2.29.1",
			shouldFind:   true,
		},
		// Chart.js
		{
			name:         "Chart.js File",
			body:         `<script src="chart.min.js"></script>`,
			expectedName: "Chart.js",
			shouldFind:   true,
		},
		// D3.js
		{
			name:         "D3.js File",
			body:         `<script src="d3.v6.min.js"></script>`,
			expectedName: "D3.js",
			expectedVer:  "6",
			shouldFind:   true,
		},
		// Three.js
		{
			name:         "Three.js File",
			body:         `<script src="three.min.js"></script>`,
			expectedName: "Three.js",
			shouldFind:   true,
		},
		// Socket.io
		{
			name:         "Socket.io File",
			body:         `<script src="/socket.io/socket.io.js"></script>`,
			expectedName: "Socket.io",
			shouldFind:   true,
		},
		// React Refinement
		{
			name:         "React.version",
			body:         `<script>React.version = "17.0.2";</script>`,
			expectedName: "React",
			expectedVer:  "17.0.2",
			shouldFind:   true,
		},
		// Vue Refinement
		{
			name:         "Vue.version",
			body:         `<script>Vue.version = "3.0.0";</script>`,
			expectedName: "Vue.js",
			expectedVer:  "3.0.0",
			shouldFind:   true,
		},
		// New Libraries Phase 1
		{
			name:         "DOMPurify",
			body:         `var DOMPurify = createDOMPurify(window);`,
			expectedName: "DOMPurify",
			shouldFind:   true,
		},
		{
			name:         "Showdown",
			body:         `var converter = new showdown.Converter();`,
			expectedName: "Showdown",
			shouldFind:   true,
		},
		{
			name:         "Marked",
			body:         `marked.parse("hello world");`,
			expectedName: "Marked",
			shouldFind:   true,
		},
		{
			name:         "sanitize-html",
			body:         `var clean = sanitizeHtml(dirty);`,
			expectedName: "sanitize-html",
			shouldFind:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			techs := detector.DetectAll(tt.body)
			found := false
			var tech *Technology

			// Find the expected tech in results
			for _, t := range techs {
				if t.Name == tt.expectedName {
					found = true
					tech = t
					break
				}
			}

			if found != tt.shouldFind {
				t.Errorf("DetectAll() found %s = %v, want %v", tt.expectedName, found, tt.shouldFind)
			}
			if found && tech != nil {
				if tt.expectedVer != "" && tech.Version != tt.expectedVer {
					t.Errorf("DetectAll() Version = %v, want %v", tech.Version, tt.expectedVer)
				}
			}
		})
	}
}
