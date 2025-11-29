package technologies

import (
	"testing"
)

func TestSignatureDetector(t *testing.T) {
	signatures := []Signature{
		{
			Name: "jQuery",
			FilePatterns: []string{
				`jquery[.-]([\d\.]+)(?:\.min)?\.js`,
			},
			ContentPatterns: []string{
				`jQuery v([\d\.]+)`,
			},
		},
		{
			Name: "React",
			FilePatterns: []string{
				`react(?:-dom)?[\.-]([\d\.]+)(?:\.min)?\.js`,
			},
			ContentPatterns: []string{
				`React v([\d\.]+)`,
			},
		},
		{
			Name: "Vue.js",
			FilePatterns: []string{
				`vue[\.-]([\d\.]+)(?:\.min)?\.js`,
				`vue\.min\.js`,
			},
			ContentPatterns: []string{
				`Vue\.js v([\d\.]+)`,
			},
		},
		{
			Name: "Bootstrap",
			FilePatterns: []string{
				`bootstrap[.-]([\d\.]+)(?:\.min)?\.js`,
			},
			ContentPatterns: []string{
				`Bootstrap v([\d\.]+)`,
			},
		},
	}
	detector := NewSignatureDetector(signatures)

	tests := []struct {
		name         string
		body         string
		expectedName string
		expectedVer  string
		shouldFind   bool
	}{
		{
			name:         "jQuery Script Src",
			body:         `<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>`,
			expectedName: "jQuery",
			expectedVer:  "3.5.1",
			shouldFind:   true,
		},
		{
			name:         "React Content",
			body:         `<script>console.log("React v16.8.0");</script>`,
			expectedName: "React",
			expectedVer:  "16.8.0",
			shouldFind:   true,
		},
		{
			name:         "Vue.js Script Src",
			body:         `<script src="/js/vue.min.js"></script>`,
			expectedName: "Vue.js",
			expectedVer:  "",
			shouldFind:   true,
		},
		{
			name:         "Bootstrap Content",
			body:         `/*! Bootstrap v4.5.0 */`,
			expectedName: "Bootstrap",
			expectedVer:  "4.5.0",
			shouldFind:   true,
		},
		{
			name:       "Unknown Library",
			body:       `<script src="unknown.js"></script>`,
			shouldFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			techs := detector.DetectAll(tt.body)
			found := len(techs) > 0
			var tech *Technology
			if found {
				tech = techs[0]
			}

			if found != tt.shouldFind {
				t.Errorf("DetectAll() found = %v, want %v", found, tt.shouldFind)
			}
			if found && tech != nil {
				if tech.Name != tt.expectedName {
					t.Errorf("DetectAll() Name = %v, want %v", tech.Name, tt.expectedName)
				}
				if tech.Version != tt.expectedVer {
					t.Errorf("DetectAll() Version = %v, want %v", tech.Version, tt.expectedVer)
				}
			}
		})
	}
}

func TestManager_DetectAll(t *testing.T) {
	manager := NewManager()

	body := `
		<html>
			<script src="angular.js"></script>
			<script src="jquery-3.5.1.min.js"></script>
		</html>
	`

	techs := manager.DetectAll(body)

	if len(techs) != 2 {
		t.Errorf("DetectAll() found %d technologies, want 2", len(techs))
	}

	foundAngular := false
	foundJQuery := false

	for _, tech := range techs {
		if tech.Name == "AngularJS" {
			foundAngular = true
		}
		if tech.Name == "jQuery" {
			foundJQuery = true
		}
	}

	if !foundAngular {
		t.Error("DetectAll() did not find AngularJS")
	}
	if !foundJQuery {
		t.Error("DetectAll() did not find jQuery")
	}
}
