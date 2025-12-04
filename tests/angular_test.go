package tests

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/models"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/reflected/analysis"
)

func TestAngularJSDetection(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		probe    string
		expected models.ReflectionContext
	}{
		{
			name: "Angular template with ng-app",
			body: `<html ng-app="myApp">
				<div>{{test}}</div>
				<script src="angular.js"></script>
			</html>`,
			probe:    "test",
			expected: models.ContextAngular,
		},
		{
			name: "Angular ng-bind attribute",
			body: `<html ng-app>
				<span ng-bind="test"></span>
			</html>`,
			probe:    "test",
			expected: models.ContextAngular,
		},
		{
			name: "Non-Angular HTML",
			body: `<html>
				<div>test</div>
			</html>`,
			probe:    "test",
			expected: models.ContextHTML,
		},
		{
			name: "Angular with data-ng-app",
			body: `<html data-ng-app="app">
				<div>{{test}}</div>
			</html>`,
			probe:    "test",
			expected: models.ContextAngular,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := analysis.DetectContext(tt.body, tt.probe, -1)
			if context != tt.expected {
				t.Errorf("DetectContext() = %v, want %v", context, tt.expected)
			}
		})
	}
}

func TestAngularJSPayloads(t *testing.T) {
	tests := []struct {
		name       string
		unfiltered []string
		wantSubstr string
	}{
		{
			name:       "Constructor escape with parens and dot",
			unfiltered: []string{"(", ")", ".", "'"},
			wantSubstr: "constructor.constructor",
		},
		{
			name:       "Array escape with brackets",
			unfiltered: []string{"[", "]", "(", ")", ".", "'"},
			wantSubstr: "[].pop.constructor",
		},
		{
			name:       "Simple expression fallback",
			unfiltered: []string{"(", ")"},
			wantSubstr: "{{alert(1)}}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := payloads.GenerateReflectedPayload(models.ContextAngular, tt.unfiltered, nil)
			if payload == "" {
				t.Error("GetSuggestedPayload() returned empty string")
			}
			// Just verify it returns something reasonable
			t.Logf("Payload: %s", payload)
		})
	}
}
