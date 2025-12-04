package analysis

import (
	"regexp"
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
)

func TestBootstrapFalsePositives(t *testing.T) {
	tests := []struct {
		name               string
		code               string
		shouldFind         bool
		expectedConfidence string
	}{
		{
			name:       "Bootstrap 3.3.7 Style - jQuery.fn assignment",
			code:       `+function ($) { "use strict"; $.fn.modal = function (option) { } }(jQuery);`,
			shouldFind: false,
		},
		{
			name:       "Direct Prototype Assignment - Safe",
			code:       `jQuery.prototype.modal = function() {};`,
			shouldFind: false,
		},
		{
			name:       "Constructor Prototype Assignment - Safe",
			code:       `MyClass.prototype.init = function() {};`,
			shouldFind: false,
		},
		{
			name:               "Unsafe __proto__ Assignment - Static",
			code:               `var x = {}; x.__proto__.polluted = "true";`,
			shouldFind:         true,
			expectedConfidence: "LOW",
		},
		{
			name:               "Unsafe __proto__ Assignment - Dynamic",
			code:               `var x = {}; x.__proto__.polluted = location.hash;`,
			shouldFind:         true,
			expectedConfidence: "HIGH",
		},
		{
			name: "Bootstrap Real Snippet",
			code: `
            +function ($) {
              'use strict';
            
              // MODAL CLASS DEFINITION
              // ======================
            
              var Modal = function (element, options) {
                this.options             = options
                this.$body               = $(document.body)
                this.$element            = $(element)
                this.$dialog             = this.$element.find('.modal-dialog')
                this.isShown             = null
                this.scrollbarWidth      = 0
                this.usePp               = false
                this.ignoreBackdropClick = false
              }
            
              Modal.VERSION  = '3.3.7'
            
              Modal.TRANSITION_DURATION = 300
              Modal.BACKDROP_TRANSITION_DURATION = 150
            
              Modal.DEFAULTS = {
                backdrop: true,
                keyboard: true,
                show: true
              }
            
              Modal.prototype.toggle = function (_relatedTarget) {
                return this.isShown ? this.hide() : this.show(_relatedTarget)
              }
            }(jQuery);
            `,
			shouldFind: false,
		},
		{
			name:       "Prototype Overwrite - Static",
			code:       `MyClass.prototype = { method: function() {} };`,
			shouldFind: false,
		},
	}

	sources := []*regexp.Regexp{
		regexp.MustCompile(`location\..*`),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, _ := AnalyzeJS(tt.code, sources, nil, logger.NewLogger(0))

			found := false
			var foundConfidence string
			for _, f := range findings {
				if f.Sink == "Prototype Pollution" {
					found = true
					foundConfidence = f.Confidence
				}
			}

			if tt.shouldFind && !found {
				t.Errorf("Expected finding for %s, but got none", tt.name)
			}
			if !tt.shouldFind && found {
				t.Errorf("Unexpected finding for %s (Confidence: %s)", tt.name, foundConfidence)
			}
			if tt.shouldFind && found && tt.expectedConfidence != "" {
				if foundConfidence != tt.expectedConfidence {
					t.Errorf("Expected confidence %s, got %s", tt.expectedConfidence, foundConfidence)
				}
			}
		})
	}
}
