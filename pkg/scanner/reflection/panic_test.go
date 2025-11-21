package reflection

import (
	"testing"

	"github.com/lcalzada-xor/xxss/pkg/models"
)

func TestPanicReproduction(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		probe   string
		context models.ReflectionContext
	}{
		{
			name:    "URL context without tag start",
			body:    `href="probe"`,
			probe:   "probe",
			context: models.ContextHTML, // Should fallback safely, not panic
		},
		{
			name:    "CSS context without tag start",
			body:    `style="probe"`,
			probe:   "probe",
			context: models.ContextHTML, // Should fallback safely, not panic
		},
		{
			name:    "JS context without tag start",
			body:    `onclick="probe"`,
			probe:   "probe",
			context: models.ContextHTML, // Should fallback safely, not panic
		},
		{
			name:    "Attribute context without tag start",
			body:    `attr="probe"`,
			probe:   "probe",
			context: models.ContextHTML, // Should fallback safely, not panic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("The code panicked: %v", r)
				}
			}()

			DetectContext(tt.body, tt.probe)
		})
	}
}
