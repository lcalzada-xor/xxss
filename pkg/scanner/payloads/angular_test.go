package payloads

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func TestAngularPayloadGeneration(t *testing.T) {
	// Simulate allowed chars: . ( ) ' { }
	// Missing < > "
	allowed := []string{".", "(", ")", "'", "{", "}", "$"}

	payload := GenerateReflectedPayload(models.ContextAngular, allowed, nil)
	expected := "{{$on.constructor('alert(1)')()}}"

	if payload != expected {
		t.Errorf("Expected payload %s, got %s", expected, payload)
	}
}
