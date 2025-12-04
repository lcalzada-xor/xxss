package payloads

import (
	"github.com/lcalzada-xor/xxss/v3/pkg/models"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/technologies"
)

// GenerationOptions defines the parameters for payload generation
type GenerationOptions struct {
	AllowedChars []string
	CallbackURL  string
	Technologies []*technologies.Technology
}

// PayloadGenerator defines the interface for generating payloads
type PayloadGenerator interface {
	Generate(context models.ReflectionContext, options GenerationOptions) []string
}

// DefaultGenerator is the default implementation of PayloadGenerator
type DefaultGenerator struct{}

// Generate dispatches to the appropriate generation logic based on the options
func (g *DefaultGenerator) Generate(context models.ReflectionContext, options GenerationOptions) []string {
	if options.CallbackURL != "" {
		return BlindPayloadsForContext(options.CallbackURL, context)
	}
	// For reflected, we currently return a single payload, but the interface supports multiple
	payload := GenerateReflectedPayload(context, options.AllowedChars, options.Technologies)
	if payload != "" {
		return []string{payload}
	}
	return []string{}
}
