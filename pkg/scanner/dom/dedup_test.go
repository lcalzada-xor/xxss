package dom

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func TestDeduplicateFindings(t *testing.T) {
	findings := []models.DOMFinding{
		{
			Source:      "source1",
			Sink:        "sink1",
			Description: "desc1",
		},
		{
			Source:      "source1",
			Sink:        "sink1",
			Description: "desc1",
		},
		{
			Source:      "source2",
			Sink:        "sink2",
			Description: "desc2",
		},
	}

	unique := deduplicateFindings(findings)

	if len(unique) != 2 {
		t.Errorf("Expected 2 unique findings, got %d", len(unique))
	}

	if unique[0].Source != "source1" || unique[1].Source != "source2" {
		t.Errorf("Unexpected findings order or content")
	}
}
