package tests

import (
	"testing"

	"github.com/lcalzada-xor/xxss/models"
	"github.com/lcalzada-xor/xxss/scanner"
)

func TestTagNameContext(t *testing.T) {
	body := "<PROBE>"
	ctx := scanner.DetectContext(body, "PROBE")
	if ctx != models.ContextTagName {
		t.Fatalf("expected ContextTagName, got %s", ctx)
	}
	payload := scanner.GetSuggestedPayload(ctx, []string{"<", ">", "=", " ", "/"})
	if payload == "" {
		t.Fatalf("expected a payload for TagName context")
	}
}

func TestRCDATAContextTitle(t *testing.T) {
	body := "<title>PROBE</title>"
	ctx := scanner.DetectContext(body, "PROBE")
	if ctx != models.ContextRCDATA {
		t.Fatalf("expected ContextRCDATA, got %s", ctx)
	}
	payload := scanner.GetSuggestedPayload(ctx, []string{"<", ">", "/"})
	if payload == "" {
		t.Fatalf("expected a payload for RCDATA context")
	}
}

func TestRCDATAContextTextarea(t *testing.T) {
	body := "<textarea>PROBE</textarea>"
	ctx := scanner.DetectContext(body, "PROBE")
	if ctx != models.ContextRCDATA {
		t.Fatalf("expected ContextRCDATA, got %s", ctx)
	}
	payload := scanner.GetSuggestedPayload(ctx, []string{"<", ">", "/"})
	if payload == "" {
		t.Fatalf("expected a payload for RCDATA context")
	}
}
