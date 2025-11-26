package tests

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/reflection"
)

func TestTagNameContext(t *testing.T) {
	body := "<PROBE>"
	ctx := reflection.DetectContext(body, "PROBE")
	if ctx != models.ContextTagName {
		t.Fatalf("expected ContextTagName, got %s", ctx)
	}
	payload := reflection.GetSuggestedPayload(ctx, []string{"<", ">", "=", " ", "/"})
	if payload == "" {
		t.Fatalf("expected a payload for TagName context")
	}
}

func TestRCDATAContextTitle(t *testing.T) {
	body := "<title>PROBE</title>"
	ctx := reflection.DetectContext(body, "PROBE")
	if ctx != models.ContextRCDATA {
		t.Fatalf("expected ContextRCDATA, got %s", ctx)
	}
	payload := reflection.GetSuggestedPayload(ctx, []string{"<", ">", "/"})
	if payload == "" {
		t.Fatalf("expected a payload for RCDATA context")
	}
}

func TestRCDATAContextTextarea(t *testing.T) {
	body := "<textarea>PROBE</textarea>"
	ctx := reflection.DetectContext(body, "PROBE")
	if ctx != models.ContextRCDATA {
		t.Fatalf("expected ContextRCDATA, got %s", ctx)
	}
	payload := reflection.GetSuggestedPayload(ctx, []string{"<", ">", "/"})
	if payload == "" {
		t.Fatalf("expected a payload for RCDATA context")
	}
}

func TestMissingContexts(t *testing.T) {
	// Test Meta Refresh
	t.Run("Meta Refresh", func(t *testing.T) {
		context := `<meta http-equiv="refresh" content="0;url=PROBE">`
		probe := "PROBE"
		ctx := reflection.DetectContext(context, probe)
		if ctx != models.ContextMetaRefresh {
			t.Errorf("Expected ContextMetaRefresh, got %s", ctx)
		}
		payload := reflection.GetSuggestedPayload(ctx, []string{"<", ">", "\"", "'", ";", ":", "/", "(", ")"})
		if payload != "javascript:alert(1)" {
			t.Errorf("Expected javascript:alert(1), got %s", payload)
		}
	})

	// Test Data URI
	t.Run("Data URI", func(t *testing.T) {
		context := `<a href="data:text/html;base64,PROBE">Click me</a>`
		probe := "PROBE"
		ctx := reflection.DetectContext(context, probe)
		if ctx != models.ContextDataURI {
			t.Errorf("Expected ContextDataURI, got %s", ctx)
		}
		payload := reflection.GetSuggestedPayload(ctx, []string{"<", ">", "\"", "'", ";", ":", "/", "(", ")"})
		if payload != "data:text/html,<script>alert(1)</script>" {
			t.Errorf("Expected data:text/html,<script>alert(1)</script>, got %s", payload)
		}
	})

	// Test SVG
	t.Run("SVG", func(t *testing.T) {
		context := `<svg><script>PROBE</script></svg>`
		probe := "PROBE"
		ctx := reflection.DetectContext(context, probe)
		// Note: DetectContext might return ContextHTML or ContextTagName depending on implementation details
		// But let's assume we want it to detect SVG context if specific SVG tags are present
		// Actually, <script> inside <svg> is just HTML/XML context essentially, or RCDATA.
		// Let's check what DetectContext actually does for SVG.
		// It checks isInSVG.
		if ctx != models.ContextSVG {
			t.Errorf("Expected ContextSVG, got %s", ctx)
		}
		payload := reflection.GetSuggestedPayload(ctx, []string{"<", ">", "\"", "'", ";", ":", "/", "(", ")"})
		if payload == "" {
			t.Error("Expected non-empty payload for SVG")
		}
	})
}
