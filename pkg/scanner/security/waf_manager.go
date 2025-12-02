package security

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
)

// WAFSignature represents a single WAF detection signature
type WAFSignature struct {
	Name           string              `json:"name"`
	Headers        map[string]string   `json:"headers,omitempty"`         // Exact header key/value match (value can be empty for key existence)
	HeaderPatterns map[string][]string `json:"header_patterns,omitempty"` // Header key to list of value substrings
	BodyPatterns   []string            `json:"body_patterns,omitempty"`   // Substrings to find in body
}

// WAFManager handles WAF detection logic
type WAFManager struct {
	signatures []WAFSignature
}

//go:embed waf_signatures.json
var defaultSignatures []byte

// NewWAFManager creates a new manager and loads signatures
func NewWAFManager() (*WAFManager, error) {
	var sigs []WAFSignature
	if err := json.Unmarshal(defaultSignatures, &sigs); err != nil {
		return nil, err
	}
	return &WAFManager{signatures: sigs}, nil
}

// Detect checks for WAF presence in the response
func (m *WAFManager) Detect(headers http.Header, body string) *WAF {
	for _, sig := range m.signatures {
		// 1. Check Exact Headers
		for key, val := range sig.Headers {
			headerVal := headers.Get(key)
			if headerVal != "" {
				if val == "" || strings.Contains(strings.ToLower(headerVal), strings.ToLower(val)) {
					return &WAF{Name: sig.Name, Detected: true}
				}
			}
		}

		// 2. Check Header Patterns
		for key, patterns := range sig.HeaderPatterns {
			headerVal := headers.Get(key)
			if headerVal != "" {
				lowerVal := strings.ToLower(headerVal)
				for _, pattern := range patterns {
					if strings.Contains(lowerVal, strings.ToLower(pattern)) {
						return &WAF{Name: sig.Name, Detected: true}
					}
				}
			}
		}

		// 3. Check Body Patterns
		for _, pattern := range sig.BodyPatterns {
			if strings.Contains(body, pattern) {
				return &WAF{Name: sig.Name, Detected: true}
			}
		}
	}

	return &WAF{Name: "", Detected: false}
}
