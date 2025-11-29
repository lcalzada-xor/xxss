package technologies

import (
	"regexp"
)

// Signature defines the patterns to detect a specific technology
type Signature struct {
	Name            string   `json:"name"`
	FilePatterns    []string `json:"file_patterns"`
	ContentPatterns []string `json:"content_patterns"`

	// Compiled regexes
	fileRegexps    []*regexp.Regexp
	contentRegexps []*regexp.Regexp
}

// Compile compiles the regex patterns for the signature
func (s *Signature) Compile() error {
	for _, p := range s.FilePatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		s.fileRegexps = append(s.fileRegexps, re)
	}
	for _, p := range s.ContentPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		s.contentRegexps = append(s.contentRegexps, re)
	}
	return nil
}

// SignatureDetector is a generic detector that uses signatures
type SignatureDetector struct {
	Signatures []Signature
}

// NewSignatureDetector creates a new detector with the given signatures
func NewSignatureDetector(signatures []Signature) *SignatureDetector {
	for i := range signatures {
		_ = signatures[i].Compile()
	}
	return &SignatureDetector{
		Signatures: signatures,
	}
}

// DetectAll returns all detected technologies, not just the first one
func (d *SignatureDetector) DetectAll(body string) []*Technology {
	var detected []*Technology
	for _, sig := range d.Signatures {
		found := false

		// Check Content Patterns
		for _, pattern := range sig.contentRegexps {
			matches := pattern.FindStringSubmatch(body)
			if len(matches) > 0 {
				version := ""
				if len(matches) > 1 {
					version = matches[1]
				}
				detected = append(detected, &Technology{
					Name:       sig.Name,
					Version:    version,
					Confidence: "High",
				})
				found = true
				break
			}
		}
		if found {
			continue
		}

		// Check File Patterns
		for _, pattern := range sig.fileRegexps {
			if pattern.MatchString(body) {
				matches := pattern.FindStringSubmatch(body)
				version := ""
				if len(matches) > 1 {
					version = matches[1]
				}
				detected = append(detected, &Technology{
					Name:       sig.Name,
					Version:    version,
					Confidence: "Medium",
				})
				break
			}
		}
	}
	return detected
}
