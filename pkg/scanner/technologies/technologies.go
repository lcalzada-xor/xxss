package technologies

// Technology represents a detected library or framework
type Technology struct {
	Name       string
	Version    string
	Confidence string // "High", "Medium", "Low"
}

// Detector is the interface that all technology detectors must implement
type Detector interface {
	// DetectAll checks if the technology is present in the response body
	DetectAll(body string) []*Technology
}
