package models

// Result represents the findings of an XSS scan for a specific URL and parameter.
type Result struct {
	URL         string   `json:"url"`
	Parameter   string   `json:"parameter"`
	Reflected   bool     `json:"reflected"`
	Unfiltered  []string `json:"unfiltered"` // Characters that were reflected without encoding
}
