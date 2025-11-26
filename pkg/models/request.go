package models

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type HTTPMethod string

const (
	MethodGET   HTTPMethod = "GET"
	MethodPOST  HTTPMethod = "POST"
	MethodPUT   HTTPMethod = "PUT"
	MethodPATCH HTTPMethod = "PATCH"
)

type ContentType string

const (
	ContentTypeForm ContentType = "application/x-www-form-urlencoded"
	ContentTypeJSON ContentType = "application/json"
)

type RequestConfig struct {
	Method      HTTPMethod        `json:"method"`
	URL         string            `json:"url"`
	Body        string            `json:"body,omitempty"`
	ContentType ContentType       `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// Validate checks if the request configuration is valid.
func (r *RequestConfig) Validate() error {
	if r.URL == "" {
		return fmt.Errorf("URL is required")
	}
	if _, err := url.Parse(r.URL); err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	if r.Method != "" {
		switch r.Method {
		case MethodGET, MethodPOST, MethodPUT, MethodPATCH:
			// Valid
		default:
			return fmt.Errorf("invalid HTTP method: %s", r.Method)
		}
	}

	return nil
}

// ParseFromString parses various input formats:
// - Simple URL: "http://example.com/?p=test" (GET)
// - With method: "POST http://example.com/" --data "p=test"
// - JSON format: {"method":"POST","url":"...","body":"..."}
func ParseFromString(input string) (*RequestConfig, error) {
	input = strings.TrimSpace(input)

	// Try JSON format first
	if strings.HasPrefix(input, "{") {
		var config RequestConfig
		if err := json.Unmarshal([]byte(input), &config); err == nil {
			// Set defaults
			if config.Method == "" {
				config.Method = MethodGET
			}
			if config.ContentType == "" && config.Body != "" {
				config.ContentType = ContentTypeForm
			}
			return &config, nil
		}
	}

	// Parse simple URL format
	parts := strings.Fields(input)

	config := &RequestConfig{
		Method:  MethodGET,
		Headers: make(map[string]string),
	}

	// Check if first part is HTTP method
	if len(parts) > 1 {
		method := strings.ToUpper(parts[0])
		if method == "GET" || method == "POST" || method == "PUT" || method == "PATCH" {
			config.Method = HTTPMethod(method)
			config.URL = parts[1]
		} else {
			config.URL = parts[0]
		}
	} else if len(parts) == 1 {
		config.URL = parts[0]
	} else {
		return nil, fmt.Errorf("invalid input format")
	}

	// Validate URL
	if _, err := url.Parse(config.URL); err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	return config, nil
}
