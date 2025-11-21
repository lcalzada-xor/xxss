package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lcalzada-xor/xxss/pkg/models"
	"github.com/lcalzada-xor/xxss/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/pkg/scanner/reflection"
)

// VulnerableHeaders is the list of common HTTP headers that can be vulnerable to XSS
var VulnerableHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Forwarded-Host",
	"X-Original-URL",
	"Accept-Language",
}

// ScanRequest performs XSS scan on POST/PUT/PATCH requests with body parameters
func (s *Scanner) ScanRequest(config *models.RequestConfig) ([]models.Result, error) {
	results := []models.Result{}

	// 1. Parse body parameters
	params := s.parseBodyParams(config.Body, string(config.ContentType))
	if len(params) == 0 {
		return results, nil
	}

	// 2. Baseline check: see which parameters are reflected
	reflectedParams := s.checkBodyReflection(config, params)

	// 3. Scan Body Parameters
	if config.Method == "POST" || config.Method == "PUT" || config.Method == "PATCH" {
		for _, param := range reflectedParams {
			result, err := s.probeBodyParameter(config, param, params)
			if err != nil {
				continue
			}

			// Contextual Blind XSS Injection (after context detection)
			if s.blindURL != "" && result.Context != models.ContextUnknown {
				s.injectContextualBlindBody(config, param, params, result.Context)
			}

			if len(result.Unfiltered) > 0 {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

func (s *Scanner) parseBodyParams(body, contentType string) map[string]string {
	params := make(map[string]string)
	if contentType == "application/json" {
		// Simple JSON parser (flat key-value for now)
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(body), &data); err == nil {
			for k, v := range data {
				if strVal, ok := v.(string); ok {
					params[k] = strVal
				}
			}
		} else {
			fmt.Printf("JSON Unmarshal error: %v\n", err)
		}
	} else {
		// Assume form-urlencoded
		values, err := url.ParseQuery(body)
		if err == nil {
			for k, v := range values {
				if len(v) > 0 {
					params[k] = v[0]
				}
			}
		}
	}
	return params
}

func (s *Scanner) checkBodyReflection(config *models.RequestConfig, params map[string]string) []string {
	reflected := []string{}

	for key := range params {
		// Create a copy of params for this test
		testParams := make(map[string]string)
		for k, v := range params {
			testParams[k] = v
		}

		probe := fmt.Sprintf("xxss_%d", time.Now().UnixNano())
		testParams[key] = probe

		// Build request body
		var body string
		if config.ContentType == "application/json" {
			// Reconstruct JSON (simplified)
			pairs := []string{}
			for k, v := range testParams {
				pairs = append(pairs, fmt.Sprintf(`"%s":"%s"`, k, v))
			}
			body = "{" + strings.Join(pairs, ",") + "}"
		} else {
			// Reconstruct form-urlencoded
			v := url.Values{}
			for k, val := range testParams {
				v.Set(k, val)
			}
			body = v.Encode()
		}

		req, err := http.NewRequest(string(config.Method), config.URL, strings.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", string(config.ContentType))
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}

		resp, err := s.client.Do(req)
		s.requestMutex.Lock()
		s.requestCount++
		s.requestMutex.Unlock()
		if err != nil {
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		respBody := string(bodyBytes)

		if strings.Contains(respBody, probe) {
			reflected = append(reflected, key)
		}
	}

	return reflected
}

func (s *Scanner) probeBodyParameter(config *models.RequestConfig, param string, params map[string]string) (models.Result, error) {
	val := params[param]
	probeStr := "xssprobe"
	payload := val + probeStr + strings.Join(reflection.SpecialChars, "") + probeStr

	// Create a copy of params with payload
	testParams := make(map[string]string)
	for k, v := range params {
		testParams[k] = v
	}
	testParams[param] = payload

	// Build request body
	var body string
	if config.ContentType == "application/json" {
		// Reconstruct JSON properly using Marshal to handle escaping
		jsonBytes, err := json.Marshal(testParams)
		if err != nil {
			return models.Result{}, err
		}
		body = string(jsonBytes)
	} else {
		// Reconstruct form-urlencoded
		if s.useRawPayload {
			// Manual construction to avoid encoding
			parts := []string{}
			for k, v := range testParams {
				parts = append(parts, k+"="+v)
			}
			body = strings.Join(parts, "&")
		} else {
			v := url.Values{}
			for k, val := range testParams {
				v.Set(k, val)
			}
			body = v.Encode()
		}
	}

	req, err := http.NewRequest(string(config.Method), config.URL, strings.NewReader(body))
	if err != nil {
		return models.Result{}, err
	}
	req.Header.Set("Content-Type", string(config.ContentType))
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	s.requestMutex.Lock()
	s.requestCount++
	s.requestMutex.Unlock()
	if err != nil {
		return models.Result{}, err
	}

	return s.AnalyzeReflection(config.URL, string(config.Method), param, models.InjectionBody, resp, probeStr)
}

// ScanHeader checks for XSS in a specific HTTP header
func (s *Scanner) ScanHeader(targetURL, header string) (models.Result, error) {
	// Blind XSS Injection
	if s.blindURL != "" {
		payloads.InjectBlindHeader(s.client, s.headers, targetURL, header, s.blindURL, s.verbose)
	}

	// 1. Check if header is reflected
	probe := fmt.Sprintf("xxss_%d", time.Now().UnixNano())

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return models.Result{}, err
	}

	req.Header.Set(header, probe)
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add custom headers
	for k, v := range s.headers {
		if k != header {
			req.Header.Set(k, v)
		}
	}

	resp, err := s.client.Do(req)
	s.requestMutex.Lock()
	s.requestCount++
	s.requestMutex.Unlock()
	if err != nil {
		return models.Result{}, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return models.Result{}, err
	}
	body := string(bodyBytes)

	if !strings.Contains(body, probe) {
		return models.Result{}, fmt.Errorf("header not reflected")
	}

	// 2. Probe with XSS payload
	probeStr := "xssprobe"
	payload := probeStr + strings.Join(reflection.SpecialChars, "") + probeStr

	req2, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return models.Result{}, err
	}

	req2.Header.Set(header, payload)
	req2.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add custom headers
	for k, v := range s.headers {
		if k != header {
			req2.Header.Set(k, v)
		}
	}

	resp2, err := s.client.Do(req2)
	s.requestMutex.Lock()
	s.requestCount++
	s.requestMutex.Unlock()
	if err != nil {
		return models.Result{}, err
	}
	// Analyze reflection using shared method
	return s.AnalyzeReflection(targetURL, "GET", header, models.InjectionHeader, resp2, probeStr)
}

// injectContextualBlindBody injects context-specific blind XSS payloads into POST body
func (s *Scanner) injectContextualBlindBody(config *models.RequestConfig, param string, params map[string]string, reflectionContext models.ReflectionContext) {
	uniqueURL := payloads.GenerateUniqueCallback(s.blindURL, param)
	contextPayloads := payloads.BlindPayloadsForContext(uniqueURL, reflectionContext)

	if s.verbose {
		fmt.Fprintf(os.Stderr, "[BLIND] Body:%s [%s] → %s (%d contextual payloads)\n", param, reflectionContext, uniqueURL, len(contextPayloads))
	}

	for _, payload := range contextPayloads {
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
			jsonData, err := json.Marshal(injectedParams)
			if err != nil {
				continue
			}
			body = string(jsonData)
			contentTypeHeader = "application/json"
		} else {
			formData := url.Values{}
			for k, v := range injectedParams {
				formData.Set(k, v)
			}
			body = formData.Encode()
			contentTypeHeader = "application/x-www-form-urlencoded"
		}

		// Fire and forget
		go func(bodyStr string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, string(config.Method), config.URL, strings.NewReader(bodyStr))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", contentTypeHeader)
			req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
			for k, v := range s.headers {
				req.Header.Set(k, v)
			}
			resp, err := s.client.Do(req)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(body)
	}
}
