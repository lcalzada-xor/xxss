package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lcalzada-xor/xxss/models"
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
	params := s.parseBodyParams(config.Body, config.ContentType)
	if len(params) == 0 {
		return results, nil
	}

	// 2. Baseline check: see which parameters are reflected
	reflectedParams, err := s.checkBodyReflection(config, params)
	if err != nil {
		return results, err
	}

	if len(reflectedParams) == 0 {
		return results, nil
	}

	// 3. Probe each reflected parameter
	for _, param := range reflectedParams {
		// Blind XSS Injection for body parameters
		if s.blindURL != "" {
			s.InjectBlindBody(config, param, s.blindURL, params)
		}

		result, err := s.probeBodyParameter(config, param, params)
		if err != nil {
			continue
		}
		if len(result.Unfiltered) > 0 {
			results = append(results, result)
		}
	}

	return results, nil
}

// parseBodyParams parses body parameters based on content type
func (s *Scanner) parseBodyParams(body string, contentType models.ContentType) map[string]string {
	params := make(map[string]string)

	if body == "" {
		return params
	}

	switch contentType {
	case models.ContentTypeForm:
		// Parse: "name=value&email=test@test.com"
		values, err := url.ParseQuery(body)
		if err != nil {
			return params
		}
		for k, v := range values {
			if len(v) > 0 {
				params[k] = v[0]
			}
		}

	case models.ContentTypeJSON:
		// Parse: {"name":"value","email":"test@test.com"}
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err != nil {
			return params
		}
		for k, v := range jsonData {
			params[k] = fmt.Sprintf("%v", v)
		}
	}

	return params
}

// checkBodyReflection checks which body parameters are reflected in the response
func (s *Scanner) checkBodyReflection(config *models.RequestConfig, params map[string]string) ([]string, error) {
	reflected := []string{}

	// Generate unique probes for each parameter
	rand.Seed(time.Now().UnixNano())
	paramProbes := make(map[string]string)
	for key := range params {
		paramProbes[key] = fmt.Sprintf("xxss_%d_%d", time.Now().UnixNano(), rand.Intn(10000))
	}

	// Build request body with probes
	var bodyWithProbes string
	switch config.ContentType {
	case models.ContentTypeForm:
		values := url.Values{}
		for k, probe := range paramProbes {
			values.Set(k, probe)
		}
		bodyWithProbes = values.Encode()

	case models.ContentTypeJSON:
		jsonData := make(map[string]string)
		for k, probe := range paramProbes {
			jsonData[k] = probe
		}
		jsonBytes, _ := json.Marshal(jsonData)
		bodyWithProbes = string(jsonBytes)
	}

	// Send request
	req, err := http.NewRequest(string(config.Method), config.URL, bytes.NewBufferString(bodyWithProbes))
	if err != nil {
		return reflected, err
	}

	req.Header.Set("Content-Type", string(config.ContentType))
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add custom headers
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return reflected, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return reflected, err
	}
	body := string(bodyBytes)

	// Check which probes are reflected
	for key, probe := range paramProbes {
		if strings.Contains(body, probe) {
			reflected = append(reflected, key)
		}
	}

	return reflected, nil
}

// probeBodyParameter probes a specific body parameter for XSS
func (s *Scanner) probeBodyParameter(config *models.RequestConfig, param string, params map[string]string) (models.Result, error) {
	// Construct payload
	probeStr := "xssprobe"
	payload := params[param] + probeStr + strings.Join(SpecialChars, "") + probeStr

	// Build request body with payload
	var bodyWithPayload string
	switch config.ContentType {
	case models.ContentTypeForm:
		values := url.Values{}
		for k, v := range params {
			if k == param {
				values.Set(k, payload)
			} else {
				values.Set(k, v)
			}
		}
		bodyWithPayload = values.Encode()

	case models.ContentTypeJSON:
		jsonData := make(map[string]string)
		for k, v := range params {
			if k == param {
				jsonData[k] = payload
			} else {
				jsonData[k] = v
			}
		}
		jsonBytes, _ := json.Marshal(jsonData)
		bodyWithPayload = string(jsonBytes)
	}

	// Send request
	req, err := http.NewRequest(string(config.Method), config.URL, bytes.NewBufferString(bodyWithPayload))
	if err != nil {
		return models.Result{}, err
	}

	req.Header.Set("Content-Type", string(config.ContentType))
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add custom headers
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return models.Result{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.Result{}, err
	}
	body := string(bodyBytes)

	unfiltered := AnalyzeResponse(body, probeStr)

	// Detect context
	context := DetectContext(body, probeStr)

	// Analyze security headers
	securityHeaders := AnalyzeSecurityHeaders(resp)

	// Determine exploitability
	exploitable := IsExploitable(context, securityHeaders, unfiltered)

	// Get suggested payload
	suggestedPayload := GetSuggestedPayload(context, unfiltered)

	return models.Result{
		URL:              config.URL,
		Method:           string(config.Method),
		Parameter:        param,
		InjectionType:    models.InjectionBody,
		Reflected:        true,
		Unfiltered:       unfiltered,
		Context:          context,
		SecurityHeaders:  securityHeaders,
		Exploitable:      exploitable,
		SuggestedPayload: suggestedPayload,
	}, nil
}

// ScanHeaders performs XSS scan on HTTP headers
func (s *Scanner) ScanHeaders(targetURL string, headersToTest []string) ([]models.Result, error) {
	results := []models.Result{}

	for _, header := range headersToTest {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}

		// Blind XSS Injection for Headers
		if s.blindURL != "" {
			s.InjectBlindHeader(targetURL, header, s.blindURL)
		}

		result, err := s.probeHeader(targetURL, header)
		if err != nil {
			continue
		}
		if len(result.Unfiltered) > 0 {
			results = append(results, result)
		}
	}

	return results, nil
}

// probeHeader probes a specific HTTP header for XSS
func (s *Scanner) probeHeader(targetURL, header string) (models.Result, error) {
	// 1. Baseline check: see if header is reflected
	rand.Seed(time.Now().UnixNano())
	probe := fmt.Sprintf("xxss_%d_%d", time.Now().UnixNano(), rand.Intn(10000))

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return models.Result{}, err
	}

	req.Header.Set(header, probe)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add custom headers (but don't override the one we're testing)
	for k, v := range s.headers {
		if k != header {
			req.Header.Set(k, v)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return models.Result{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.Result{}, err
	}
	body := string(bodyBytes)

	// Check if probe is reflected
	if !strings.Contains(body, probe) {
		return models.Result{}, fmt.Errorf("header not reflected")
	}

	// 2. Probe with XSS payload
	probeStr := "xssprobe"
	payload := probeStr + strings.Join(SpecialChars, "") + probeStr

	req2, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return models.Result{}, err
	}

	req2.Header.Set(header, payload)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add custom headers
	for k, v := range s.headers {
		if k != header {
			req2.Header.Set(k, v)
		}
	}

	resp2, err := s.client.Do(req2)
	if err != nil {
		return models.Result{}, err
	}
	defer resp2.Body.Close()

	bodyBytes2, err := io.ReadAll(resp2.Body)
	if err != nil {
		return models.Result{}, err
	}
	body2 := string(bodyBytes2)

	unfiltered := AnalyzeResponse(body2, probeStr)

	// Detect context
	context := DetectContext(body2, probeStr)

	// Analyze security headers
	securityHeaders := AnalyzeSecurityHeaders(resp2)

	// Determine exploitability
	exploitable := IsExploitable(context, securityHeaders, unfiltered)

	// Get suggested payload
	suggestedPayload := GetSuggestedPayload(context, unfiltered)

	return models.Result{
		URL:              targetURL,
		Method:           "GET",
		Parameter:        header,
		InjectionType:    models.InjectionHeader,
		Reflected:        true,
		Unfiltered:       unfiltered,
		Context:          context,
		SecurityHeaders:  securityHeaders,
		Exploitable:      exploitable,
		SuggestedPayload: suggestedPayload,
	}, nil
}
