package reflected

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
	"github.com/lcalzada-xor/xxss/v3/pkg/models"
	"github.com/lcalzada-xor/xxss/v3/pkg/network"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/reflected/analysis"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/security"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/technologies"
)

// Scanner handles reflected XSS scanning
type Scanner struct {
	client        *network.Client
	headers       map[string]string
	logger        *logger.Logger
	techManager   *technologies.Manager
	wafManager    *security.WAFManager
	useRawPayload bool
	requestCount  int
	requestMutex  sync.Mutex
}

// NewScanner creates a new reflected XSS scanner
func NewScanner(client *network.Client, headers map[string]string, logger *logger.Logger, techManager *technologies.Manager) *Scanner {
	wafManager, err := security.NewWAFManager()
	if err != nil {
		logger.Detail("Error initializing WAF Manager: %v", err)
		// Proceed with nil manager, Detect will handle it or we check for nil
	}

	return &Scanner{
		client:      client,
		headers:     headers,
		logger:      logger,
		techManager: techManager,
		wafManager:  wafManager,
	}
}

// SetRawPayload enables or disables raw payload mode
func (s *Scanner) SetRawPayload(raw bool) {
	s.useRawPayload = raw
}

// GetRequestCount returns the number of HTTP requests made
func (s *Scanner) GetRequestCount() int {
	s.requestMutex.Lock()
	defer s.requestMutex.Unlock()
	return s.requestCount
}

// ResetRequestCount resets the request counter to zero
func (s *Scanner) ResetRequestCount() {
	s.requestMutex.Lock()
	defer s.requestMutex.Unlock()
	s.requestCount = 0
}

// CheckReflection checks which parameters are reflected in the response
func (s *Scanner) CheckReflection(ctx context.Context, targetURL string) ([]string, error) {
	reflected := []string{}

	u, err := url.Parse(targetURL)
	if err != nil {
		return reflected, err
	}

	s.logger.Section("Reflection Check")

	rand.Seed(time.Now().UnixNano())
	originalQS := u.Query()

	for key := range originalQS {
		testQS := u.Query()
		probe := fmt.Sprintf("xxss_%d_%d", time.Now().UnixNano(), rand.Intn(10000))
		testQS.Set(key, probe)

		s.logger.VV("Testing parameter: '%s' with probe: '%s'", key, probe)

		testURL := *u
		testURL.RawQuery = testQS.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
		if err != nil {
			s.logger.Detail("Error creating request: %v", err)
			continue
		}
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
			s.logger.Detail("Error sending request: %v", err)
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		if err != nil {
			s.logger.Detail("Error reading response: %v", err)
			continue
		}
		body := string(bodyBytes)

		if strings.Contains(body, probe) {
			reflected = append(reflected, key)
			s.logger.Detail("Reflected: YES (%d bytes, %v)", len(bodyBytes), elapsed)
		} else {
			s.logger.Detail("Reflected: NO (%d bytes, %v)", len(bodyBytes), elapsed)
		}
	}

	return reflected, nil
}

// ProbeParameter injects special characters into a parameter to test for XSS
func (s *Scanner) ProbeParameter(ctx context.Context, targetURL, param string) ([]models.Result, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	s.logger.Section(fmt.Sprintf("Probing Parameter: %s", param))

	qs := u.Query()
	val := qs.Get(param)

	probeStr := fmt.Sprintf("xxss_%d", rand.Intn(100000))
	payload := val + probeStr + strings.Join(analysis.SpecialChars, "") + probeStr

	s.logger.VV("Payload (%d chars): %s", len(payload), payload)

	var finalURL string
	encodingMode := "URL-encoded"
	if s.useRawPayload {
		encodingMode = "Raw (no encoding)"
		qs.Set(param, payload)
		rawQuery := ""
		for k, values := range qs {
			for _, v := range values {
				if rawQuery != "" {
					rawQuery += "&"
				}
				if k == param {
					rawQuery += k + "=" + v
				} else {
					rawQuery += url.QueryEscape(k) + "=" + url.QueryEscape(v)
				}
			}
		}
		u.RawQuery = rawQuery
		finalURL = u.String()
	} else {
		qs.Set(param, payload)
		u.RawQuery = qs.Encode()
		finalURL = u.String()
	}

	s.logger.Detail("Encoding: %s", encodingMode)
	s.logger.VV("Request URL: %s", finalURL)

	req, err := http.NewRequestWithContext(ctx, "GET", finalURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := s.client.Do(req)
	s.requestMutex.Lock()
	s.requestCount++
	s.requestMutex.Unlock()
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}

	s.logger.Detail("Response: %d %s (%v, %d bytes)", resp.StatusCode, resp.Status, elapsed, resp.ContentLength)

	return s.AnalyzeReflection(targetURL, "GET", param, models.InjectionQuery, resp, probeStr)
}

// CheckBodyReflection checks which body parameters are reflected
func (s *Scanner) CheckBodyReflection(config *models.RequestConfig, params map[string]string) ([]string, error) {
	reflected := []string{}

	for key := range params {
		testParams := make(map[string]string)
		for k, v := range params {
			testParams[k] = v
		}

		probe := fmt.Sprintf("xxss_%d", time.Now().UnixNano())
		testParams[key] = probe

		var body string
		if config.ContentType == "application/json" {
			jsonBytes, _ := json.Marshal(testParams)
			body = string(jsonBytes)
		} else {
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

// ProbeBodyParameter injects special characters into a body parameter
func (s *Scanner) ProbeBodyParameter(ctx context.Context, config *models.RequestConfig, param string, params map[string]string) ([]models.Result, error) {
	s.logger.Section(fmt.Sprintf("Probing Parameter: %s", param))

	val := params[param]
	probeStr := fmt.Sprintf("xxss_%d", rand.Intn(100000))
	payload := val + probeStr + strings.Join(analysis.SpecialChars, "") + probeStr

	testBody := CreateBodyWithProbe(params, param, payload, config.ContentType)

	req, err := http.NewRequestWithContext(ctx, string(config.Method), config.URL, bytes.NewBufferString(testBody))
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return s.AnalyzeReflection(config.URL, string(config.Method), param, models.InjectionBody, resp, probeStr)
}

// ScanHeader scans a specific HTTP header for XSS
func (s *Scanner) ScanHeader(ctx context.Context, targetURL, headerName string) ([]models.Result, error) {
	probeStr := fmt.Sprintf("xxss_%d", rand.Intn(100000))
	payload := probeStr + strings.Join(analysis.SpecialChars, "") + probeStr

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return s.AnalyzeReflection(targetURL, "GET", headerName, models.InjectionHeader, resp, probeStr)
}

// CreateBodyWithProbe creates a request body with the probe injected
func CreateBodyWithProbe(params map[string]string, targetParam, probe string, contentType models.ContentType) string {
	if contentType == "application/json" {
		newParams := make(map[string]string)
		for k, v := range params {
			newParams[k] = v
		}
		newParams[targetParam] = probe

		jsonBytes, _ := json.Marshal(newParams)
		return string(jsonBytes)
	}

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

// AnalyzeReflection performs common analysis on the response
func (s *Scanner) AnalyzeReflection(targetURL, method, param string, injectionType models.InjectionType, resp *http.Response, probeStr string) ([]models.Result, error) {
	defer resp.Body.Close()

	statusCode := resp.StatusCode

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)

	s.logger.Section("Context Analysis")

	s.logger.Section("Security Analysis")
	s.logger.Detail("HTTP Status: %d", statusCode)
	securityHeaders := security.AnalyzeSecurityHeaders(resp)

	var waf *security.WAF
	if s.wafManager != nil {
		waf = s.wafManager.Detect(resp.Header, body)
	} else {
		waf = &security.WAF{Detected: false}
	}
	if waf.Detected {
		securityHeaders.WAF = waf.Name
		s.logger.Detail("WAF: %s", waf.Name)
	} else {
		s.logger.Detail("WAF: not detected")
	}

	if securityHeaders.CSP != "" {
		s.logger.Detail("CSP: %s", securityHeaders.CSP)
	} else {
		s.logger.Detail("CSP: none")
	}
	if securityHeaders.XXSSProtection != "" {
		s.logger.Detail("X-XSS-Protection: %s", securityHeaders.XXSSProtection)
	} else {
		s.logger.Detail("X-XSS-Protection: not set")
	}

	// Find all reflections
	var exploitableResults []models.Result
	var allResults []models.Result
	var bestNonExploitable models.Result
	bestNonExploitable.Exploitable = false

	// Helper to find all indices of a substring
	var indices []int
	start := 0
	for {
		idx := strings.Index(body[start:], probeStr)
		if idx == -1 {
			break
		}
		indices = append(indices, start+idx)
		start += idx + len(probeStr)
	}

	if len(indices) == 0 {
		return nil, nil
	}

	s.logger.Detail("Found %d reflections", len(indices))

	visited := make(map[int]bool)

	for _, idx := range indices {
		if visited[idx] {
			continue
		}

		// Analyze this specific reflection
		context := analysis.DetectContextVerbose(body, probeStr, idx, s.logger)

		// Local check for unfiltered chars
		localUnfiltered, nextProbeIdx := checkLocalUnfiltered(body, idx, probeStr, analysis.SpecialChars)
		if nextProbeIdx != -1 {
			visited[nextProbeIdx] = true
		}

		exploitable := security.IsExploitable(context, securityHeaders, localUnfiltered)

		s.logger.Detail("Reflection at %d: Context=%s, Exploitable=%v, Unfiltered=%v", idx, context, exploitable, localUnfiltered)

		techs := s.techManager.DetectAll(body)
		suggestedPayload := payloads.GenerateReflectedPayload(context, localUnfiltered, techs)

		var techStrings []string
		for _, tech := range techs {
			techStrings = append(techStrings, fmt.Sprintf("%s %s", tech.Name, tech.Version))
		}

		result := models.Result{
			URL:              targetURL,
			Method:           method,
			Parameter:        param,
			InjectionType:    injectionType,
			HTTPStatus:       statusCode,
			Reflected:        true,
			Unfiltered:       localUnfiltered,
			Context:          context,
			SecurityHeaders:  securityHeaders,
			Exploitable:      exploitable,
			SuggestedPayload: suggestedPayload,
			Technologies:     techStrings,
		}

		allResults = append(allResults, result)

		if exploitable {
			exploitableResults = append(exploitableResults, result)
		} else {
			// Keep track of the "best" non-exploitable result (e.g. most unfiltered chars)
			if !bestNonExploitable.Reflected || len(localUnfiltered) > len(bestNonExploitable.Unfiltered) {
				bestNonExploitable = result
			}
		}
	}

	// If we have exploitable results, return ALL of them
	if len(exploitableResults) > 0 {
		s.logger.Detail("Found %d exploitable reflections", len(exploitableResults))
		for _, res := range exploitableResults {
			s.logger.Section("Suggested Payload")
			s.logger.VV("%s", res.SuggestedPayload)
		}
		return exploitableResults, nil
	}

	// If no exploitable results, return the best non-exploitable one
	s.logger.Detail("No exploitable reflections found. Returning best non-exploitable result.")
	return []models.Result{bestNonExploitable}, nil
}

// checkLocalUnfiltered checks which special characters are present immediately after the probe
func checkLocalUnfiltered(body string, probeIdx int, probe string, specialChars []string) ([]string, int) {
	unfiltered := []string{}

	start := probeIdx + len(probe)
	if start >= len(body) {
		return unfiltered, -1
	}

	// Look for the next probe to define the end of the content
	nextProbe := strings.Index(body[start:], probe)
	if nextProbe == -1 {
		// If we can't find the next probe, we might be at the end of the reflection
		// or the reflection is truncated.
		// Let's try to look at a reasonable window (e.g., 200 chars)
		// This handles cases where the second probe is cut off or modified.
		windowSize := 200
		if len(body[start:]) < windowSize {
			windowSize = len(body[start:])
		}
		nextProbe = windowSize
	}

	content := body[start : start+nextProbe]

	// Validate content:
	// We used to fail if we found alphanumeric chars, but that's too strict.
	// WAFs/Sanitizers might replace chars with text (e.g. < -> [removed]).
	// So we just look for the special chars we injected.
	// However, we should be careful not to match random text if the probe is very common (which is why we use dynamic probes now).

	// Check for each special char in `content`
	for _, char := range specialChars {
		if strings.Contains(content, char) {
			unfiltered = append(unfiltered, char)
		}
	}

	return unfiltered, start + nextProbe
}
