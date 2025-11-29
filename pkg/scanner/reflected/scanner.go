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

	"github.com/lcalzada-xor/xxss/v2/pkg/logger"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/network"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/reflection"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/security"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/technologies"
)

// Scanner handles reflected XSS scanning
type Scanner struct {
	client        *network.Client
	headers       map[string]string
	logger        *logger.Logger
	techManager   *technologies.Manager
	useRawPayload bool
	requestCount  int
	requestMutex  sync.Mutex
}

// NewScanner creates a new reflected XSS scanner
func NewScanner(client *network.Client, headers map[string]string, logger *logger.Logger, techManager *technologies.Manager) *Scanner {
	return &Scanner{
		client:      client,
		headers:     headers,
		logger:      logger,
		techManager: techManager,
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
func (s *Scanner) ProbeParameter(ctx context.Context, targetURL, param string) (models.Result, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return models.Result{}, err
	}

	s.logger.Section(fmt.Sprintf("Probing Parameter: %s", param))

	qs := u.Query()
	val := qs.Get(param)

	probeStr := "xssprobe"
	payload := val + probeStr + strings.Join(reflection.SpecialChars, "") + probeStr

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
		return models.Result{}, err
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
		return models.Result{}, err
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
func (s *Scanner) ProbeBodyParameter(ctx context.Context, config *models.RequestConfig, param string, params map[string]string) (models.Result, error) {
	s.logger.Section(fmt.Sprintf("Probing Parameter: %s", param))

	val := params[param]
	probeStr := "xssprobe"
	payload := val + probeStr + strings.Join(reflection.SpecialChars, "") + probeStr

	testBody := CreateBodyWithProbe(params, param, payload, config.ContentType)

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
func (s *Scanner) AnalyzeReflection(targetURL, method, param string, injectionType models.InjectionType, resp *http.Response, probeStr string) (models.Result, error) {
	defer resp.Body.Close()

	statusCode := resp.StatusCode

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.Result{}, err
	}
	body := string(bodyBytes)

	unfiltered := reflection.AnalyzeResponse(body, probeStr)
	s.logger.Detail("Unfiltered chars: %v", unfiltered)

	s.logger.Section("Context Analysis")
	context := reflection.DetectContextVerbose(body, probeStr, s.logger)

	s.logger.Section("Security Analysis")
	s.logger.Detail("HTTP Status: %d", statusCode)
	securityHeaders := security.AnalyzeSecurityHeaders(resp)

	waf := security.Detect(resp.Header, body)
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

	exploitable := security.IsExploitable(context, securityHeaders, unfiltered)
	s.logger.Detail("Exploitable: %v", exploitable)

	s.logger.Section("Suggested Payload")

	techs := s.techManager.DetectAll(body)
	if len(techs) > 0 {
		s.logger.Detail("Detected Technologies:")
		for _, tech := range techs {
			s.logger.Detail(" - %s %s (%s)", tech.Name, tech.Version, tech.Confidence)
		}
	}

	suggestedPayload := payloads.GeneratePayload(context, unfiltered, techs)
	s.logger.VV("%s", suggestedPayload)

	var techStrings []string
	for _, tech := range techs {
		techStrings = append(techStrings, fmt.Sprintf("%s %s", tech.Name, tech.Version))
	}

	return models.Result{
		URL:              targetURL,
		Method:           method,
		Parameter:        param,
		InjectionType:    injectionType,
		HTTPStatus:       statusCode,
		Reflected:        true,
		Unfiltered:       unfiltered,
		Context:          context,
		SecurityHeaders:  securityHeaders,
		Exploitable:      exploitable,
		SuggestedPayload: suggestedPayload,
		Technologies:     techStrings,
	}, nil
}
