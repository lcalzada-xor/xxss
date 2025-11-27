package scanner

import (
	"context"
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
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/dom"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/reflection"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/security"
)

// Scanner is the main struct for the XSS scanner.
// It holds configuration, dependencies, and state for the scanning process.
type Scanner struct {
	client        *network.Client
	headers       map[string]string
	useRawPayload bool
	blindURL      string
	logger        *logger.Logger
	domScanner    *dom.DOMScanner
	scanDOM       bool
	scanDeepDOM   bool
	requestCount  int
	requestMutex  sync.Mutex
}

// NewScanner creates a new Scanner instance with the given HTTP client and headers.
func NewScanner(client *network.Client, headers map[string]string) *Scanner {
	return &Scanner{
		client:        client,
		headers:       headers,
		useRawPayload: false,
		blindURL:      "",
		logger:        logger.NewLogger(0), // Default: silent
		requestCount:  0,
		domScanner:    dom.NewDOMScanner(logger.NewLogger(0)),
	}
}

// SetScanDOM enables or disables DOM XSS scanning
func (s *Scanner) SetScanDOM(enable bool) {
	s.scanDOM = enable
}

// SetScanDeepDOM enables or disables deep DOM XSS scanning (fetching external JS)
func (s *Scanner) SetScanDeepDOM(enable bool) {
	s.scanDeepDOM = enable
}

// SetBlindURL sets the callback URL for Blind XSS attacks
func (s *Scanner) SetBlindURL(url string) {
	s.blindURL = url
}

// SetVerboseLevel sets the verbosity level (0=silent, 1=verbose, 2=very verbose)
func (s *Scanner) SetVerboseLevel(level int) {
	s.logger = logger.NewLogger(level)
	s.domScanner.SetVerboseLevel(level)
}

// SetRawPayload enables or disables raw payload mode (no URL encoding)
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

// Scan performs the XSS scan on the given URL.
// It checks for DOM XSS (if enabled) and Reflected XSS using a single-shot probe strategy.
func (s *Scanner) Scan(ctx context.Context, targetURL string) ([]models.Result, error) {
	results := []models.Result{}

	// DOM XSS Scanning
	if s.scanDOM {
		// Fetch the page content
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			return results, err
		}
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}

		resp, err := s.client.Do(req)
		s.requestMutex.Lock()
		s.requestCount++
		s.requestMutex.Unlock()
		if err != nil {
			return results, err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return results, err
		}
		body := string(bodyBytes)

		var findings []models.DOMFinding
		if s.scanDeepDOM {
			findings = s.domScanner.ScanDeepDOM(targetURL, body, s.client.HTTPClient)
		} else {
			findings = s.domScanner.ScanDOM(body)
		}

		if len(findings) > 0 {
			s.logger.Section("DOM XSS Findings Summary")
			s.logger.Detail("Total findings: %d", len(findings))
			for i, finding := range findings {
				s.logger.VV("")
				s.logger.VV("Finding #%d:", i+1)
				s.logger.Detail("  Confidence: %s", finding.Confidence)
				s.logger.Detail("  Source: %s", finding.Source)
				s.logger.Detail("  Sink: %s", finding.Sink)
				if finding.LineNumber > 0 {
					s.logger.Detail("  Line: %d", finding.LineNumber)
				}
				s.logger.VV("  Description: %s", finding.Description)
			}

			results = append(results, models.Result{
				URL:         targetURL,
				Method:      "GET",
				Parameter:   "DOM",
				Exploitable: true, // Potential DOM XSS
				DOMFindings: findings,
			})
		} else {
			s.logger.Detail("No DOM XSS vulnerabilities detected")
		}
	}

	// 1. Baseline Check: See which parameters are reflected at all.
	reflectedParams, err := s.checkReflection(ctx, targetURL)
	if err != nil {
		return results, err
	}

	// Blind All Injection (if enabled)
	if s.blindURL != "" {
		u, err := url.Parse(targetURL)
		if err == nil {
			for param := range u.Query() {
				// Inject generic blind payloads into every parameter
				payloads.InjectBlind(s.client, s.headers, targetURL, param, s.blindURL, s.logger.IsVerbose())
			}
		}
	}

	if len(reflectedParams) == 0 {
		return results, nil
	}

	// 2. Single-Shot Probe: For each reflected param, inject all chars.
	for _, param := range reflectedParams {
		// Check context before each probe
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		result, err := s.probeParameter(ctx, targetURL, param)
		if err != nil {
			// Log error but continue with other params?
			// For now, just continue.
			continue
		}

		// Contextual Blind XSS Injection (after context detection)
		if s.blindURL != "" && result.Context != models.ContextUnknown {
			s.injectContextualBlind(targetURL, param, result.Context)
		}

		if len(result.Unfiltered) > 0 {
			results = append(results, result)
		}
	}

	return results, nil
}

func (s *Scanner) checkReflection(ctx context.Context, targetURL string) ([]string, error) {
	reflected := []string{}

	u, err := url.Parse(targetURL)
	if err != nil {
		return reflected, err
	}

	s.logger.Section("Reflection Check")

	// Test each parameter individually to avoid false negatives
	// when a parameter's reflection depends on another parameter's value
	rand.Seed(time.Now().UnixNano())
	originalQS := u.Query()

	for key := range originalQS {
		// Create a fresh copy of query parameters for each test
		testQS := u.Query()

		// Generate unique probe for THIS parameter only
		probe := fmt.Sprintf("xxss_%d_%d", time.Now().UnixNano(), rand.Intn(10000))
		testQS.Set(key, probe)

		s.logger.VV("Testing parameter: '%s' with probe: '%s'", key, probe)

		// Build test URL with only this parameter modified
		testURL := *u
		testURL.RawQuery = testQS.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
		if err != nil {
			s.logger.Detail("Error creating request: %v", err)
			continue // Skip this parameter on error
		}
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

		// Add custom headers
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
			continue // Skip this parameter on error
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		if err != nil {
			s.logger.Detail("Error reading response: %v", err)
			continue // Skip this parameter on error
		}
		body := string(bodyBytes)

		// Check if this probe is reflected
		isReflected := strings.Contains(body, probe)
		if isReflected {
			reflected = append(reflected, key)
			s.logger.Detail("Reflected: YES (%d bytes, %v)", len(bodyBytes), elapsed)
		} else {
			s.logger.Detail("Reflected: NO (%d bytes, %v)", len(bodyBytes), elapsed)
		}
	}

	return reflected, nil
}

func (s *Scanner) probeParameter(ctx context.Context, targetURL, param string) (models.Result, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return models.Result{}, err
	}

	s.logger.Section(fmt.Sprintf("Probing Parameter: %s", param))

	qs := u.Query()
	val := qs.Get(param)

	// Construct payload: "original_value" + "random_prefix" + all_chars + "random_suffix"
	// Using a static prefix/suffix for now for simplicity, but unique enough.
	probeStr := "xssprobe"
	payload := val + probeStr + strings.Join(reflection.SpecialChars, "") + probeStr

	s.logger.VV("Payload (%d chars): %s", len(payload), payload)

	var finalURL string
	encodingMode := "URL-encoded"
	if s.useRawPayload {
		encodingMode = "Raw (no encoding)"
		// Raw mode: construct URL manually without encoding special characters
		qs.Set(param, payload)
		// Build the query string manually to avoid encoding
		rawQuery := ""
		for k, values := range qs {
			for _, v := range values {
				if rawQuery != "" {
					rawQuery += "&"
				}
				if k == param {
					// Don't encode the payload for this parameter
					rawQuery += k + "=" + v
				} else {
					// Encode other parameters normally
					rawQuery += url.QueryEscape(k) + "=" + url.QueryEscape(v)
				}
			}
		}
		u.RawQuery = rawQuery
		finalURL = u.String()
	} else {
		// Normal mode: use standard URL encoding
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

	// Add custom headers
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

	// Analyze reflection using shared method
	return s.AnalyzeReflection(targetURL, "GET", param, models.InjectionQuery, resp, probeStr)
}

// AnalyzeReflection performs common analysis on the response
func (s *Scanner) AnalyzeReflection(targetURL, method, param string, injectionType models.InjectionType, resp *http.Response, probeStr string) (models.Result, error) {
	defer resp.Body.Close()

	// Capture HTTP status code
	statusCode := resp.StatusCode

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.Result{}, err
	}
	body := string(bodyBytes)

	unfiltered := reflection.AnalyzeResponse(body, probeStr)
	s.logger.Detail("Unfiltered chars: %v", unfiltered)

	// Detect context
	s.logger.Section("Context Analysis")
	context := reflection.DetectContextVerbose(body, probeStr, s.logger)

	// Analyze security headers
	s.logger.Section("Security Analysis")
	s.logger.Detail("HTTP Status: %d", statusCode)
	securityHeaders := security.AnalyzeSecurityHeaders(resp)

	// Detect WAF
	waf := security.DetectWAF(resp.Header)
	if !waf.Detected {
		// Active Probe
		waf = security.ProbeWAF(s.client.HTTPClient, targetURL)
	}
	if waf.Detected {
		securityHeaders.WAF = waf.Name
		s.logger.Detail("WAF: %s", waf.Name)
	} else {
		s.logger.Detail("WAF: not detected")
	}

	// Log security headers in -vv mode
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

	// Determine exploitability
	exploitable := security.IsExploitable(context, securityHeaders, unfiltered)
	s.logger.Detail("Exploitable: %v", exploitable)

	// Get suggested payload
	s.logger.Section("Suggested Payload")
	suggestedPayload := payloads.GeneratePayload(context, unfiltered)
	s.logger.VV("%s", suggestedPayload)

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
	}, nil
}

// injectContextualBlind injects context-specific blind XSS payloads
func (s *Scanner) injectContextualBlind(targetURL, param string, context models.ReflectionContext) {
	uniqueURL := payloads.GenerateUniqueCallback(s.blindURL, param)
	contextPayloads := payloads.BlindPayloadsForContext(uniqueURL, context)

	s.logger.V("[BLIND] %s [%s] → %s (%d contextual payloads)", param, context, uniqueURL, len(contextPayloads))

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	qs := u.Query()

	for _, payload := range contextPayloads {
		qs.Set(param, payload)
		u.RawQuery = qs.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}

		// Fire and forget
		go func(r *http.Request) {
			resp, err := s.client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
	}
}
