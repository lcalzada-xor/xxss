package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
	"github.com/lcalzada-xor/xxss/v3/pkg/models"
	"github.com/lcalzada-xor/xxss/v3/pkg/network"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/blind"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/dom"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/payloads"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/reflected"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/security"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/technologies"
)

// Scanner is the main struct for the XSS scanner.
// It orchestrates multiple scanning engines.
type Scanner struct {
	client  *network.Client
	headers map[string]string
	logger  *logger.Logger

	// Sub-scanners
	domScanner       *dom.DOMScanner
	reflectedScanner *reflected.Scanner
	blindScanner     *blind.Scanner
	techManager      *technologies.Manager
	wafManager       *security.WAFManager

	// Configuration
	scanDOM     bool
	scanDeepDOM bool
	blindURL    string

	// State
	requestCount int // Local count for DOM requests etc
	requestMutex sync.Mutex
}

// NewScanner creates a new Scanner instance
func NewScanner(client *network.Client, headers map[string]string) *Scanner {
	logger := logger.NewLogger(0) // Default: silent
	techManager := technologies.NewManager()
	wafManager, _ := security.NewWAFManager() // Ignore error for now, similar to reflected scanner

	return &Scanner{
		client:           client,
		headers:          headers,
		logger:           logger,
		domScanner:       dom.NewDOMScanner(logger),
		reflectedScanner: reflected.NewScanner(client, headers, logger, techManager),
		blindScanner:     blind.NewScanner(client, headers, logger, ""),
		techManager:      techManager,
		wafManager:       wafManager,
	}
}

// SetScanDOM enables or disables DOM XSS scanning
func (s *Scanner) SetScanDOM(enable bool) {
	s.scanDOM = enable
}

// SetScanDeepDOM enables or disables deep DOM XSS scanning
func (s *Scanner) SetScanDeepDOM(enable bool) {
	s.scanDeepDOM = enable
}

// SetBlindURL sets the callback URL for Blind XSS attacks
func (s *Scanner) SetBlindURL(url string) {
	s.blindURL = url
	s.blindScanner = blind.NewScanner(s.client, s.headers, s.logger, url)
}

// SetVerboseLevel sets the verbosity level
func (s *Scanner) SetVerboseLevel(level int) {
	s.logger = logger.NewLogger(level)
	s.domScanner.SetVerboseLevel(level)
	s.reflectedScanner = reflected.NewScanner(s.client, s.headers, s.logger, s.techManager)
	s.blindScanner = blind.NewScanner(s.client, s.headers, s.logger, s.blindURL)
}

// SetRawPayload enables or disables raw payload mode
func (s *Scanner) SetRawPayload(raw bool) {
	s.reflectedScanner.SetRawPayload(raw)
}

// GetRequestCount returns the total number of HTTP requests made
func (s *Scanner) GetRequestCount() int {
	s.requestMutex.Lock()
	defer s.requestMutex.Unlock()

	total := s.requestCount
	total += s.reflectedScanner.GetRequestCount()
	return total
}

// ResetRequestCount resets the request counter
func (s *Scanner) ResetRequestCount() {
	s.requestMutex.Lock()
	s.requestCount = 0
	s.requestMutex.Unlock()

	s.reflectedScanner.ResetRequestCount()
}

// Scan performs the XSS scan on the given URL (GET)
func (s *Scanner) Scan(ctx context.Context, targetURL string) ([]models.Result, error) {
	results := []models.Result{}

	// DOM XSS Scanning
	if s.scanDOM {
		domResults, err := s.scanDOMXSS(ctx, targetURL)
		if err != nil {
			return results, err
		}
		results = append(results, domResults...)
	}

	// 1. Baseline Check: See which parameters are reflected
	reflectedParams, err := s.reflectedScanner.CheckReflection(ctx, targetURL)
	if err != nil {
		return results, err
	}

	// Blind All Injection (if enabled)
	if s.blindURL != "" {
		u, err := url.Parse(targetURL)
		if err == nil {
			for param := range u.Query() {
				payloads.InjectBlind(s.client, s.headers, targetURL, param, s.blindURL, s.logger.IsVerbose())
			}
		}
	}

	if len(reflectedParams) == 0 {
		return results, nil
	}

	// 2. Single-Shot Probe
	for _, param := range reflectedParams {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		resultsList, err := s.reflectedScanner.ProbeParameter(ctx, targetURL, param)
		if err != nil {
			continue
		}

		for _, result := range resultsList {
			// Contextual Blind XSS Injection
			if s.blindURL != "" && result.Context != models.ContextUnknown {
				s.blindScanner.InjectContextualBlind(targetURL, param, result.Context)
			}

			if len(result.Unfiltered) > 0 {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// ScanRequest performs XSS scan on POST/PUT/PATCH requests
func (s *Scanner) ScanRequest(ctx context.Context, config *models.RequestConfig) ([]models.Result, error) {
	results := []models.Result{}

	// 1. Parse body parameters
	params := parseBodyParams(config.Body, string(config.ContentType))
	if len(params) == 0 {
		return results, nil
	}

	// 2. Baseline check
	reflectedParams, err := s.reflectedScanner.CheckBodyReflection(config, params)
	if err != nil {
		return results, err
	}

	// Blind All Injection
	if s.blindURL != "" {
		for param := range params {
			payloads.InjectBlindBody(s.client, s.headers, config, param, s.blindURL, params, s.logger.IsVerbose())
		}
	}

	// 3. Scan Body Parameters
	for _, param := range reflectedParams {
		resultsList, err := s.reflectedScanner.ProbeBodyParameter(ctx, config, param, params)
		if err != nil {
			continue
		}

		for _, result := range resultsList {
			if s.blindURL != "" && result.Context != models.ContextUnknown {
				s.blindScanner.InjectContextualBlindBody(config, param, result.Context, params, reflected.CreateBodyWithProbe)
			}

			if len(result.Unfiltered) > 0 {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// ScanHeader scans a specific HTTP header for XSS
func (s *Scanner) ScanHeader(ctx context.Context, targetURL, headerName string) (models.Result, error) {
	// Delegate to reflected scanner
	results, err := s.reflectedScanner.ScanHeader(ctx, targetURL, headerName)
	if err != nil {
		return models.Result{}, err
	}

	// Blind injection for header
	if s.blindURL != "" {
		s.blindScanner.InjectBlindHeader(targetURL, headerName)
	}

	if len(results) > 0 {
		return results[0], err
	}
	return models.Result{}, err
}

func (s *Scanner) scanDOMXSS(ctx context.Context, targetURL string) ([]models.Result, error) {
	var results []models.Result

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
			Exploitable: true,
			DOMFindings: findings,
		})
	} else {
		s.logger.Detail("No DOM XSS vulnerabilities detected")
	}

	return results, nil
}

func parseBodyParams(body, contentType string) map[string]string {
	params := make(map[string]string)
	if contentType == "application/json" {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(body), &data); err == nil {
			for k, v := range data {
				if strVal, ok := v.(string); ok {
					params[k] = strVal
				}
			}
		} else {
			// s.logger.Error("JSON Unmarshal error: %v", err)
			// Note: We don't have access to scanner instance here easily as it is a helper function.
			// Ideally this function should be a method of Scanner or take a logger.
			// For now, let's just suppress it or print to stderr if we really must, but better to just ignore as it might be garbage body.

		}
	} else {
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

// DetectTechnologies fetches the URL and detects technologies
// DetectTechnologies fetches the URL and detects technologies, including external scripts
func (s *Scanner) DetectTechnologies(ctx context.Context, targetURL string) ([]*technologies.Technology, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)

	// 1. Detect in HTML body
	techs := s.techManager.DetectAll(body)

	// 1.5 Detect WAF (Passive)
	var waf *security.WAF
	if s.wafManager != nil {
		waf = s.wafManager.Detect(resp.Header, body)
	} else {
		waf = &security.WAF{Detected: false}
	}

	if waf.Detected {
		techs = append(techs, &technologies.Technology{
			Name:       waf.Name,
			Version:    "Unknown",
			Confidence: "High",
		})
	}

	// 2. Extract script URLs
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	matches := scriptPattern.FindAllStringSubmatch(body, -1)

	if len(matches) == 0 {
		return techs, nil
	}

	// 3. Fetch external scripts concurrently
	var wg sync.WaitGroup
	scriptChan := make(chan string, len(matches))

	// Limit concurrency for script fetching
	sem := make(chan struct{}, 10)

	baseURL, err := url.Parse(targetURL)
	if err != nil {
		return techs, nil
	}

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		scriptSrc := match[1]

		// Resolve relative URLs
		scriptURL, err := url.Parse(scriptSrc)
		if err != nil {
			continue
		}
		absURL := baseURL.ResolveReference(scriptURL).String()

		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check context
			if ctx.Err() != nil {
				return
			}

			// Fetch script
			sReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return
			}
			sReq.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

			sResp, err := s.client.Do(sReq)

			s.requestMutex.Lock()
			s.requestCount++
			s.requestMutex.Unlock()

			if err != nil {
				return
			}
			defer sResp.Body.Close()

			sBodyBytes, err := io.ReadAll(sResp.Body)
			if err != nil {
				return
			}

			scriptChan <- string(sBodyBytes)
		}(absURL)
	}

	go func() {
		wg.Wait()
		close(scriptChan)
	}()

	// 4. Detect in scripts
	for scriptContent := range scriptChan {
		scriptTechs := s.techManager.DetectAll(scriptContent)
		techs = append(techs, scriptTechs...)
	}

	// Deduplicate results
	uniqueTechs := make(map[string]*technologies.Technology)
	for _, t := range techs {
		key := t.Name
		if existing, ok := uniqueTechs[key]; ok {
			// Prioritize version over no version/Unknown
			newHasVersion := t.Version != "" && t.Version != "Unknown"
			oldHasVersion := existing.Version != "" && existing.Version != "Unknown"

			if newHasVersion && !oldHasVersion {
				uniqueTechs[key] = t
			}
			// If both have versions or neither, keep existing (first found usually better/same)
		} else {
			uniqueTechs[key] = t
		}
	}

	finalTechs := make([]*technologies.Technology, 0, len(uniqueTechs))
	for _, t := range uniqueTechs {
		finalTechs = append(finalTechs, t)
	}

	return finalTechs, nil
}
