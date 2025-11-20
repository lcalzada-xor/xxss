package scanner

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lcalzada-xor/xxss/models"
)

type Scanner struct {
	client        *http.Client
	headers       map[string]string
	useRawPayload bool
	blindURL      string
	requestCount  int
	requestMutex  sync.Mutex
}

func NewScanner(client *http.Client, headers map[string]string) *Scanner {
	return &Scanner{
		client:        client,
		headers:       headers,
		useRawPayload: false,
		blindURL:      "",
		requestCount:  0,
	}
}

// SetBlindURL sets the callback URL for Blind XSS attacks
func (s *Scanner) SetBlindURL(url string) {
	s.blindURL = url
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
func (s *Scanner) Scan(targetURL string) ([]models.Result, error) {
	results := []models.Result{}

	// 1. Baseline Check: See which parameters are reflected at all.
	reflectedParams, err := s.checkReflection(targetURL)
	if err != nil {
		return results, err
	}

	if len(reflectedParams) == 0 {
		return results, nil
	}

	// 2. Single-Shot Probe: For each reflected param, inject all chars.
	for _, param := range reflectedParams {
		// Blind XSS Injection
		if s.blindURL != "" {
			s.InjectBlind(targetURL, param, s.blindURL)
		}

		result, err := s.probeParameter(targetURL, param)
		if err != nil {
			// Log error but continue with other params?
			// For now, just continue.
			continue
		}
		if len(result.Unfiltered) > 0 {
			results = append(results, result)
		}
	}

	return results, nil
}

func (s *Scanner) checkReflection(targetURL string) ([]string, error) {
	reflected := []string{}

	u, err := url.Parse(targetURL)
	if err != nil {
		return reflected, err
	}

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

		// Build test URL with only this parameter modified
		testURL := *u
		testURL.RawQuery = testQS.Encode()

		req, err := http.NewRequest("GET", testURL.String(), nil)
		if err != nil {
			continue // Skip this parameter on error
		}
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

		// Add custom headers
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}

		resp, err := s.client.Do(req)
		s.requestMutex.Lock()
		s.requestCount++
		s.requestMutex.Unlock()
		if err != nil {
			continue // Skip this parameter on error
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue // Skip this parameter on error
		}
		body := string(bodyBytes)

		// Check if this probe is reflected
		if strings.Contains(body, probe) {
			reflected = append(reflected, key)
		}
	}

	return reflected, nil
}

func (s *Scanner) probeParameter(targetURL, param string) (models.Result, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return models.Result{}, err
	}

	qs := u.Query()
	val := qs.Get(param)

	// Construct payload: "original_value" + "random_prefix" + all_chars + "random_suffix"
	// Using a static prefix/suffix for now for simplicity, but unique enough.
	probeStr := "xssprobe"
	payload := val + probeStr + strings.Join(SpecialChars, "") + probeStr

	var finalURL string
	if s.useRawPayload {
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

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return models.Result{}, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add custom headers
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
	if suggestedPayload == "" {
		suggestedPayload = GetPolyglot(context)
	}

	return models.Result{
		URL:              targetURL,
		Method:           "GET",
		Parameter:        param,
		InjectionType:    models.InjectionQuery,
		Reflected:        true,
		Unfiltered:       unfiltered,
		Context:          context,
		SecurityHeaders:  securityHeaders,
		Exploitable:      exploitable,
		SuggestedPayload: suggestedPayload,
	}, nil
}
