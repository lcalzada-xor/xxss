package network

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client wraps http.Client with retry logic and rate limiting.
type Client struct {
	HTTPClient  *http.Client
	RateLimiter *RateLimiter
}

// NewClient creates a new Client instance with optimized connection pooling and optional rate limiting.
// rateLimit: requests per second (0 = unlimited)
func NewClient(timeout time.Duration, proxyURL string, concurrency int, rateLimit float64) *Client {
	// Calculate optimal pool sizes based on concurrency
	maxIdleConns := concurrency * 2
	maxIdleConnsPerHost := max(concurrency/2, 10)
	maxConnsPerHost := concurrency

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,

		// Connection pooling - scales with concurrency
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		MaxConnsPerHost:     maxConnsPerHost,
		IdleConnTimeout:     30 * time.Second,

		// Additional timeouts for better performance
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,

		// Performance optimizations
		DisableCompression: false,
		DisableKeepAlives:  false,
	}

	if proxyURL != "" {
		if pURL, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects automatically
		},
	}

	return &Client{
		HTTPClient:  httpClient,
		RateLimiter: NewRateLimiter(rateLimit),
	}
}

// Do sends an HTTP request with automatic retries and rate limiting.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// Apply rate limiting
	if c.RateLimiter != nil {
		if err := c.RateLimiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}

	var resp *http.Response
	var err error
	maxRetries := 3

	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			// Exponential backoff: 100ms, 200ms, 400ms
			backoff := time.Duration(math.Pow(2, float64(i-1))*100) * time.Millisecond
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(backoff):
			}
		}

		resp, err = c.HTTPClient.Do(req)

		// Success
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		// Don't retry 4xx errors (except maybe 429, but let's stick to 5xx/network for now)
		if err == nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return resp, nil
		}

		// Close body if we are going to retry
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Return last error or response
	if err != nil {
		return nil, fmt.Errorf("request failed after %d retries: %v", maxRetries, err)
	}
	return resp, nil
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
