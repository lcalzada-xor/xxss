package network

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// NewClient creates a new HTTP client with optimized connection pooling and optional rate limiting.
// The pooling parameters scale dynamically based on concurrency level.
// rateLimit: requests per second (0 = unlimited)
func NewClient(timeout time.Duration, proxyURL string, concurrency int, rateLimit float64) (*http.Client, *RateLimiter) {
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

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects automatically
		},
	}

	// Create rate limiter
	rateLimiter := NewRateLimiter(rateLimit)

	return client, rateLimiter
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
