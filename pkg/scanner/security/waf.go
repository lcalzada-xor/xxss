package security

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

// WAF represents a detected Web Application Firewall
type WAF struct {
	Name     string
	Detected bool
}

// DetectWAF analyzes HTTP response headers to identify the presence of a WAF
func DetectWAF(headers http.Header) *WAF {
	for key, values := range headers {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(strings.Join(values, " "))

		// Cloudflare
		if keyLower == "server" && strings.Contains(valueLower, "cloudflare") {
			return &WAF{Name: "Cloudflare", Detected: true}
		}
		if keyLower == "cf-ray" || keyLower == "cf-cache-status" {
			return &WAF{Name: "Cloudflare", Detected: true}
		}

		// AWS WAF
		if keyLower == "x-amzn-requestid" || keyLower == "x-amz-cf-id" {
			return &WAF{Name: "AWS WAF", Detected: true}
		}
		if strings.Contains(valueLower, "awselb") || strings.Contains(valueLower, "awsalb") {
			return &WAF{Name: "AWS WAF", Detected: true}
		}

		// Akamai
		if keyLower == "x-akamai-transformed" || keyLower == "akamai-origin-hop" {
			return &WAF{Name: "Akamai", Detected: true}
		}
		if strings.Contains(valueLower, "akamai") {
			return &WAF{Name: "Akamai", Detected: true}
		}

		// Imperva/Incapsula
		if keyLower == "x-iinfo" || keyLower == "x-cdn" && strings.Contains(valueLower, "incapsula") {
			return &WAF{Name: "Imperva", Detected: true}
		}
		if strings.Contains(valueLower, "incapsula") || strings.Contains(valueLower, "imperva") {
			return &WAF{Name: "Imperva", Detected: true}
		}

		// ModSecurity
		if strings.Contains(valueLower, "mod_security") || strings.Contains(valueLower, "modsecurity") {
			return &WAF{Name: "ModSecurity", Detected: true}
		}

		// F5 BIG-IP
		if keyLower == "x-cnection" || keyLower == "x-wa-info" {
			return &WAF{Name: "F5 BIG-IP", Detected: true}
		}
		if strings.Contains(valueLower, "bigip") || strings.Contains(valueLower, "f5") {
			return &WAF{Name: "F5 BIG-IP", Detected: true}
		}

		// Sucuri
		if keyLower == "x-sucuri-id" || keyLower == "x-sucuri-cache" {
			return &WAF{Name: "Sucuri", Detected: true}
		}
		if strings.Contains(valueLower, "sucuri") {
			return &WAF{Name: "Sucuri", Detected: true}
		}

		// Barracuda
		if strings.Contains(valueLower, "barracuda") || keyLower == "barra-counter" {
			return &WAF{Name: "Barracuda", Detected: true}
		}
	}

	return &WAF{Name: "", Detected: false}
}

// ProbeWAF actively probes the target to detect WAFs by sending a suspicious request.
// It returns a WAF struct if a block is detected.
func ProbeWAF(client *http.Client, targetURL string) *WAF {
	u, err := url.Parse(targetURL)
	if err != nil {
		return &WAF{Name: "", Detected: false}
	}

	// Add a suspicious parameter
	q := u.Query()
	q.Set("waf_probe", "<script>alert(1)</script>")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return &WAF{Name: "", Detected: false}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return &WAF{Name: "", Detected: false}
	}
	defer resp.Body.Close()

	// Check for blocking status codes
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 501 {
		// Analyze body for specific WAF signatures
		bodyBytes, _ := io.ReadAll(resp.Body)
		body := strings.ToLower(string(bodyBytes))

		if strings.Contains(body, "cloudflare") {
			return &WAF{Name: "Cloudflare (Active)", Detected: true}
		}
		if strings.Contains(body, "incapsula") || strings.Contains(body, "imperva") {
			return &WAF{Name: "Imperva (Active)", Detected: true}
		}
		if strings.Contains(body, "mod_security") || strings.Contains(body, "modsecurity") {
			return &WAF{Name: "ModSecurity (Active)", Detected: true}
		}
		if strings.Contains(body, "sucuri") {
			return &WAF{Name: "Sucuri (Active)", Detected: true}
		}
		if strings.Contains(body, "aws waf") {
			return &WAF{Name: "AWS WAF (Active)", Detected: true}
		}
		if strings.Contains(body, "akamai") {
			return &WAF{Name: "Akamai (Active)", Detected: true}
		}

		// Generic detection
		return &WAF{Name: "Generic WAF (Blocked Request)", Detected: true}
	}

	return &WAF{Name: "", Detected: false}
}
