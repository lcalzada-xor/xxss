package scanner

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lcalzada-xor/xxss/models"
)

type Scanner struct {
	client        *http.Client
	headers       map[string]string
	useRawPayload bool
}

func NewScanner(client *http.Client, headers map[string]string) *Scanner {
	return &Scanner{
		client:        client,
		headers:       headers,
		useRawPayload: false,
	}
}

// SetRawPayload enables or disables raw payload mode (no URL encoding)
func (s *Scanner) SetRawPayload(raw bool) {
	s.useRawPayload = raw
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

	// For each parameter, inject a unique value to avoid false positives
	// from common values like "1", "en", "test"
	rand.Seed(time.Now().UnixNano())
	paramProbes := make(map[string]string)
	qs := u.Query()

	for key := range qs {
		// Generate unique probe for this parameter
		paramProbes[key] = fmt.Sprintf("xxss_%d_%d", time.Now().UnixNano(), rand.Intn(10000))
		qs.Set(key, paramProbes[key])
	}

	u.RawQuery = qs.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return reflected, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	// Add custom headers
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return reflected, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return reflected, err
	}
	body := string(bodyBytes)

	// Check which unique probes are reflected
	for key, probe := range paramProbes {
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
	if err != nil {
		return models.Result{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return models.Result{}, err
	}
	body := string(bodyBytes)

	unfiltered := AnalyzeResponse(body, probeStr)

	return models.Result{
		URL:        targetURL,
		Parameter:  param,
		Reflected:  true,
		Unfiltered: unfiltered,
	}, nil
}
