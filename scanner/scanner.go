package scanner

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"xxss/models"
)

type Scanner struct {
	client *http.Client
}

func NewScanner(client *http.Client) *Scanner {
	return &Scanner{
		client: client,
	}
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

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return reflected, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

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

	u, err := url.Parse(targetURL)
	if err != nil {
		return reflected, err
	}

	for key, values := range u.Query() {
		for _, v := range values {
			// Basic reflection check: is the value present?
			if strings.Contains(body, v) {
				reflected = append(reflected, key)
				break // Found one instance of this param being reflected
			}
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

	qs.Set(param, payload)
	u.RawQuery = qs.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return models.Result{}, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

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
