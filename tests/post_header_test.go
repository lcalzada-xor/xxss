package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/pkg/models"
	"github.com/lcalzada-xor/xxss/pkg/network"
	"github.com/lcalzada-xor/xxss/pkg/scanner"
)

// Test POST form-urlencoded scanning
func TestPOSTFormScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		name := r.FormValue("name")
		email := r.FormValue("email")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>" + name + "</h1><p>" + email + "</p></body></html>"))
	}))
	defer server.Close()

	config := &models.RequestConfig{
		Method:      models.MethodPOST,
		URL:         server.URL,
		Body:        "name=test&email=test@test.com",
		ContentType: models.ContentTypeForm,
	}

	client := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.ScanRequest(context.Background(), config)
	if err != nil {
		t.Fatalf("ScanRequest failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	// Verify result structure
	for _, res := range results {
		if res.Method != "POST" {
			t.Errorf("Expected method POST, got %s", res.Method)
		}
		if res.InjectionType != models.InjectionBody {
			t.Errorf("Expected injection type body, got %s", res.InjectionType)
		}
		if res.Context == "" {
			t.Error("Expected context to be set")
		}
		t.Logf("Found vulnerable param: %s (context: %s, exploitable: %v)", res.Parameter, res.Context, res.Exploitable)
	}
}

// Test POST JSON scanning
func TestPOSTJSONScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data map[string]interface{}
		json.NewDecoder(r.Body).Decode(&data)

		name, _ := data["name"].(string)
		email, _ := data["email"].(string)

		w.Header().Set("Content-Type", "text/html")
		response := `<html><body><div class="user">` + name + `</div><div class="email">` + email + `</div></body></html>`
		w.Write([]byte(response))
	}))
	defer server.Close()

	config := &models.RequestConfig{
		Method:      models.MethodPOST,
		URL:         server.URL,
		Body:        `{"name":"test","email":"test@test.com"}`,
		ContentType: models.ContentTypeJSON,
	}

	client := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.ScanRequest(context.Background(), config)
	if err != nil {
		t.Fatalf("ScanRequest failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	t.Logf("Found %d vulnerable parameters in JSON POST", len(results))
}

// Test PUT request scanning
func TestPUTScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow WAF probes (GET)
		if r.Method == "GET" && r.URL.Query().Get("waf_probe") != "" {
			w.WriteHeader(200)
			return
		}

		if r.Method != "PUT" {
			t.Errorf("Expected PUT method, got %s", r.Method)
		}

		var data map[string]interface{}
		json.NewDecoder(r.Body).Decode(&data)

		title, _ := data["title"].(string)

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>" + title + "</h1></body></html>"))
	}))
	defer server.Close()

	config := &models.RequestConfig{
		Method:      models.MethodPUT,
		URL:         server.URL,
		Body:        `{"title":"Updated Title"}`,
		ContentType: models.ContentTypeJSON,
	}

	client := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	results, err := sc.ScanRequest(context.Background(), config)
	if err != nil {
		t.Fatalf("ScanRequest failed: %v", err)
	}

	if len(results) > 0 {
		t.Logf("Found vulnerable param in PUT: %s", results[0].Parameter)
	}
}

// Test header injection scanning
func TestHeaderInjectionScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		referer := r.Header.Get("Referer")
		xff := r.Header.Get("X-Forwarded-For")

		w.Header().Set("Content-Type", "text/html")
		response := `<html><body>
			<div>UA: ` + ua + `</div>
			<div>Referer: ` + referer + `</div>
			<div>XFF: ` + xff + `</div>
		</body></html>`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	headers := []string{"User-Agent", "Referer", "X-Forwarded-For"}
	var results []models.Result
	for _, h := range headers {
		res, err := sc.ScanHeader(context.Background(), server.URL, h)
		if err != nil {
			// It might fail if not reflected, but in this test we expect reflection
			continue
		}
		if len(res.Unfiltered) > 0 {
			results = append(results, res)
		}
	}

	if len(results) == 0 {
		t.Fatal("Expected at least one vulnerable header")
	}

	for _, res := range results {
		if res.InjectionType != models.InjectionHeader {
			t.Errorf("Expected injection type header, got %s", res.InjectionType)
		}
		t.Logf("Found vulnerable header: %s (context: %s, exploitable: %v)", res.Parameter, res.Context, res.Exploitable)
	}
}

// Test mixed scenario: GET + headers
func TestMixedScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		ua := r.Header.Get("User-Agent")

		w.Header().Set("Content-Type", "text/html")
		response := `<html><body>
			<div>Query: ` + query + `</div>
			<div>UA: ` + ua + `</div>
		</body></html>`
		w.Write([]byte(response))
	}))
	defer server.Close()

	client := network.NewClient(2*time.Second, "", 10, 0)
	sc := scanner.NewScanner(client, map[string]string{})

	// Scan GET parameters
	getResults, err := sc.Scan(context.Background(), server.URL + "/?q=test")
	if err != nil {
		t.Fatalf("GET scan failed: %v", err)
	}

	// Scan headers
	headerResult, err := sc.ScanHeader(context.Background(), server.URL, "User-Agent")
	if err != nil {
		t.Fatalf("Header scan failed: %v", err)
	}
	var headerResults []models.Result
	if len(headerResult.Unfiltered) > 0 {
		headerResults = append(headerResults, headerResult)
	}

	totalResults := len(getResults) + len(headerResults)
	if totalResults == 0 {
		t.Fatal("Expected at least one result from mixed scan")
	}

	t.Logf("Mixed scan found %d GET params and %d headers", len(getResults), len(headerResults))
}
