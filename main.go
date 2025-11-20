package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lcalzada-xor/xxss/models"
	"github.com/lcalzada-xor/xxss/network"
	"github.com/lcalzada-xor/xxss/scanner"
)

// formatOutput formats the result based on the selected output format
func formatOutput(res models.Result, format string) string {
	switch format {
	case "url":
		// URL-only format for dalfox pipeline
		return res.URL

	case "human":
		// Human-readable format
		var sb strings.Builder
		sb.WriteString("\n[+] XSS Vulnerability Found\n")
		sb.WriteString(fmt.Sprintf("    URL:        %s\n", res.URL))
		sb.WriteString(fmt.Sprintf("    Method:     %s\n", res.Method))
		sb.WriteString(fmt.Sprintf("    Parameter:  %s\n", res.Parameter))
		sb.WriteString(fmt.Sprintf("    Injection:  %s\n", res.InjectionType))
		sb.WriteString(fmt.Sprintf("    Context:    %s\n", res.Context))
		sb.WriteString(fmt.Sprintf("    Exploitable: %v\n", res.Exploitable))
		sb.WriteString(fmt.Sprintf("    Unfiltered: %v\n", res.Unfiltered))
		if res.SuggestedPayload != "" {
			sb.WriteString(fmt.Sprintf("    Payload:    %s\n", res.SuggestedPayload))
		}
		if res.SecurityHeaders.CSP != "" {
			sb.WriteString(fmt.Sprintf("    CSP:        %s\n", res.SecurityHeaders.CSP))
		}
		return sb.String()

	case "json":
		// JSON format
		output, err := json.Marshal(res)
		if err != nil {
			return ""
		}
		return string(output)

	default:
		// Default to URL format
		return res.URL
	}
}

func main() {
	var (
		concurrency  int
		timeout      time.Duration
		verbose      bool
		silent       bool
		allow        string
		ignore       string
		rawPayload   bool
		method       string
		data         string
		contentType  string
		scanHeaders  bool
		headerList   string
		outputFormat string
	)

	// Define flags with both short and long names
	flag.IntVar(&concurrency, "c", 40, "Concurrency level")
	flag.IntVar(&concurrency, "concurrency", 40, "Concurrency level")

	flag.DurationVar(&timeout, "t", 10*time.Second, "Request timeout")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "Request timeout")

	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")

	flag.BoolVar(&silent, "s", false, "Silent mode (suppress errors)")
	flag.BoolVar(&silent, "silent", false, "Silent mode (suppress errors)")

	flag.StringVar(&allow, "a", "", "Comma-separated list of allowed characters (e.g. <,>)")
	flag.StringVar(&allow, "allow", "", "Comma-separated list of allowed characters (e.g. <,>)")

	flag.StringVar(&ignore, "i", "", "Comma-separated list of ignored characters (e.g. ', \")")
	flag.StringVar(&ignore, "ignore", "", "Comma-separated list of ignored characters (e.g. ', \")")

	var proxy string
	flag.StringVar(&proxy, "x", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")

	var headers headerFlags
	flag.Var(&headers, "H", "Custom header (e.g. 'Cookie: session=123')")
	flag.Var(&headers, "header", "Custom header (e.g. 'Cookie: session=123')")

	flag.BoolVar(&rawPayload, "r", false, "Send payloads without URL encoding")
	flag.BoolVar(&rawPayload, "raw", false, "Send payloads without URL encoding")

	flag.StringVar(&method, "X", "GET", "HTTP method (GET, POST, PUT, PATCH)")
	flag.StringVar(&method, "method", "GET", "HTTP method (GET, POST, PUT, PATCH)")

	flag.StringVar(&data, "d", "", "Request body for POST/PUT/PATCH")
	flag.StringVar(&data, "data", "", "Request body for POST/PUT/PATCH")

	flag.StringVar(&contentType, "ct", "application/x-www-form-urlencoded", "Content-Type for request body")
	flag.StringVar(&contentType, "content-type", "application/x-www-form-urlencoded", "Content-Type for request body")

	flag.BoolVar(&scanHeaders, "sh", false, "Scan HTTP headers for XSS")
	flag.BoolVar(&scanHeaders, "scan-headers", false, "Scan HTTP headers for XSS")

	flag.StringVar(&headerList, "hl", "User-Agent,Referer,X-Forwarded-For", "Headers to scan (comma-separated)")
	flag.StringVar(&headerList, "headers-list", "User-Agent,Referer,X-Forwarded-For", "Headers to scan")

	flag.StringVar(&outputFormat, "o", "url", "Output format: url, human, json")
	flag.StringVar(&outputFormat, "output", "url", "Output format: url, human, json")

	// Custom Usage function
	flag.Usage = func() {
		h := `xxss - Fast XSS reflected params prober

Usage:
  xxss [flags]

Flags:
  -c, --concurrency int   Concurrency level (default 40)
  -t, --timeout duration  Request timeout (default 10s)
  -v, --verbose           Verbose output
  -s, --silent            Silent mode (suppress errors)
  -a, --allow string      Comma-separated list of allowed characters (e.g. <,>)
  -i, --ignore string     Comma-separated list of ignored characters (e.g. ', ")
  -x, --proxy string      Proxy URL (e.g. http://127.0.0.1:8080)
  -H, --header string     Custom header (e.g. 'Cookie: session=123')
  -r, --raw               Send payloads without URL encoding

Examples:
  echo "http://example.com/?p=val" | xxss
  cat urls.txt | xxss -c 50 -silent
  cat urls.txt | xxss --allow "<,>" --ignore "'"
  echo "http://example.com" | xxss -x http://127.0.0.1:8080
  echo "http://example.com" | xxss -H "Cookie: session=123"
  cat urls.txt | xxss --raw  # Send special chars unencoded
`
		fmt.Fprint(os.Stderr, h)
	}

	flag.Parse()

	// Parse filters
	allowList := make(map[string]bool)
	if allow != "" {
		for _, c := range strings.Split(allow, ",") {
			allowList[c] = true
		}
	}

	ignoreList := make(map[string]bool)
	if ignore != "" {
		for _, c := range strings.Split(ignore, ",") {
			ignoreList[c] = true
		}
	}

	// Parse headers
	headerMap := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	client := network.NewClient(timeout, proxy)
	sc := scanner.NewScanner(client, headerMap)
	sc.SetRawPayload(rawPayload)

	// Print banner unless silent
	if !silent {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  ██╗  ██╗██╗  ██╗███████╗███████╗")
		fmt.Fprintln(os.Stderr, "  ╚██╗██╔╝╚██╗██╔╝██╔════╝██╔════╝")
		fmt.Fprintln(os.Stderr, "   ╚███╔╝  ╚███╔╝ ███████╗███████╗")
		fmt.Fprintln(os.Stderr, "   ██╔██╗  ██╔██╗ ╚════██║╚════██║")
		fmt.Fprintln(os.Stderr, "  ██╔╝ ██╗██╔╝ ██╗███████║███████║")
		fmt.Fprintln(os.Stderr, "  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Fast XSS Reflected Params Scanner")
		fmt.Fprintln(os.Stderr, "  v1.3.0 | github.com/lcalzada-xor/xxss")
		fmt.Fprintln(os.Stderr, "")
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] Concurrency: %d workers\n", concurrency)
			fmt.Fprintf(os.Stderr, "[*] Timeout: %v\n", timeout)
			fmt.Fprintf(os.Stderr, "[*] Raw payload: %v\n", rawPayload)
			if len(allowList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] Allow filter: %v\n", allow)
			}
			if len(ignoreList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] Ignore filter: %v\n", ignore)
			}
			fmt.Fprintln(os.Stderr, "")
		}
	}

	jobs := make(chan string)
	var wg sync.WaitGroup

	// Statistics
	var (
		totalURLs   int
		scannedURLs int
		foundVulns  int
		statsMutex  sync.Mutex
	)

	// Worker pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				statsMutex.Lock()
				scannedURLs++
				currentScanned := scannedURLs
				statsMutex.Unlock()

				if verbose && !silent {
					fmt.Fprintf(os.Stderr, "[%d] Scanning: %s\n", currentScanned, url)
				}

				var allResults []models.Result

				// 1. Scan GET parameters (default)
				if method == "GET" || method == "" {
					results, err := sc.Scan(url)
					if err != nil {
						if verbose && !silent {
							fmt.Fprintf(os.Stderr, "[!] Error scanning GET %s: %v\n", url, err)
						}
					} else {
						allResults = append(allResults, results...)
					}
				}

				// 2. Scan POST/PUT/PATCH body parameters
				if method != "GET" && method != "" && data != "" {
					config := &models.RequestConfig{
						Method:      models.HTTPMethod(method),
						URL:         url,
						Body:        data,
						ContentType: models.ContentType(contentType),
					}
					results, err := sc.ScanRequest(config)
					if err != nil {
						if verbose && !silent {
							fmt.Fprintf(os.Stderr, "[!] Error scanning %s body: %v\n", method, err)
						}
					} else {
						allResults = append(allResults, results...)
					}
				}

				// 3. Scan HTTP headers
				if scanHeaders {
					headers := strings.Split(headerList, ",")
					results, err := sc.ScanHeaders(url, headers)
					if err != nil {
						if verbose && !silent {
							fmt.Fprintf(os.Stderr, "[!] Error scanning headers: %v\n", err)
						}
					} else {
						allResults = append(allResults, results...)
					}
				}

				for _, res := range allResults {
					// Apply filters
					filteredUnfiltered := []string{}
					for _, char := range res.Unfiltered {
						if ignoreList[char] {
							continue
						}
						if len(allowList) > 0 && !allowList[char] {
							continue
						}
						filteredUnfiltered = append(filteredUnfiltered, char)
					}

					if len(filteredUnfiltered) == 0 {
						continue
					}

					// Update result to show what remains
					res.Unfiltered = filteredUnfiltered

					statsMutex.Lock()
					foundVulns++
					statsMutex.Unlock()

					if verbose && !silent {
						fmt.Fprintf(os.Stderr, "[+] Found: %s (param: %s, chars: %v)\n", res.URL, res.Parameter, res.Unfiltered)
					}

					// Output based on selected format
					output := formatOutput(res, outputFormat)
					if output != "" {
						fmt.Println(output)
					}
				}
			}
		}()
	}

	// Read from Stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := scanner.Text()
		if url != "" {
			statsMutex.Lock()
			totalURLs++
			statsMutex.Unlock()
			jobs <- url
		}
	}

	close(jobs)
	wg.Wait()

	// Print statistics
	if !silent {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "[*] Scan complete: %d URLs processed, %d vulnerabilities found\n", scannedURLs, foundVulns)
	}
}

// headerFlags allows setting multiple headers
type headerFlags []string

func (h *headerFlags) String() string {
	return fmt.Sprint(*h)
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}
