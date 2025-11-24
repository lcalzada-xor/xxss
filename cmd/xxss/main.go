package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lcalzada-xor/xxss/pkg/models"
	"github.com/lcalzada-xor/xxss/pkg/network"
	"github.com/lcalzada-xor/xxss/pkg/output"
	"github.com/lcalzada-xor/xxss/pkg/scanner"
)

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
		blindURL     string
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

	defaultHeaders := strings.Join(scanner.VulnerableHeaders, ",")
	flag.StringVar(&headerList, "hl", defaultHeaders, "Headers to scan (comma-separated)")
	flag.StringVar(&headerList, "headers-list", defaultHeaders, "Headers to scan")

	flag.StringVar(&outputFormat, "o", "url", "Output format: url, human, json")
	flag.StringVar(&outputFormat, "output", "url", "Output format: url, human, json")

	flag.StringVar(&blindURL, "b", "", "Blind XSS callback URL (e.g. https://xss.hunter)")
	flag.StringVar(&blindURL, "blind", "", "Blind XSS callback URL (e.g. https://xss.hunter)")

	var noDOM bool
	flag.BoolVar(&noDOM, "no-dom", false, "Disable DOM XSS scanning (static analysis)")

	var scanDeepDOM bool
	flag.BoolVar(&scanDeepDOM, "deep-dom", false, "Enable Deep DOM XSS scanning (fetch external JS)")

	// Custom Usage function
	flag.Usage = func() {
		banner := "\n" +
			"   \x1b[38;5;93m▄▀▀▄  ▄▀▄  ▄▀▀▄  ▄▀▄  ▄▀▀▀▀▄  ▄▀▀▀▀▄ \x1b[0m\n" +
			"  \x1b[38;5;129m█    █   █ █    █   █ █ █   ▐ █ █   ▐ \x1b[0m\n" +
			"  \x1b[38;5;141m▐     ▀▄▀  ▐     ▀▄▀     ▀▄      ▀▄   \x1b[0m\n" +
			"       \x1b[38;5;129m▄▀ █       ▄▀ █  ▀▄   █  ▀▄   █  \x1b[0m\n" +
			"      \x1b[38;5;93m█  ▄▀      █  ▄▀   █▀▀▀    █▀▀▀   \x1b[0m\n" +
			"    \x1b[38;5;57m▄▀  ▄▀     ▄▀  ▄▀    ▐       ▐      \x1b[0m\n" +
			"   \x1b[38;5;57m█    ▐     █    ▐                    \x1b[0m\n" +
			"           \x1b[38;5;141mv1.8.0\x1b[0m | \x1b[38;5;141m@lcalzada-xor\x1b[0m\n"

		fmt.Fprint(os.Stderr, banner)
		h := `
USAGE:
  xxss [flags]

SCANNING:
  -c,  --concurrency int     Number of concurrent workers (default 40)
  -t,  --timeout duration    Request timeout (default 10s)
  -x,  --proxy string        Proxy URL (e.g. http://127.0.0.1:8080)
  -H,  --header string       Custom header (e.g. 'Cookie: session=123')

REQUEST CONFIGURATION:
  -X,  --method string       HTTP method (GET, POST, PUT, PATCH) (default "GET")
  -d,  --data string         Request body data for POST/PUT/PATCH
  -ct, --content-type string Content-Type for request body (default "application/x-www-form-urlencoded")
  -r,  --raw                 Send payloads without URL encoding

SCOPE & FILTERS:
  -sh, --scan-headers        Scan HTTP headers for XSS (User-Agent, Referer, etc.)
  -hl, --headers-list string Comma-separated list of headers to scan (default "User-Agent,Referer,X-Forwarded-For")
  -a,  --allow string        Comma-separated list of allowed characters (e.g. <,>)
  -i,  --ignore string       Comma-separated list of ignored characters (e.g. ', ")

OUTPUT:
  -o,  --output string       Output format: url, human, json (default "url")
  -v,  --verbose             Verbose output (show progress and details)
  -s,  --silent              Silent mode (suppress banner and errors)
  	-b,  --blind string        Blind XSS callback URL
	--no-dom                   Disable DOM XSS scanning (static analysis)
	--deep-dom                 Enable Deep DOM XSS scanning (fetch external JS)

EXAMPLES:
  echo "http://example.com/?p=val" | xxss
  cat urls.txt | xxss -c 50 -o human
  echo "http://example.com" | xxss -X POST -d "user=test" -o json
  echo "http://example.com" | xxss --scan-headers -v
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

	// Create HTTP client with optimized connection pooling
	client, _ := network.NewClient(timeout, proxy, concurrency, 0)
	sc := scanner.NewScanner(client, headerMap)
	sc.SetRawPayload(rawPayload)
	sc.SetVerbose(verbose)
	sc.SetScanDOM(!noDOM)
	sc.SetScanDeepDOM(scanDeepDOM)

	if blindURL != "" {
		// Validate blind URL
		if _, err := url.Parse(blindURL); err != nil {
			if !silent {
				fmt.Fprintf(os.Stderr, "Error: Invalid blind URL: %v\n", err)
			}
			os.Exit(1)
		}
		sc.SetBlindURL(blindURL)
	}

	// Print banner unless silent
	if !silent {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "   \x1b[38;5;93m▄▀▀▄  ▄▀▄  ▄▀▀▄  ▄▀▄  ▄▀▀▀▀▄  ▄▀▀▀▀▄ \x1b[0m")
		fmt.Fprintln(os.Stderr, "  \x1b[38;5;129m█    █   █ █    █   █ █ █   ▐ █ █   ▐ \x1b[0m")
		fmt.Fprintln(os.Stderr, "  \x1b[38;5;141m▐     ▀▄▀  ▐     ▀▄▀     ▀▄      ▀▄   \x1b[0m")
		fmt.Fprintln(os.Stderr, "       \x1b[38;5;129m▄▀ █       ▄▀ █  ▀▄   █  ▀▄   █  \x1b[0m")
		fmt.Fprintln(os.Stderr, "      \x1b[38;5;93m█  ▄▀      █  ▄▀   █▀▀▀    █▀▀▀   \x1b[0m")
		fmt.Fprintln(os.Stderr, "    \x1b[38;5;57m▄▀  ▄▀     ▄▀  ▄▀    ▐       ▐      \x1b[0m")
		fmt.Fprintln(os.Stderr, "   \x1b[38;5;57m█    ▐     █    ▐                    \x1b[0m")
		fmt.Fprintln(os.Stderr, "           \x1b[38;5;141mv1.8.0\x1b[0m | \x1b[38;5;141m@lcalzada-xor\x1b[0m")
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
		totalURLs     int
		scannedURLs   int
		foundVulns    int
		totalRequests int
		statsMutex    sync.Mutex
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
				var urlPrinted bool
				var urlRequests int

				// 1. Scan GET parameters (default)
				if method == "GET" || method == "" {
					sc.ResetRequestCount()
					results, err := sc.Scan(url)
					if err != nil {
						if verbose && !silent {
							fmt.Fprintf(os.Stderr, "[!] Error scanning GET %s: %v\n", url, err)
						}
					} else {
						reqCount := sc.GetRequestCount()
						urlRequests += reqCount
						statsMutex.Lock()
						totalRequests += reqCount
						statsMutex.Unlock()
						allResults = append(allResults, results...)
					}
				}

				// 2. Scan POST/PUT/PATCH body parameters
				if method != "GET" && method != "" && data != "" {
					sc.ResetRequestCount()
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
						reqCount := sc.GetRequestCount()
						urlRequests += reqCount
						statsMutex.Lock()
						totalRequests += reqCount
						statsMutex.Unlock()
						allResults = append(allResults, results...)
					}
				}

				// 3. Scan HTTP headers
				if scanHeaders {
					sc.ResetRequestCount()
					headers := strings.Split(headerList, ",")
					for _, header := range headers {
						header = strings.TrimSpace(header)
						if header == "" {
							continue
						}

						if verbose && !silent {
							fmt.Fprintf(os.Stderr, "[*] Scanning header: %s\n", header)
						}

						result, err := sc.ScanHeader(url, header)
						if err != nil {
							// Header not reflected or error
							continue
						}

						reqCount := sc.GetRequestCount()
						urlRequests += reqCount
						statsMutex.Lock()
						totalRequests += reqCount
						statsMutex.Unlock()

						if len(result.Unfiltered) > 0 {
							allResults = append(allResults, result)
						}
					}
				}

				if verbose && !silent && urlRequests > 0 {
					fmt.Fprintf(os.Stderr, "[*] %s: %d HTTP requests\n", url, urlRequests)
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
					if outputFormat == "url" {
						if !urlPrinted {
							fmt.Println(res.URL)
							urlPrinted = true
						}
					} else {
						output := output.Format(res, outputFormat)
						if output != "" {
							fmt.Println(output)
						}
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
		fmt.Fprintf(os.Stderr, "[*] Scan complete: %d URLs processed, %d vulnerabilities found, %d HTTP requests\n", scannedURLs, foundVulns, totalRequests)
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
