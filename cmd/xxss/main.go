package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
		veryVerbose  bool
		silent       bool
		charsAllow   string
		charsIgnore  string
		httpAllow    string
		httpIgnore   string
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

	// Verbose flags: -v for verbose, -vv for very verbose
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&veryVerbose, "vv", false, "Very verbose output (detailed debugging)")

	flag.BoolVar(&silent, "s", false, "Silent mode (suppress errors)")
	flag.BoolVar(&silent, "silent", false, "Silent mode (suppress errors)")

	flag.StringVar(&charsAllow, "ca", "", "Comma-separated list of allowed characters (e.g. <,>)")
	flag.StringVar(&charsAllow, "chars-allow", "", "Comma-separated list of allowed characters (e.g. <,>)")

	flag.StringVar(&charsIgnore, "ci", "", "Comma-separated list of ignored characters (e.g. ', \")")
	flag.StringVar(&charsIgnore, "chars-ignore", "", "Comma-separated list of ignored characters (e.g. ', \")")

	flag.StringVar(&httpAllow, "ha", "", "Comma-separated list of allowed HTTP status codes (e.g. 200,201)")
	flag.StringVar(&httpAllow, "http-allow", "", "Comma-separated list of allowed HTTP status codes (e.g. 200,201)")

	flag.StringVar(&httpIgnore, "hi", "", "Comma-separated list of ignored HTTP status codes (e.g. 403,404)")
	flag.StringVar(&httpIgnore, "http-ignore", "", "Comma-separated list of ignored HTTP status codes (e.g. 403,404)")

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
			"           \x1b[38;5;141mv2.0.0\x1b[0m | \x1b[38;5;141m@lcalzada-xor\x1b[0m\n"

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
  -sh, --scan-headers         Scan HTTP headers for XSS (User-Agent, Referer, etc.)
  -hl, --headers-list string  Comma-separated list of headers to scan (default "User-Agent,Referer,X-Forwarded-For")
  -ca, --chars-allow string   Comma-separated list of allowed characters (e.g. <,>)
  -ci, --chars-ignore string  Comma-separated list of ignored characters (e.g. ', ")
  -ha, --http-allow string    Comma-separated list of allowed HTTP status codes (e.g. 200,201)
  -hi, --http-ignore string   Comma-separated list of ignored HTTP status codes (e.g. 403,404)

OUTPUT:
  -o,  --output string       Output format: url, human, json (default "url")
  -v,  --verbose             Verbose output (show progress and details)
  -vv                        Very verbose output (show detailed debugging info)
  -s,  --silent              Silent mode (suppress banner and errors)

ADVANCED SCANNING:
  -b,  --blind string        Blind XSS callback URL (e.g. https://xss.hunter)
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

	// Calculate verbose level
	verboseLevel := 0
	if verbose {
		verboseLevel = 1
	}
	if veryVerbose {
		verboseLevel = 2
	}

	// Parse character filters
	charsAllowList := make(map[string]bool)
	if charsAllow != "" {
		for _, c := range strings.Split(charsAllow, ",") {
			charsAllowList[strings.TrimSpace(c)] = true
		}
	}

	charsIgnoreList := make(map[string]bool)
	if charsIgnore != "" {
		for _, c := range strings.Split(charsIgnore, ",") {
			charsIgnoreList[strings.TrimSpace(c)] = true
		}
	}

	// Parse HTTP status filters
	httpAllowList := make(map[int]bool)
	if httpAllow != "" {
		for _, code := range strings.Split(httpAllow, ",") {
			if statusCode, err := strconv.Atoi(strings.TrimSpace(code)); err == nil {
				httpAllowList[statusCode] = true
			}
		}
	}

	httpIgnoreList := make(map[int]bool)
	if httpIgnore != "" {
		for _, code := range strings.Split(httpIgnore, ",") {
			if statusCode, err := strconv.Atoi(strings.TrimSpace(code)); err == nil {
				httpIgnoreList[statusCode] = true
			}
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

	// Create root context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !silent {
			fmt.Fprintln(os.Stderr, "\n[!] Received interrupt, shutting down...")
		}
		cancel()
	}()

	// Create HTTP client with optimized connection pooling
	client := network.NewClient(timeout, proxy, concurrency, 0)
	sc := scanner.NewScanner(client, headerMap)
	sc.SetRawPayload(rawPayload)
	sc.SetVerboseLevel(verboseLevel)
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
		fmt.Fprintln(os.Stderr, "           \x1b[38;5;141mv2.0.0\x1b[0m | \x1b[38;5;141m@lcalzada-xor\x1b[0m")
		fmt.Fprintln(os.Stderr, "")
		if verboseLevel >= 1 {
			fmt.Fprintf(os.Stderr, "[*] Concurrency: %d workers\n", concurrency)
			fmt.Fprintf(os.Stderr, "[*] Timeout: %v\n", timeout)
			fmt.Fprintf(os.Stderr, "[*] Raw payload: %v\n", rawPayload)
			if verboseLevel >= 2 {
				fmt.Fprintf(os.Stderr, "[*] Verbose level: %d (very verbose)\n", verboseLevel)
			}
			if len(charsAllowList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] Chars allow filter: %v\n", charsAllow)
			}
			if len(charsIgnoreList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] Chars ignore filter: %v\n", charsIgnore)
			}
			if len(httpAllowList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] HTTP allow filter: %v\n", httpAllow)
			}
			if len(httpIgnoreList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] HTTP ignore filter: %v\n", httpIgnore)
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
			for {
				select {
				case <-ctx.Done():
					return
				case url, ok := <-jobs:
					if !ok {
						return
					}

					// Check context before starting work
					if ctx.Err() != nil {
						return
					}

					statsMutex.Lock()
					scannedURLs++
					currentScanned := scannedURLs
					statsMutex.Unlock()

					if verboseLevel >= 1 && !silent {
						fmt.Fprintf(os.Stderr, "[%d] Scanning: %s\n", currentScanned, url)
					}

					var allResults []models.Result
					var urlPrinted bool
					var urlRequests int

					// 1. Scan GET parameters (default)
					if method == "GET" || method == "" {
						sc.ResetRequestCount()
						// Wait, if I change main.go to call Scan(ctx, url) it will break compilation until I update scanner.go.
						// I should update scanner.go FIRST or use multi_replace to update both?
						// I can't update multiple files with replace_file_content.
						// I should update scanner.go first.
						// But I already started editing main.go in this thought process.
						// I will cancel this edit and update scanner.go first?
						// No, I can just leave Scan(url) and rely on the loop check for now,
						// but for true cancellation I need to pass context.
						// Let's look at how to do this properly.
						// I'll update main.go to use `sc.Scan(ctx, url)` and `sc.ScanRequest(ctx, config)`
						// AND update `scanner.go` in the next step.
						// This will cause a temporary compilation error if I run tests in between.
						// That's fine as long as I fix it quickly.
						// actually, let's check imports.
						// I need to import "context", "os/signal", "syscall".

						results, err := sc.Scan(ctx, url)
						if err != nil {
							if verboseLevel >= 1 && !silent {
								// Don't log error if it's just context canceled
								if err != context.Canceled {
									fmt.Fprintf(os.Stderr, "[!] Error scanning GET %s: %v\n", url, err)
								}
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
						results, err := sc.ScanRequest(ctx, config)
						if err != nil {
							if verboseLevel >= 1 && !silent {
								if err != context.Canceled {
									fmt.Fprintf(os.Stderr, "[!] Error scanning %s body: %v\n", method, err)
								}
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

							// Check context
							if ctx.Err() != nil {
								break
							}

							if verboseLevel >= 1 && !silent {
								fmt.Fprintf(os.Stderr, "[*] Scanning header: %s\n", header)
							}

							result, err := sc.ScanHeader(ctx, url, header)
							if err != nil {
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

					if verboseLevel >= 1 && !silent && urlRequests > 0 {
						fmt.Fprintf(os.Stderr, "[*] %s: %d HTTP requests\n", url, urlRequests)
					}

					for _, res := range allResults {
						// Apply HTTP status filters first
						if httpIgnoreList[res.HTTPStatus] {
							continue
						}
						if len(httpAllowList) > 0 && !httpAllowList[res.HTTPStatus] {
							continue
						}

						// Apply character filters
						filteredUnfiltered := []string{}
						for _, char := range res.Unfiltered {
							if charsIgnoreList[char] {
								continue
							}
							if len(charsAllowList) > 0 && !charsAllowList[char] {
								continue
							}
							filteredUnfiltered = append(filteredUnfiltered, char)
						}

						if len(filteredUnfiltered) == 0 && len(res.DOMFindings) == 0 {
							continue
						}

						// Update result to show what remains
						res.Unfiltered = filteredUnfiltered

						statsMutex.Lock()
						foundVulns++
						statsMutex.Unlock()

						if verboseLevel >= 1 && !silent {
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
			}
		}()
	}

	// Read from Stdin
	scanner := bufio.NewScanner(os.Stdin)
	go func() {
		for scanner.Scan() {
			if ctx.Err() != nil {
				break
			}
			url := scanner.Text()
			if url != "" {
				statsMutex.Lock()
				totalURLs++
				statsMutex.Unlock()
				select {
				case jobs <- url:
				case <-ctx.Done():
					return
				}
			}
		}
		close(jobs)
	}()

	// Wait for workers to finish or context to be canceled
	// We can just wait on wg because workers will return on ctx.Done()
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
