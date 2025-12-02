package runner

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/lcalzada-xor/xxss/v2/pkg/config"
	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/network"
	"github.com/lcalzada-xor/xxss/v2/pkg/output"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner"
)

// Runner handles the execution of the scanning process
type Runner struct {
	options *Options
}

// NewRunner creates a new Runner instance
func NewRunner(options *Options) *Runner {
	return &Runner{
		options: options,
	}
}

// Run executes the scan
func (r *Runner) Run() {
	// Calculate verbose level
	verboseLevel := 0
	if r.options.Verbose {
		verboseLevel = 1
	}
	if r.options.VeryVerbose {
		verboseLevel = 2
	}

	// Parse character filters
	charsAllowList := make(map[string]bool)
	if r.options.CharsAllow != "" {
		for _, c := range strings.Split(r.options.CharsAllow, ",") {
			charsAllowList[strings.TrimSpace(c)] = true
		}
	}

	charsIgnoreList := make(map[string]bool)
	if r.options.CharsIgnore != "" {
		for _, c := range strings.Split(r.options.CharsIgnore, ",") {
			charsIgnoreList[strings.TrimSpace(c)] = true
		}
	}

	// Parse HTTP status filters
	httpAllowList := make(map[int]bool)
	if r.options.HTTPAllow != "" {
		for _, code := range strings.Split(r.options.HTTPAllow, ",") {
			if statusCode, err := strconv.Atoi(strings.TrimSpace(code)); err == nil {
				httpAllowList[statusCode] = true
			}
		}
	}

	httpIgnoreList := make(map[int]bool)
	if r.options.HTTPIgnore != "" {
		for _, code := range strings.Split(r.options.HTTPIgnore, ",") {
			if statusCode, err := strconv.Atoi(strings.TrimSpace(code)); err == nil {
				httpIgnoreList[statusCode] = true
			}
		}
	}

	// Parse headers
	headerMap := make(map[string]string)
	for _, h := range r.options.Headers {
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
		if !r.options.Silent {
			fmt.Fprintln(os.Stderr, "\n[!] Received interrupt, shutting down...")
		}
		cancel()
	}()

	// Create HTTP client with optimized connection pooling
	client := network.NewClient(r.options.Timeout, r.options.Proxy, r.options.Concurrency, 0)

	if r.options.BlindURL != "" {
		// Validate blind URL
		if _, err := url.Parse(r.options.BlindURL); err != nil {
			if !r.options.Silent {
				fmt.Fprintf(os.Stderr, "Error: Invalid blind URL: %v\n", err)
			}
			os.Exit(1)
		}
	}

	// Print banner unless silent
	if !r.options.Silent {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "   \x1b[38;5;93m▄▀▀▄  ▄▀▄  ▄▀▀▄  ▄▀▄  ▄▀▀▀▀▄  ▄▀▀▀▀▄ \x1b[0m")
		fmt.Fprintln(os.Stderr, "  \x1b[38;5;129m█    █   █ █    █   █ █ █   ▐ █ █   ▐ \x1b[0m")
		fmt.Fprintln(os.Stderr, "  \x1b[38;5;141m▐     ▀▄▀  ▐     ▀▄▀     ▀▄      ▀▄   \x1b[0m")
		fmt.Fprintln(os.Stderr, "       \x1b[38;5;129m▄▀ █       ▄▀ █  ▀▄   █  ▀▄   █  \x1b[0m")
		fmt.Fprintln(os.Stderr, "      \x1b[38;5;93m█  ▄▀      █  ▄▀   █▀▀▀    █▀▀▀   \x1b[0m")
		fmt.Fprintln(os.Stderr, "    \x1b[38;5;57m▄▀  ▄▀     ▄▀  ▄▀    ▐       ▐      \x1b[0m")
		fmt.Fprintln(os.Stderr, "   \x1b[38;5;57m█    ▐     █    ▐                    \x1b[0m")
		fmt.Fprintf(os.Stderr, "           \x1b[38;5;141m%s\x1b[0m | \x1b[38;5;141m%s\x1b[0m\n", config.Version, config.Author)
		fmt.Fprintln(os.Stderr, "")
		if verboseLevel >= 1 {
			fmt.Fprintf(os.Stderr, "[*] Concurrency: %d workers\n", r.options.Concurrency)
			fmt.Fprintf(os.Stderr, "[*] Timeout: %v\n", r.options.Timeout)
			fmt.Fprintf(os.Stderr, "[*] Raw payload: %v\n", r.options.RawPayload)
			if verboseLevel >= 2 {
				fmt.Fprintf(os.Stderr, "[*] Verbose level: %d (very verbose)\n", verboseLevel)
			}
			if len(charsAllowList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] Chars allow filter: %v\n", r.options.CharsAllow)
			}
			if len(charsIgnoreList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] Chars ignore filter: %v\n", r.options.CharsIgnore)
			}
			if len(httpAllowList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] HTTP allow filter: %v\n", r.options.HTTPAllow)
			}
			if len(httpIgnoreList) > 0 {
				fmt.Fprintf(os.Stderr, "[*] HTTP ignore filter: %v\n", r.options.HTTPIgnore)
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

	// Unified Technology Results
	var (
		allTechResults []output.TechResult
		techMutex      sync.Mutex
	)

	// Worker pool
	for i := 0; i < r.options.Concurrency; i++ {
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

					// Create a new scanner for this worker to avoid shared state issues
					sc := scanner.NewScanner(client, headerMap)
					sc.SetRawPayload(r.options.RawPayload)
					sc.SetVerboseLevel(verboseLevel)
					sc.SetScanDOM(!r.options.NoDOM)
					sc.SetScanDeepDOM(r.options.ScanDeepDOM)
					if r.options.BlindURL != "" {
						sc.SetBlindURL(r.options.BlindURL)
					}

					statsMutex.Lock()
					scannedURLs++
					currentScanned := scannedURLs
					statsMutex.Unlock()

					if verboseLevel >= 1 && !r.options.Silent {
						fmt.Fprintf(os.Stderr, "[%d] Scanning: %s\n", currentScanned, url)
					}

					var allResults []models.Result
					var urlPrinted bool
					var urlRequests int

					// 0. Detect Libraries Mode
					if r.options.DetectLibraries {
						techs, err := sc.DetectTechnologies(ctx, url)

						// Always count requests
						reqCount := sc.GetRequestCount()
						urlRequests += reqCount
						statsMutex.Lock()
						totalRequests += reqCount
						statsMutex.Unlock()

						if err != nil {
							if !r.options.Silent {
								if err != context.Canceled {
									fmt.Fprintf(os.Stderr, "[!] Error detecting libraries for %s: %v\n", url, err)
								}
							}
						} else if len(techs) > 0 {
							techMutex.Lock()
							allTechResults = append(allTechResults, output.TechResult{
								URL:          url,
								Technologies: techs,
							})
							techMutex.Unlock()
						}

						// Skip other scans
						continue
					}

					// 1. Scan GET parameters (default)
					if r.options.Method == "GET" || r.options.Method == "" {
						sc.ResetRequestCount()
						results, err := sc.Scan(ctx, url)

						// Always count requests, even on error
						reqCount := sc.GetRequestCount()
						urlRequests += reqCount
						statsMutex.Lock()
						totalRequests += reqCount
						statsMutex.Unlock()

						if err != nil {
							if !r.options.Silent {
								// Don't log error if it's just context canceled
								if err != context.Canceled {
									fmt.Fprintf(os.Stderr, "[!] Error scanning GET %s: %v\n", url, err)
								}
							}
						} else {
							allResults = append(allResults, results...)
						}
					}

					// 2. Scan POST/PUT/PATCH body parameters
					if r.options.Method != "GET" && r.options.Method != "" && r.options.Data != "" {
						sc.ResetRequestCount()
						config := &models.RequestConfig{
							Method:      models.HTTPMethod(r.options.Method),
							URL:         url,
							Body:        r.options.Data,
							ContentType: models.ContentType(r.options.ContentType),
						}
						results, err := sc.ScanRequest(ctx, config)

						// Always count requests, even on error
						reqCount := sc.GetRequestCount()
						urlRequests += reqCount
						statsMutex.Lock()
						totalRequests += reqCount
						statsMutex.Unlock()

						if err != nil {
							if !r.options.Silent {
								if err != context.Canceled {
									fmt.Fprintf(os.Stderr, "[!] Error scanning %s body: %v\n", r.options.Method, err)
								}
							}
						} else {
							allResults = append(allResults, results...)
						}
					}

					// 3. Scan HTTP headers
					if r.options.ScanHeaders {
						sc.ResetRequestCount()
						headers := strings.Split(r.options.HeaderList, ",")
						for _, header := range headers {
							header = strings.TrimSpace(header)
							if header == "" {
								continue
							}

							// Check context
							if ctx.Err() != nil {
								break
							}

							if verboseLevel >= 1 && !r.options.Silent {
								fmt.Fprintf(os.Stderr, "[*] Scanning header: %s\n", header)
							}

							result, err := sc.ScanHeader(ctx, url, header)

							// Always count requests
							reqCount := sc.GetRequestCount()
							urlRequests += reqCount
							statsMutex.Lock()
							totalRequests += reqCount
							statsMutex.Unlock()

							if err != nil {
								continue
							}

							if len(result.Unfiltered) > 0 {
								allResults = append(allResults, result)
							}
						}
					}

					if verboseLevel >= 1 && !r.options.Silent && urlRequests > 0 {
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

						if verboseLevel >= 1 && !r.options.Silent {
							fmt.Fprintf(os.Stderr, "[+] Found: %s (param: %s, chars: %v)\n", res.URL, res.Parameter, res.Unfiltered)
						}

						// Output based on selected format
						if r.options.OutputFormat == "url" {
							if !urlPrinted {
								fmt.Println(res.URL)
								urlPrinted = true
							}
						} else {
							output := output.Format(res, r.options.OutputFormat)
							if output != "" {
								fmt.Println(output)
							}
						}
					}

					// If output is human, also print detected technologies
					// NOTE: For normal scans, we still print per URL because we want to see it as it happens.
					// But for -dt mode, we accumulate.
					// Wait, the user asked for -dt to be unified.
					// What about normal scans with -o human?
					// The user specifically asked "quiero que el -dt saque una unica tabla".
					// So I will only change the behavior for -dt.
					// For normal scans, I will keep the per-URL output for now unless requested otherwise.
					if !r.options.DetectLibraries && r.options.OutputFormat == "human" {
						techs, err := sc.DetectTechnologies(ctx, url)
						if err == nil && len(techs) > 0 {
							statsMutex.Lock()
							totalRequests++ // DetectTechnologies makes 1 request
							statsMutex.Unlock()

							// Use the single-URL formatter for normal scans
							// But wait, I removed FormatTechnologies and replaced it with FormatAllTechnologies.
							// I need to adapt this call.
							singleResult := []output.TechResult{{URL: url, Technologies: techs}}
							out := output.FormatAllTechnologies(singleResult, "human")
							if out != "" {
								fmt.Println(out)
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

	// Print unified technology results if in DetectLibraries mode
	if r.options.DetectLibraries && len(allTechResults) > 0 {
		out := output.FormatAllTechnologies(allTechResults, r.options.OutputFormat)
		if out != "" {
			fmt.Println(out)
		}
	}

	// Print statistics
	if !r.options.Silent {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "[*] Scan complete: %d URLs processed, %d vulnerabilities found, %d HTTP requests\n", scannedURLs, foundVulns, totalRequests)
	}
}
