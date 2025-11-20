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

	"github.com/lcalzada-xor/xxss/network"
	"github.com/lcalzada-xor/xxss/scanner"
)

func main() {
	var (
		concurrency int
		timeout     time.Duration
		verbose     bool
		silent      bool
		allow       string
		ignore      string
		rawPayload  bool
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

	jobs := make(chan string)
	var wg sync.WaitGroup

	// Worker pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				results, err := sc.Scan(url)
				if err != nil {
					if verbose && !silent {
						fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", url, err)
					}
					continue
				}

				for _, res := range results {
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

					output, err := json.Marshal(res)
					if err != nil {
						continue
					}
					fmt.Println(string(output))
				}
			}
		}()
	}

	// Read from Stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := scanner.Text()
		if url != "" {
			jobs <- url
		}
	}

	close(jobs)
	wg.Wait()
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
