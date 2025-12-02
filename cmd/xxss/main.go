package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/config"
	"github.com/lcalzada-xor/xxss/v2/pkg/runner"
)

// headerFlags allows setting multiple headers
type headerFlags []string

func (h *headerFlags) String() string {
	return fmt.Sprint(*h)
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func main() {
	options := runner.DefaultOptions()

	// Define flags with both short and long names
	flag.IntVar(&options.Concurrency, "c", config.DefaultConcurrency, "Concurrency level")
	flag.IntVar(&options.Concurrency, "concurrency", config.DefaultConcurrency, "Concurrency level")

	flag.DurationVar(&options.Timeout, "t", config.DefaultTimeout, "Request timeout")
	flag.DurationVar(&options.Timeout, "timeout", config.DefaultTimeout, "Request timeout")

	// Verbose flags: -v for verbose, -vv for very verbose
	flag.BoolVar(&options.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&options.VeryVerbose, "vv", false, "Very verbose output (detailed debugging)")

	flag.BoolVar(&options.Silent, "s", false, "Silent mode (suppress errors)")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode (suppress errors)")

	flag.StringVar(&options.CharsAllow, "ca", "", "Comma-separated list of allowed characters (e.g. <,>)")
	flag.StringVar(&options.CharsAllow, "chars-allow", "", "Comma-separated list of allowed characters (e.g. <,>)")

	flag.StringVar(&options.CharsIgnore, "ci", "", "Comma-separated list of ignored characters (e.g. ', \")")
	flag.StringVar(&options.CharsIgnore, "chars-ignore", "", "Comma-separated list of ignored characters (e.g. ', \")")

	flag.StringVar(&options.HTTPAllow, "ha", "", "Comma-separated list of allowed HTTP status codes (e.g. 200,201)")
	flag.StringVar(&options.HTTPAllow, "http-allow", "", "Comma-separated list of allowed HTTP status codes (e.g. 200,201)")

	flag.StringVar(&options.HTTPIgnore, "hi", "", "Comma-separated list of ignored HTTP status codes (e.g. 403,404)")
	flag.StringVar(&options.HTTPIgnore, "http-ignore", "", "Comma-separated list of ignored HTTP status codes (e.g. 403,404)")

	flag.StringVar(&options.Proxy, "x", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	flag.StringVar(&options.Proxy, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")

	var headers headerFlags
	flag.Var(&headers, "H", "Custom header (e.g. 'Cookie: session=123')")
	flag.Var(&headers, "header", "Custom header (e.g. 'Cookie: session=123')")

	flag.BoolVar(&options.RawPayload, "r", false, "Send payloads without URL encoding")
	flag.BoolVar(&options.RawPayload, "raw", false, "Send payloads without URL encoding")

	flag.StringVar(&options.Method, "X", "GET", "HTTP method (GET, POST, PUT, PATCH)")
	flag.StringVar(&options.Method, "method", "GET", "HTTP method (GET, POST, PUT, PATCH)")

	flag.StringVar(&options.Data, "d", "", "Request body for POST/PUT/PATCH")
	flag.StringVar(&options.Data, "data", "", "Request body for POST/PUT/PATCH")

	flag.StringVar(&options.ContentType, "ct", "application/x-www-form-urlencoded", "Content-Type for request body")
	flag.StringVar(&options.ContentType, "content-type", "application/x-www-form-urlencoded", "Content-Type for request body")

	flag.BoolVar(&options.ScanHeaders, "sh", false, "Scan HTTP headers for XSS")
	flag.BoolVar(&options.ScanHeaders, "scan-headers", false, "Scan HTTP headers for XSS")

	defaultHeaders := strings.Join(config.VulnerableHeaders, ",")
	flag.StringVar(&options.HeaderList, "hl", defaultHeaders, "Headers to scan (comma-separated)")
	flag.StringVar(&options.HeaderList, "headers-list", defaultHeaders, "Headers to scan")

	flag.StringVar(&options.OutputFormat, "o", "url", "Output format: url, human, json")
	flag.StringVar(&options.OutputFormat, "output", "url", "Output format: url, human, json")

	flag.StringVar(&options.BlindURL, "b", "", "Blind XSS callback URL (e.g. https://xss.hunter)")
	flag.StringVar(&options.BlindURL, "blind", "", "Blind XSS callback URL (e.g. https://xss.hunter)")

	flag.BoolVar(&options.NoDOM, "no-dom", false, "Disable DOM XSS scanning (static analysis)")

	flag.BoolVar(&options.ScanDeepDOM, "deep-dom", false, "Enable Deep DOM XSS scanning (fetch external JS)")

	flag.BoolVar(&options.DetectLibraries, "dt", false, "Detect technologies only (no XSS scan)")
	flag.BoolVar(&options.DetectLibraries, "detect-libraries", false, "Detect technologies only (no XSS scan)")

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
			fmt.Sprintf("           \x1b[38;5;141m%s\x1b[0m | \x1b[38;5;141m%s\x1b[0m\n", config.Version, config.Author)

		fmt.Fprint(os.Stderr, banner)
		h := `
USAGE:
  xxss [flags]

SCANNING:
  -c,  --concurrency int     Number of concurrent workers (default %d)
  -t,  --timeout duration    Request timeout (default %s)
  -x,  --proxy string        Proxy URL (default http://127.0.0.1:8080 if flag is present without value)
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
  -dt, --detect-libraries    Detect technologies only (no XSS scan)

EXAMPLES:
  echo "http://example.com/?p=val" | xxss
  cat urls.txt | xxss -c 50 -o human
  echo "http://example.com" | xxss -X POST -d "user=test" -o json
  echo "http://example.com" | xxss --scan-headers -v
  echo "http://example.com" | xxss -dt -o human
`
		fmt.Fprint(os.Stderr, h)
	}

	// Handle default value for -x/--proxy if provided without argument
	// This must be done before flag.Parse()
	args := os.Args[1:]
	for i, arg := range args {
		if arg == "-x" || arg == "--proxy" {
			// Check if next arg is missing or starts with -
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				// Insert default proxy
				newArgs := make([]string, 0, len(os.Args)+1)
				newArgs = append(newArgs, os.Args[:i+2]...)
				newArgs = append(newArgs, "http://127.0.0.1:8080")
				newArgs = append(newArgs, os.Args[i+2:]...)
				os.Args = newArgs
			}
			break
		}
	}

	flag.Parse()

	// Validation for --detect-libraries
	if options.DetectLibraries {
		if options.OutputFormat != "human" && options.OutputFormat != "json" {
			fmt.Fprintln(os.Stderr, "Error: --detect-libraries requires -o human or -o json")
			os.Exit(1)
		}

		// Warn if other scanning flags are present (heuristic check)
		// Since we can't easily check if default values were changed by user or not without more complex flag parsing,
		// we will just rely on the fact that DetectLibraries takes precedence in runner.
		if !options.Silent {
			// Check for some common flags that might indicate user intent to scan
			if options.ScanHeaders || options.BlindURL != "" || options.Data != "" || options.ScanDeepDOM {
				fmt.Fprintln(os.Stderr, "\x1b[38;5;214m[!] Warning: --detect-libraries (-dt) is enabled. XSS scanning is DISABLED.\x1b[0m")
				fmt.Fprintln(os.Stderr, "\x1b[38;5;214m[!] Remove -dt to perform XSS scanning.\x1b[0m")
			}
		}
	}

	// Assign headers to options
	options.Headers = headers

	// Run the application
	r := runner.NewRunner(options)
	r.Run()
}
