package runner

import (
	"time"
)

// Options holds all configuration options for the runner
type Options struct {
	// Scanning
	Concurrency  int
	Timeout      time.Duration
	Proxy        string
	Headers      []string
	RateLimit    int
	InputFile    string
	OutputFile   string
	PayloadsFile string

	// Request Configuration
	Method      string
	Data        string
	ContentType string
	RawPayload  bool

	// Scope & Filters
	ScanHeaders bool
	HeaderList  string
	CharsAllow  string
	CharsIgnore string
	HTTPAllow   string
	HTTPIgnore  string

	// Output
	OutputFormat string
	Verbose      bool
	VeryVerbose  bool
	Silent       bool

	// Advanced
	BlindURL    string
	NoDOM       bool
	ScanDeepDOM bool

	// Modes
	DetectLibraries bool
}

// DefaultOptions returns a new Options struct with default values
func DefaultOptions() *Options {
	return &Options{
		Concurrency:  40,
		Timeout:      10 * time.Second,
		Method:       "GET",
		ContentType:  "application/x-www-form-urlencoded",
		HeaderList:   "User-Agent,Referer,X-Forwarded-For", // Default vulnerable headers
		OutputFormat: "url",
	}
}
