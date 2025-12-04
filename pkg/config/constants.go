package config

import "time"

// Version is the current version of xxss
const Version = "v3.0.0"

// Author is the author of the tool
const Author = "@lcalzada-xor"

// Default Values
const (
	DefaultConcurrency = 40
	DefaultTimeout     = 10 * time.Second
	DefaultUserAgent   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36"
)

// VulnerableHeaders is the list of common HTTP headers that can be vulnerable to XSS
var VulnerableHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Forwarded-Host",
	"X-Original-URL",
	"Accept-Language",
}
