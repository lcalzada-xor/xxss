package security

// WAF represents a detected Web Application Firewall
type WAF struct {
	Name     string
	Detected bool
}

// Detect is now handled by WAFManager in waf_manager.go
