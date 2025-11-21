package models

type InjectionType string

const (
	InjectionQuery  InjectionType = "query"
	InjectionBody   InjectionType = "body"
	InjectionHeader InjectionType = "header"
)

type ReflectionContext string

const (
	ContextHTML            ReflectionContext = "html"
	ContextJavaScript      ReflectionContext = "javascript" // Deprecated: use specific JS contexts
	ContextJSSingleQuote   ReflectionContext = "javascript_single_quote"
	ContextJSDoubleQuote   ReflectionContext = "javascript_double_quote"
	ContextJSRaw           ReflectionContext = "javascript_raw"
	ContextTemplateLiteral ReflectionContext = "template_literal"
	ContextCSS             ReflectionContext = "css"
	ContextAttribute       ReflectionContext = "attribute"
	ContextURL             ReflectionContext = "url"
	ContextDataURI         ReflectionContext = "data_uri"
	ContextSVG             ReflectionContext = "svg"
	ContextMetaRefresh     ReflectionContext = "meta_refresh"
	ContextComment         ReflectionContext = "comment"
	ContextAngular         ReflectionContext = "angular" // AngularJS template context
	ContextTagName         ReflectionContext = "tag_name"
	ContextRCDATA          ReflectionContext = "rcdata"
	ContextUnknown         ReflectionContext = "unknown"
)

type SecurityHeaders struct {
	ContentType         string `json:"content_type,omitempty"`
	CSP                 string `json:"csp,omitempty"`
	CSPBypassable       bool   `json:"csp_bypassable,omitempty"`
	XContentTypeOptions string `json:"x_content_type_options,omitempty"`
	XXSSProtection      string `json:"x_xss_protection,omitempty"`
	HasAntiXSS          bool   `json:"has_anti_xss"`
	WAF                 string `json:"waf,omitempty"` // Detected Web Application Firewall
}

// Result represents the findings of an XSS scan for a specific URL and parameter.
type Result struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	Parameter        string            `json:"parameter"`
	InjectionType    InjectionType     `json:"injection_type"`
	Reflected        bool              `json:"reflected"`
	Unfiltered       []string          `json:"unfiltered"`
	Context          ReflectionContext `json:"context,omitempty"`
	SecurityHeaders  SecurityHeaders   `json:"security_headers,omitempty"`
	Exploitable      bool              `json:"exploitable"`
	SuggestedPayload string            `json:"suggested_payload,omitempty"`
}
