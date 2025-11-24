# Changelog

## [v2.0.0] - 2025-11-24
### Added
- **New AST-Based DOM XSS Engine**: Replaced regex-based analysis with a full JavaScript parser (`goja/parser`) for superior accuracy.
- **Scope-Aware Taint Tracking**: The scanner now understands variable scope and data flow, reducing false positives and detecting complex transitive vulnerabilities.
- **Modern Vector Support**: Added detection for:
    - Navigation API (`navigation.currentEntry`, `navigation.navigate`).
    - jQuery Sinks (`.html()`, `.append()`, etc.).
    - `insertAdjacentHTML`, `setImmediate`.
- **Prototype Pollution Detection**: Now identifies assignments to `__proto__`, `prototype`, and `constructor`.
- **Sanitization Detection**: Automatically ignores data flows that pass through `DOMPurify.sanitize`.
- **Line Number Mapping**: Reports the exact line number of the sink in the source code.

### Changed
- **Major**: DOM XSS scanning is now enabled by default. Use `--no-dom` to disable.
- **Improved**: `isSource` logic now handles nested properties (e.g., `window.opener.location`).

## [v1.7.0] - Previous
- Added Blind XSS support.
- Added Deep DOM scanning.

All notable changes to this project will be documented in this file.

## [v1.4.3] - 2025-11-20

### Fixed
- **Precision**: Updated attribute payloads to correctly close quotes (`"` or `'`).
- **Attribute Context**: Switched to `onmouseover` event for broader applicability.
- **URL Context**: Added tag‑breakout payloads before falling back to `javascript:`.

### Added
- **Granular JavaScript contexts**: `ContextJSSingleQuote`, `ContextJSDoubleQuote`, `ContextJSRaw` with appropriate payloads.
- **Tag Name context** (`ContextTagName`) and **RCDATA context** (`ContextRCDATA`) detection and payloads.

### Changed
- Updated version banner to `v1.4.3`.


### Fixed
- **Critical**: Parameter reflection detection bug where parameters were tested simultaneously, causing false negatives when reflection depended on other parameters. Now tests each parameter individually.

### Added
- **Feature**: HTTP request counter in verbose mode (`-v`) and final statistics to track the number of requests made during scanning.

## [v1.4.1] - 2025-11-20

### Fixed
- **Critical**: Context detection false positives causing wrong payload suggestions
- **Critical**: `isInAttribute()` incorrectly detecting HTML content as attribute context
- **High**: `isInJavaScript()` event handler detection false positives
- **High**: `isInCSS()` inline style detection false positives
- **High**: `isInURL()` URL attribute detection false positives
- **High**: Payload priority for attribute context (now prioritizes tag breakout over event handlers)

### Changed
- Improved all context detection functions to verify probe is actually inside the detected context
- Updated payload suggestion logic to prioritize more reliable payloads

## [v1.4.0] - 2025-11-20

### Added
- **Blind XSS for POST Body**: Complete blind XSS support for POST request bodies (form-urlencoded and JSON)
- **Advanced Context Detection**: 4 new contexts - Template Literals, SVG, Meta Refresh, Data URIs (+67% coverage)
- **Advanced CSP Analysis**: Detects bypassable CSP policies (unsafe-inline, unsafe-eval, JSONP endpoints, missing base-uri)
- **Connection Pooling Optimization**: Dynamic pooling that scales with concurrency (+12% performance)
- **Rate Limiting Infrastructure**: Token bucket algorithm with configurable requests/second
- **Blind URL Validation**: Input validation for blind XSS callback URLs
- **Context Cancellation**: 10-second timeout for all blind XSS requests
- **CSPBypassable Field**: New field in SecurityHeaders to indicate if CSP can be bypassed

### Changed
- **Performance**: +12% faster in parallel scans (~20,000 ops/second)
- **API**: `network.NewClient` now returns `(*http.Client, *RateLimiter)` and accepts `concurrency` and `rateLimit` parameters
- **Error Handling**: JSON marshal errors now return error message instead of empty string
- **Deprecated APIs**: Replaced `ioutil.ReadAll` with `io.ReadAll` (7 locations)
- **Context Coverage**: Expanded from 6 to 10 context types

### Fixed
- **Critical**: Goroutine leaks in blind XSS functions (3 locations)
- **Critical**: Incorrect JSON escaping in blind XSS payloads
- **Critical**: Request body not being sent in blind XSS POST requests
- **High**: Missing response body cleanup causing resource leaks
- **High**: No timeout on blind XSS requests (now 10s timeout)
- **Medium**: Data races in blind XSS tests (fixed with atomic.Bool)

### Security
- Proper JSON escaping prevents injection vulnerabilities
- Input validation for blind URLs
- Context cancellation prevents hanging requests
- Resource cleanup prevents memory leaks

## [v1.3.0] - 2025-11-20

### Added
- **Context-Aware Detection**: Automatically detects reflection context (HTML, JavaScript, Attribute, URL, Comment) to reduce false positives.
- **Security Headers Analysis**: Checks for CSP, X-Content-Type-Options, and X-XSS-Protection to determine exploitability.
- **Output Formats**: Added `-o` / `--output` flag with support for `url` (default), `human`, and `json` formats.
- **POST/PUT/PATCH Support**: Added `-X` flag to specify HTTP method and `-d` for body data.
- **Header Scanning**: Added `--scan-headers` and `--headers-list` to test for XSS in HTTP headers.
- **JSON Support**: Native support for JSON request bodies with `-ct application/json`.
- **Exploitability Scoring**: Intelligent scoring based on context and security headers.
- **Payload Suggestions**: Context-specific payload suggestions in human and JSON output.

### Changed
- Updated verbose output to include context and exploitability information.
- Improved internal scanner architecture to support multiple injection types.

## [v1.1.0] - 2025-11-19

### Added
- **Raw Payload Mode**: Added `--raw` flag to send payloads without URL encoding.
- **Expanded Special Characters**: Increased detection from 13 to 21 special characters.
- **HTML Encoding Detection**: Added detection for HTML-encoded reflections.
- **Unique Probes**: Implemented timestamped probes for better baseline checking.
- **Verbose Banner**: Added ASCII art banner and progress statistics.

### Changed
- Increased reflection analysis limit from 200 to 1000 characters.
- Improved false positive reduction logic.
