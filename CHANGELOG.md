# Changelog

All notable changes to this project will be documented in this file.

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
