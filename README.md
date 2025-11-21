# xxss - High-Performance Reflected XSS Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21%2B-cyan)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-red)

---
<img width="372" height="173" alt="imagen" src="https://github.com/user-attachments/assets/57a5b9b2-8120-486a-b4bf-a936a7638424" />

---

**xxss** is a blazing fast, modular, and scalable **Reflected Cross-Site Scripting (XSS) scanner** written in Go. Designed for **bug bounty hunters** and **AppSec engineers**, it serves as a **high-speed screening tool** to identify potentially vulnerable parameters before deeper analysis with tools like `dalfox`.

Unlike traditional scanners that send dozens of requests per parameter, `xxss` uses a smart **single-shot probing strategy**, reducing traffic by over **90%** (approx. 1 request per reflected parameter). It prioritizes **recall over precision** - better to report a potential vulnerability than miss one.

## 🚀 Features

- **Fast & Efficient**: 
  - Optimized connection pooling that scales with concurrency
  - ~20,000 requests/second throughput
  - Smart single-shot probing strategy
- **Advanced Detection**:
  - **12 Context Types**: HTML, JavaScript (Single Quote, Double Quote, Raw), Template Literals, CSS, Attribute, URL, Data URIs, SVG, Meta Refresh, Comment, Tag Name, RCDATA
  - **Granular JavaScript Detection**: Distinguishes between `'input'`, `"input"`, and raw `input` contexts
  - **Blind XSS**: Full support for GET, POST body, and header injections
  - **Security Headers**: Analyzes CSP and other headers to determine exploitability
  - **HTML Encoding Detection**: Identifies when special characters are encoded
- **Comprehensive Scanning**:
  - **GET/POST/PUT/PATCH**: Support for various HTTP methods
  - **Header Injection**: Scans HTTP headers (User-Agent, Referer, etc.) for XSS
  - **Body Parameters**: Form-urlencoded and JSON support
- **Flexible Output**:
  - **URL** (default): Pipe-friendly for tools like `dalfox`
  - **Human**: Pretty-printed findings with context and payloads
  - **JSON**: Structured output for automation
- **Customizable**:
  - Filter reflected characters (`-allow`, `-ignore`)
  - Blind XSS callback URL (`-b`)
  - Raw payload mode (`--raw`)
  - Proxy support

## Installation

```bash
go install github.com/lcalzada-xor/xxss/cmd/xxss@latest
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--concurrency` | `-c` | Number of concurrent workers | `40` |
| `--timeout` | `-t` | HTTP request timeout | `10s` |
| `--verbose` | `-v` | Show verbose output (e.g., headers being scanned) | `false` |
| `--silent` | `-s` | Silent mode (suppress banner & errors) | `false` |
| `--allow` | `-a` | Comma-separated list of allowed chars (e.g., `<,>`) | `""` |
| `--ignore` | `-i` | Comma-separated list of ignored chars (e.g., `',"`)`| `""` |
| `--proxy` | `-x` | Proxy URL (e.g., `http://127.0.0.1:8080`) | `""` |
| `--header` | `-H` | Custom header (e.g., `Cookie: session=123`) | `""` |
| `--blind` | `-b` | Blind XSS callback URL (e.g., `https://xss.hunter`) | `""` |
| `--raw` | `-r` | Send payloads without URL encoding | `false` |
| `--method` | `-X` | HTTP method (GET, POST, PUT, PATCH) | `GET` |
| `--data` | `-d` | Request body for POST/PUT/PATCH | `""` |
| `--content-type` | `-ct` | Content-Type for request body | `application/x-www-form-urlencoded` |
| `--scan-headers` | `-sh` | Scan HTTP headers for XSS | `false` |
| `--headers-list` | `-hl` | Headers to scan (comma-separated) | `User-Agent,Referer,X-Forwarded-For,X-Real-IP,X-Forwarded-Host,X-Original-URL,Accept-Language` |
| `--output` | `-o` | Output format: url, human, json | `url` |

## 💡 Examples

### 1. Basic Scan
Scan a single URL for reflected parameters.
```bash
echo "http://testphp.vulnweb.com/listproducts.php?cat=1" | xxss
```

### 2. Bug Bounty Pipeline (Recommended)
Use xxss as a fast screening tool, then verify with dalfox.
```bash
# Step 1: Fast screening with xxss
subfinder -d example.com | gau | gf xss | xxss -s > potential_xss.json

# Step 2: Deep verification with dalfox
cat potential_xss.json | jq -r '.url' | dalfox pipe
```

### 3. Strict Filtering
Only report if critical characters like `<` or `>` are reflected, and ignore common noise like single quotes.
```bash
cat urls.txt | xxss --allow "<,>" --ignore "'"
```

### 4. Raw Payload Mode
Send special characters without URL encoding (useful for some servers).
```bash
cat urls.txt | xxss --raw
```

### 5. Authenticated Scan & Proxy
Scan with a session cookie and route traffic through Burp Suite.
```bash
echo "http://example.com/profile?name=test" | xxss -H "Cookie: session=secret" -x http://127.0.0.1:8080
```

### 6. Header Injection Scanning
Scan HTTP headers for XSS vulnerabilities with verbose output.
```bash
echo "http://testphp.vulnweb.com" | xxss -sh -v
```

### 7. POST Request Scanning
Scan POST body parameters (form-urlencoded or JSON).
```bash
# Form data
echo "http://example.com/login" | xxss -X POST -d "username=test&password=test"

# JSON data
echo "http://example.com/api/user" | xxss -X POST -d '{"name":"test","email":"test@test.com"}' -ct application/json
```

### 8. Human-Readable Output
Get detailed findings with context and suggested payloads.
```bash
echo "http://testphp.vulnweb.com/listproducts.php?cat=1" | xxss -o human
```

## 📝 Output Format

`xxss` outputs one JSON object per finding:

```json
{
  "url": "http://example.com/?p=val",
  "parameter": "p",
  "reflected": true,
  "unfiltered": ["<", ">", "\"", "'", "=", "/", " "]
}
```

## 🎯 Positioning: Pre-Dalfox Screening

**xxss** is designed as a **fast screening tool** in your XSS hunting workflow:

1. **xxss** (this tool) - Fast screening to identify potentially vulnerable parameters
2. **dalfox** - Deep verification with browser-based exploitation testing

This approach gives you:
- ⚡ **Speed**: xxss quickly filters thousands of URLs
- 🎯 **Accuracy**: dalfox confirms real exploitability
- 💰 **Efficiency**: Focus manual testing on verified vulnerabilities

### Detected Contexts

xxss now detects **10 reflection contexts** including:
- **HTML**: `<div>{{input}}</div>`
- **JavaScript**: `<script>var x = '{{input}}';</script>`
- **Template Literals**: `` <script>const x = `${input}`;</script> ``
- **Attribute**: `<div class="{{input}}">`
- **URL**: `<a href="{{input}}">`
- **Data URI**: `<a href="data:text/html,{{input}}">`
- **SVG**: `<svg><text>{{input}}</text></svg>`
- **Meta Refresh**: `<meta http-equiv="refresh" content="0;url={{input}}">`
- **CSS**: `<style>.class { color: {{input}}; }</style>`
- **Comment**: `<!-- {{input}} -->`

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## 📜 License

This project is licensed under the MIT License.
