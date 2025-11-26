# xxss - High-Performance Reflected XSS Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21%2B-cyan)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-red)

---
<img width="372" height="173" alt="imagen" src="https://github.com/user-attachments/assets/57a5b9b2-8120-486a-b4bf-a936a7638424" />

---

**xxss** is a blazing fast, modular, and scalable **Reflected Cross-Site Scripting (XSS) scanner** written in Go. Designed for **bug bounty hunters** and **AppSec engineers**, it serves as a **high-speed screening tool** to identify potentially vulnerable parameters before deeper analysis with tools like `dalfox`.

Unlike traditional scanners that send dozens of requests per parameter, `xxss` uses a smart **single-shot probing strategy**, reducing traffic by over **90%** (approx. 1 request per reflected parameter). It prioritizes **recall over precision** - better to report a potential vulnerability than miss one.

## Features

- **Fast & Efficient**: Optimized for speed with concurrency control.
- **Smart Detection**: 
    - **Reflected XSS**: Context-aware analysis (HTML, JS, Attribute) to reduce false positives.
    - **DOM XSS (v2.0 Engine)**: 
        - **AST-Based Analysis**: Uses Abstract Syntax Tree to understand code structure, not just regex.
        - **Scope-Aware Taint Tracking**: Tracks data flow across variables and functions.
        - **Modern Vectors**: Detects Navigation API, jQuery sinks, and Prototype Pollution.
        - **Sanitization Aware**: Recognizes `DOMPurify` and other sanitizers to prevent false alarms.
- **Deep Scanning**: Can fetch and analyze external JavaScript files (`--deep-dom`).
- **Blind XSS**: Integrated support for Blind XSS callbacks.
- **Customizable**: extensive flags for headers, methods, and output formats.
  - **13 Context Types**: HTML, JavaScript (Single Quote, Double Quote, Raw), Template Literals, CSS, Attribute, URL, Data URIs, SVG, Meta Refresh, Comment, Tag Name, RCDATA, **AngularJS**
  - **Granular JavaScript Detection**: Distinguishes between `'input'`, `"input"`, and raw `input` contexts
  - **AngularJS Sandbox Escape**: Detects and exploits AngularJS template injection
  - **WAF Detection**: Identifies 8 common WAFs (Cloudflare, AWS, Imperva, ModSecurity, F5, Sucuri, Barracuda)
  - **Header Scanning**: Inject into `User-Agent`, `Referer`, `X-Forwarded-For`, etc.
  - **Blind XSS**: 
    - **Unique Identifiers**: Subdomain-based tracking (`param123.oast.fun`)
    - **12+ Payloads**: Expanded from 4 generic to 12+ diverse vectors
    - **Contextual Payloads**: Context-aware blind XSS (HTML, JS, Attribute, Angular, etc.)
    - **Verbose Output**: See exactly what's being injected
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

## 🛡️ Detected Vulnerabilities

**xxss** goes beyond simple reflection checks. It understands the *context* of the injection to prevent false positives and detect complex DOM issues.

### Reflected XSS
- **HTML Context**: Injections into HTML tags, comments, or RCDATA (e.g., `<textarea>`).
- **Attribute Context**: Injections into event handlers (`onload`, `onerror`) or critical attributes (`href`, `src`).
- **JavaScript Context**: Injections into script blocks, supporting single quotes, double quotes, template literals, and raw code.

### DOM-based XSS (v2.0 Engine)
- **Source -> Sink Flows**: Tracks tainted data from sources (e.g., `location.search`) to dangerous sinks (e.g., `innerHTML`).
- **Protocol Injection**: Detects `javascript:` pseudo-protocol usage in `href`/`src` attributes.
- **DOM Clobbering**: Identifies attempts to shadow global variables via HTML attributes.
- **Prototype Pollution**: Detects assignments to `__proto__`, `prototype`, or `constructor`.
- **Framework Specifics**: Checks for React's `dangerouslySetInnerHTML` and Angular's `v-html` / `ng-bind-html`.
- **Web Workers**: Detects dangerous `importScripts` calls.

### Blind XSS
- **Out-of-Band Detection**: Automatically injects unique payloads to detect vulnerabilities that trigger on backend systems or admin panels.


## Installation

```bash
go install github.com/lcalzada-xor/xxss/v2/cmd/xxss@latest
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

### 5. Blind XSS with interactsh
Use `interactsh-client` for out-of-band detection with unique identifiers.
```bash
# Terminal 1: Start interactsh
interactsh-client
# Output: c59h6dg0vtc0000gg6c0g.oast.fun

# Terminal 2: Scan with xxss (verbose to see injections)
cat urls.txt | xxss -b https://c59h6dg0vtc0000gg6c0g.oast.fun -v

# Output:
# [BLIND] search [html] → https://098f6bcd.c59h6dg0vtc0000gg6c0g.oast.fun (6 contextual payloads)
# [BLIND] user [javascript] → https://5f4dcc3b.c59h6dg0vtc0000gg6c0g.oast.fun (3 contextual payloads)
```

**Features:**
- **Unique Identifiers**: Each parameter gets a unique subdomain (`param123.oast.fun`)
- **Contextual Payloads**: Automatically selects payloads based on detected context
- **Verbose Output**: See exactly what's being injected with `-v`

### 6. Authenticated Scan & Proxy
Scan with a session cookie and route traffic through Burp Suite.
```bash
echo "http://example.com/profile?name=test" | xxss -H "Cookie: session=secret" -x http://127.0.0.1:8080
```

### 7. Header Injection Scanning
Scan HTTP headers for XSS vulnerabilities with verbose output.
```bash
echo "http://testphp.vulnweb.com" | xxss -sh -v
```

### 8. POST Request Scanning
Scan POST body parameters (form-urlencoded or JSON).
```bash
# Form data
echo "http://example.com/login" | xxss -X POST -d "username=test&password=test"

# JSON data
echo "http://example.com/api/user" | xxss -X POST -d '{"name":"test","email":"test@test.com"}' -ct application/json
```

### 9. Human-Readable Output
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
