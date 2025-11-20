# xxss - High-Performance Reflected XSS Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21%2B-cyan)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-red)

**xxss** is a blazing fast, modular, and scalable **Reflected Cross-Site Scripting (XSS) scanner** written in Go. Designed for **bug bounty hunters** and **AppSec engineers**, it serves as a **high-speed screening tool** to identify potentially vulnerable parameters before deeper analysis with tools like `dalfox`.

Unlike traditional scanners that send dozens of requests per parameter, `xxss` uses a smart **single-shot probing strategy**, reducing traffic by over **90%** (approx. 1 request per reflected parameter). It prioritizes **recall over precision** - better to report a potential vulnerability than miss one.

## 🚀 Features

- **Fast & Efficient**: Optimized for speed with concurrent scanning.
- **Smart Detection**:
  - **Context-Aware**: Detects HTML, JavaScript, Attribute, URL, and Comment contexts.
  - **Security Headers**: Analyzes CSP and other headers to determine exploitability.
  - **HTML Encoding Detection**: Identifies when special characters are encoded.
- **Comprehensive Scanning**:
  - **GET/POST/PUT/PATCH**: Support for various HTTP methods.
  - **Header Injection**: Scans HTTP headers (User-Agent, Referer, etc.) for XSS.
- **Flexible Output**:
  - **URL** (default): Pipe-friendly for tools like `dalfox`.
  - **Human**: Pretty-printed findings with context and payloads.
  - **JSON**: Structured output for automation.
- **Customizable**:
  - Filter reflected characters (`-allow`, `-ignore`).
  - Raw payload mode (`--raw`).
  - Proxy support.

## Installation

```bash
go install github.com/lcalzada-xor/xxss@latest
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--concurrency` | `-c` | Number of concurrent workers | `40` |
| `--timeout` | `-t` | HTTP request timeout | `10s` |
| `--verbose` | `-v` | Show verbose error messages | `false` |
| `--silent` | `-s` | Silent mode (suppress banner & errors) | `false` |
| `--allow` | `-a` | Comma-separated list of allowed chars (e.g., `<,>`) | `""` |
| `--ignore` | `-i` | Comma-separated list of ignored chars (e.g., `',"`)| `""` |
| `--proxy` | `-x` | Proxy URL (e.g., `http://127.0.0.1:8080`) | `""` |
| `--header` | `-H` | Custom header (e.g., `Cookie: session=123`) | `""` |
| `--raw` | `-r` | Send payloads without URL encoding | `false` |

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

### Detected Characters

xxss now detects **21 special characters** including:
- HTML/XML: `<`, `>`, `"`, `'`, `&`, `/`
- JavaScript: `$`, `(`, `)`, `` ` ``, `{`, `}`
- Attributes: `=`, `:`, `;`, space, tab
- Encoding: `%`, `#`, `\`, `|`

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## 📜 License

This project is licensed under the MIT License.
