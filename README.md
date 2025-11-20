# xxss - High-Performance Reflected XSS Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21%2B-cyan)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-red)

**xxss** is a blazing fast, modular, and scalable **Reflected Cross-Site Scripting (XSS) scanner** written in Go. Designed for **bug bounty hunters** and **AppSec engineers**, it serves as a **high-speed screening tool** to identify potentially vulnerable parameters before deeper analysis with tools like `dalfox`.

Unlike traditional scanners that send dozens of requests per parameter, `xxss` uses a smart **single-shot probing strategy**, reducing traffic by over **90%** (approx. 1 request per reflected parameter). It prioritizes **recall over precision** - better to report a potential vulnerability than miss one.

## 🚀 Features

- **⚡️ Optimized Probing:** Checks for 21 special characters in a single request (including `<`, `>`, `"`, `'`, `=`, `/`, space, and more)
- **🔥 High Concurrency:** Built-in worker pool for blazing fast scanning of massive URL lists
- **🛡️ Smart Filtering:** `-allow` and `-ignore` flags for precise, noise-free results
- **🧪 HTML Encoding Detection:** Identifies when characters are HTML-encoded to reduce false positives
- **🎯 Unique Baseline Probes:** Avoids false positives from common parameter values
- **🔓 Raw Payload Mode:** Option to send payloads without URL encoding (`--raw` flag)
- **🤫 Silent Mode:** Perfect for piping into other tools like `dalfox`, `jq`, or `notify`
- **📦 JSON Output:** Structured, machine-readable output for easy integration

## 📦 Installation

### From Source
```bash
git clone https://github.com/lcalzada-xor/xxss
cd xxss
go build -o xxss
sudo mv xxss /usr/local/bin/
```

### Using Go
```bash
go install github.com/lcalzada-xor/xxss@latest
```

## 🛠️ Usage

`xxss` accepts URLs from `stdin`, making it ideal for chaining with tools like `waybackurls`, `gau`, or `katana`.

```bash
cat urls.txt | xxss [flags]
```

### Flags

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
