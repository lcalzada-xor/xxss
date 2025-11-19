# xxss - High-Performance Reflected XSS Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21%2B-cyan)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-red)

**xxss** is a blazing fast, modular, and scalable **Reflected Cross-Site Scripting (XSS) scanner** written in Go. Designed for **bug bounty hunters** and **AppSec engineers**, it optimizes the scanning process to minimize HTTP requests while maximizing detection accuracy.

Unlike traditional scanners that send dozens of requests per parameter, `xxss` uses a smart **single-shot probing strategy**, reducing traffic by over **90%** (approx. 1 request per reflected parameter).

## 🚀 Features

- **⚡️ Optimized Probing:** Checks for multiple special characters in a single request.
- **🔥 High Concurrency:** Built-in worker pool for blazing fast scanning of massive URL lists.
- **🛡️ Smart Filtering:** `-allow` and `-ignore` flags for precise, noise-free results.
- **🤫 Silent Mode:** Perfect for piping into other tools like `jq`, `notify`, or `nuclei`.
- **📦 JSON Output:** Structured, machine-readable output for easy integration.

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

## 💡 Examples

### 1. Basic Scan
Scan a single URL for reflected parameters.
```bash
echo "http://testphp.vulnweb.com/listproducts.php?cat=1" | xxss
```

### 2. Bug Bounty Pipeline
Chain with other tools to find XSS in a list of subdomains.
```bash
subfinder -d example.com | gau | gf xss | xxss -silent | jq .
```

### 3. Strict Filtering
Only report if critical characters like `<` or `>` are reflected, and ignore common noise like single quotes.
```bash
cat urls.txt | xxss --allow "<,>" --ignore "'"
```

## 📝 Output Format

`xxss` outputs one JSON object per finding:

```json
{
  "url": "http://example.com/?p=val",
  "parameter": "p",
  "reflected": true,
  "unfiltered": ["<", ">", "\"", "'"]
}
```

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## 📜 License

This project is licensed under the MIT License.
