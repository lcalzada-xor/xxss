# Release Notes v1.3.0

## 🚀 Major Update: Context Awareness & Full HTTP Support

This release transforms `xxss` from a simple reflected parameter checker into a smart, context-aware XSS scanner capable of handling complex scenarios.

### ✨ New Features

#### 🧠 Context-Aware Detection
`xxss` now understands where your input is reflected:
- **HTML Context**: `<div>REFLECTION</div>`
- **JavaScript Context**: `<script>var x = "REFLECTION";</script>`
- **Attribute Context**: `<input value="REFLECTION">`
- **URL Context**: `<a href="REFLECTION">`
- **Comment Context**: `<!-- REFLECTION -->`

This significantly reduces false positives (e.g., reflections in comments) and provides context-specific payload suggestions.

#### 🛡️ Security Headers Analysis
The scanner now analyzes security headers like **Content-Security-Policy (CSP)** to determine if a reflection is actually exploitable.

#### 📮 Full HTTP Method Support
You can now scan beyond GET requests:
- **POST/PUT/PATCH**: Support for request bodies (form-urlencoded and JSON).
- **Header Injection**: Scan HTTP headers like `User-Agent`, `Referer`, and `X-Forwarded-For`.

```bash
# Scan a POST request
echo "http://example.com/api" | xxss -X POST -d '{"name":"test"}' -ct application/json
```

#### 📊 Flexible Output Formats
New `-o` / `--output` flag:
- **url** (default): Perfect for piping to `dalfox`.
- **human**: Beautiful, readable output for manual verification.
- **json**: Structured data for automated pipelines.

```bash
echo "http://example.com" | xxss -o human
```

### 📦 Installation

```bash
go install github.com/lcalzada-xor/xxss@latest
```

### 🤝 Contributors
- @lcalzada-xor
